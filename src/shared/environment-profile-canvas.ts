/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  EnvironmentProfile,
  HuntPrimitive,
  JoinKeyKind,
} from "./environment-profile.js";

/**
 * Render an {@link EnvironmentProfile} as a self-contained Cursor Canvas
 * (`.canvas.tsx`) source string. This is the visual sibling of
 * {@link renderProfileMarkdown}: the same IPB/IPOE findings, laid out as an
 * interactive brief (stat strip, hunt-target table, primitive/joinability
 * charts, and expandable field glossaries) an analyst can open beside the chat.
 *
 * The output imports only from `cursor/canvas`, embeds all data inline (no
 * network), and default-exports the top-level component — the contract the
 * Cursor canvas host requires. The profile findings are baked into a typed
 * `DATA` literal so the file is fully static.
 *
 * The `profile-environment` skill writes this to the workspace canvases
 * directory (e.g. `…/canvases/environment-brief.canvas.tsx`).
 */
export function renderProfileCanvas(profile: EnvironmentProfile): string {
  const data = buildBriefData(profile);
  return CANVAS_TEMPLATE.replace(
    "/*__DATA__*/ null",
    JSON.stringify(data, null, 2)
  );
}

// --- Display metadata (kept in sync with the markdown renderer) -------------

const PRIMITIVE_ORDER: HuntPrimitive[] = [
  // Foundational (composable; always-available or field + a source).
  "ioc_match",
  "frequency_analysis",
  "enrichment_match",
  "known_good_diff",
  "string_analysis",
  // Terrain-gated behavioral.
  "process_lineage",
  "temporal_sequence",
  "auth_lateral",
  "network_beaconing",
  "dns_analytics",
  "cloud_identity",
  "geo_impossible_travel",
  "egress_exfil",
  "file_integrity",
  "code_signature",
];

const PRIMITIVE_DESC: Record<HuntPrimitive, string> = {
  // Foundational.
  ioc_match: "Match observables against intel / IOC sources.",
  frequency_analysis: "Stack-count & rare-term outliers over any field.",
  enrichment_match: "Join observables to reputation / CTI verdicts.",
  known_good_diff: "New-term / first-seen / allowlist differencing.",
  string_analysis: "Substring / entropy analysis of free-text fields.",
  // Terrain-gated behavioral.
  process_lineage: "Walk parent/child process chains — who-spawned-what.",
  temporal_sequence: "Order events over time within a join key (EQL sequences).",
  auth_lateral: "Logon / RDP / lateral-movement correlation.",
  network_beaconing: "Periodic C2 callbacks — regular-interval egress.",
  dns_analytics: "DGA, tunneling, and suspicious resolutions.",
  cloud_identity: "Cloud IdP session abuse — assume-role, MFA, password spray.",
  geo_impossible_travel: "Rare geo / velocity anomalies per user.",
  egress_exfil: "Outbound data-volume anomalies.",
  file_integrity: "File create / modify / delete activity (FIM).",
  code_signature: "Surface unsigned / untrusted binary execution.",
};

const PRIMITIVE_FIELDS: Record<HuntPrimitive, string> = {
  // Foundational.
  ioc_match:
    "file.hash.* · source.ip · destination.domain · url.full × intel_sources",
  frequency_analysis:
    "process.name · user.name · dns.question.name (any categorical)",
  enrichment_match:
    "source.ip · destination.domain · file.hash.* → enrichable source",
  known_good_diff: "first_seen · host.id · user.name · process.entity_id",
  string_analysis:
    "process.command_line · url.full · user_agent.original · registry.path",
  // Terrain-gated behavioral.
  process_lineage:
    "process.entity_id · process.parent.entity_id · process.Ext.ancestry · ppid",
  temporal_sequence: "@timestamp + a stable entity id (host / process)",
  auth_lateral:
    "event.category=authentication · winlog.event_id 4624/4625 · source.ip → destination.ip · user.name",
  network_beaconing:
    "destination.ip · destination.port · network.bytes · @timestamp cadence",
  dns_analytics: "dns.question.name · dns.question.type · dns.answers.*",
  cloud_identity: "aws.cloudtrail.* · okta.* · azure.signinlogs.* · user.name",
  geo_impossible_travel: "source.geo.* · user.name · @timestamp",
  egress_exfil:
    "network.bytes · source.bytes · destination.ip · network.direction=outbound",
  file_integrity: "file.path · file.name · file.hash.* · event.action",
  code_signature:
    "process.code_signature.trusted · file.code_signature.subject_name · *.signed",
};

const JOIN_KEY_ORDER: JoinKeyKind[] = [
  "event",
  "agent",
  "user",
  "process",
  "host",
  "host_ip",
  "network",
  "session",
  "container",
  "cloud",
];

const JOIN_KEY_LABEL: Record<JoinKeyKind, string> = {
  event: "event (dedup)",
  agent: "agent",
  user: "user",
  process: "process (sequence)",
  host: "host",
  host_ip: "host_ip",
  network: "network",
  session: "session",
  container: "container",
  cloud: "cloud",
};

const JOIN_KEY_DESC: Record<JoinKeyKind, string> = {
  event: "Collapse duplicate copies of the same event across streams.",
  agent: "The Elastic Agent / endpoint that produced the document.",
  user: "Pivot activity to an identity.",
  process: "Stitch a single process's events into a sequence.",
  host: "Pivot to a machine.",
  host_ip: "Network-address pivot when host.name is absent.",
  network: "Connection endpoints for flow correlation.",
  session: "Linux session grouping (entry / session leader).",
  container: "Containerized-workload pivot.",
  cloud: "Cloud resource / account pivot.",
};

const JOIN_KEY_FIELD: Record<JoinKeyKind, string> = {
  event: "event.id · _id",
  agent: "agent.id",
  user: "user.name · user.id",
  process: "process.entity_id",
  host: "host.name · host.id",
  host_ip: "host.ip",
  network: "source.ip · destination.ip",
  session: "process.entry_leader.entity_id · process.session_leader.entity_id",
  container: "container.id",
  cloud: "cloud.account.id · cloud.instance.id",
};

/** Response domains a worker can actually *enforce* against (vs. notify/enrich). */
const ENFORCEMENT_DOMAINS = ["endpoint", "network", "cloud", "identity"] as const;

// --- Shape of the inlined data literal --------------------------------------

interface Kv {
  key: string;
  n: number;
}
interface GlossaryItem {
  key: string;
  n: number;
  desc: string;
  fields: string;
}
interface HuntRow {
  name: string;
  schema: "ecs" | "off_schema";
  dataClass: string;
  docs: number | null;
  prims: number;
  keys: number;
  lineage: string;
}
interface Big {
  name: string;
  docs: number;
  note: string;
}
interface BriefData {
  cluster: string;
  scopeId: string;
  scopeLevel: string;
  generatedAt: string;
  isSample: boolean;
  errors: number;
  summaryLine: string;
  notes: string[];
  stats: {
    dataStreams: number;
    huntTotal: number;
    huntEcs: number;
    huntOff: number;
    rulesEnabled: number;
    rulesTotal: number;
    entities: number;
  };
  biggest: Big[];
  hunt: HuntRow[];
  primitives: Kv[];
  joins: Kv[];
  primitiveGlossary: GlossaryItem[];
  joinGlossary: GlossaryItem[];
  response: Kv[];
  responseNote: string;
  intelSources: string[];
  mirrors: { name: string; mirror_of: string }[];
  integrations: string[];
  blindSpots: string[];
  capabilities: {
    entity_analytics: boolean;
    attack_discovery: boolean;
    cases: boolean;
    correlation_corpus: boolean;
  };
  defend: { policy: string; os: string; protections: string }[];
  thirdParty: string[];
}

function buildBriefData(profile: EnvironmentProfile): BriefData {
  const { scope, inventory, endpoint_posture, response_capabilities, terrain, capabilities, collection_errors } =
    profile;

  const cluster = scope.ref.deployment ?? scope.ref.space ?? scope.ref.index_pattern ?? "unknown";
  const hunt = terrain.hunt_indices ?? [];
  const huntNames = new Set(hunt.map((h) => h.name));
  const intelSet = new Set(terrain.intel_sources);
  const primByName = new Map(hunt.map((h) => [h.name, (h.primitives ?? []).length]));

  const huntEcs = hunt.filter((h) => h.schema_alignment === "ecs").length;
  const huntOff = hunt.length - huntEcs;
  const entities =
    inventory.entity_counts.host +
    inventory.entity_counts.user +
    inventory.entity_counts.service +
    inventory.entity_counts.generic;

  // Biggest data by volume across every index we saw a doc_count for.
  const docByName = new Map<string, number>();
  const consider = (name: string, docs?: number) => {
    if (docs == null) return;
    docByName.set(name, Math.max(docByName.get(name) ?? 0, docs));
  };
  for (const h of hunt) consider(h.name, h.doc_count);
  for (const o of terrain.classified_indices ?? []) consider(o.name, o.doc_count);
  for (const o of terrain.high_volume_off_schema) consider(o.name, o.doc_count);
  for (const ds of inventory.active_data_streams) consider(ds.name, ds.doc_count);
  const biggest: Big[] = [...docByName.entries()]
    .filter(([, docs]) => docs > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 9)
    .map(([name, docs]) => ({ name, docs, note: bigNote(name, huntNames, intelSet, primByName) }));

  const huntRows: HuntRow[] = hunt.slice(0, 12).map((h) => ({
    name: h.name,
    schema: h.schema_alignment === "ecs" ? "ecs" : "off_schema",
    dataClass: h.data_class ?? "—",
    docs: h.doc_count ?? null,
    prims: (h.primitives ?? []).length,
    keys: (h.join_keys ?? []).length,
    lineage: h.lineage?.capability ?? "—",
  }));

  const matrix = terrain.primitive_matrix ?? {};
  const primitives: Kv[] = PRIMITIVE_ORDER.map((p) => ({ key: p, n: (matrix[p] ?? []).length }))
    .filter((x) => x.n > 0)
    .sort((a, b) => b.n - a.n);
  const primitiveGlossary: GlossaryItem[] = primitives.map((x) => ({
    key: x.key,
    n: x.n,
    desc: PRIMITIVE_DESC[x.key as HuntPrimitive],
    fields: PRIMITIVE_FIELDS[x.key as HuntPrimitive],
  }));

  const byKey = terrain.joinability?.by_key ?? {};
  const joins: Kv[] = JOIN_KEY_ORDER.map((k) => ({
    key: JOIN_KEY_LABEL[k],
    n: (byKey[k] ?? []).length,
  }))
    .filter((x) => x.n > 0)
    .sort((a, b) => b.n - a.n);
  const joinGlossary: GlossaryItem[] = JOIN_KEY_ORDER.filter((k) => (byKey[k] ?? []).length)
    .map((k) => ({
      key: JOIN_KEY_LABEL[k],
      n: (byKey[k] ?? []).length,
      desc: JOIN_KEY_DESC[k],
      fields: JOIN_KEY_FIELD[k],
    }))
    .sort((a, b) => b.n - a.n);

  // Response connectors grouped by domain.
  const domainCounts = new Map<string, number>();
  for (const c of response_capabilities.connectors) {
    domainCounts.set(c.capability_domain, (domainCounts.get(c.capability_domain) ?? 0) + 1);
  }
  const response: Kv[] = [...domainCounts.entries()]
    .map(([key, n]) => ({ key, n }))
    .sort((a, b) => b.n - a.n);
  const missingEnforcement = ENFORCEMENT_DOMAINS.filter((d) => !domainCounts.has(d));
  const responseNote =
    response_capabilities.connectors.length === 0
      ? "No response connectors configured."
      : missingEnforcement.length === ENFORCEMENT_DOMAINS.length
        ? "No host / network / cloud / identity response actions — enrich / notify / automate only."
        : missingEnforcement.length
          ? `No ${missingEnforcement.join(" / ")} response actions.`
          : "";

  const defend = endpoint_posture.defend.map((d) => ({
    policy: d.policy_name,
    os: d.os,
    protections: d.protections.map((pr) => `${pr.protection}=${pr.intended_mode}`).join(", "),
  }));

  // Headline: templated character read of the cluster.
  const notes: string[] = [];
  if (huntOff > huntEcs && huntOff > 0)
    notes.push("Most huntable data sits off the ECS happy path — ECS-only probes would miss it.");
  if (entities === 0) notes.push("Entity Store is empty — no risk/entity analytics engine populated.");
  if (endpoint_posture.defend.length === 0) notes.push("No Elastic Defend policies detected.");
  if (inventory.deployed_tech.cloud_providers.length === 0)
    notes.push("No cloud providers integrated.");
  if (inventory.rule_inventory.total > 0 && inventory.rule_inventory.enabled / inventory.rule_inventory.total < 0.25)
    notes.push(
      `Only ${inventory.rule_inventory.enabled} of ${inventory.rule_inventory.total} detection rules enabled.`
    );

  const summaryLine =
    `${cap(scope.level)} profile: ${inventory.active_data_streams.length} data streams, ` +
    `${hunt.length} hunt indices (${huntEcs} ECS / ${huntOff} off-schema), ` +
    `${inventory.rule_inventory.enabled}/${inventory.rule_inventory.total} rules enabled.`;

  return {
    cluster,
    scopeId: scope.scope_id,
    scopeLevel: scope.level,
    generatedAt: profile.generated_at,
    isSample: capabilities.is_sample_data,
    errors: collection_errors.length,
    summaryLine,
    notes,
    stats: {
      dataStreams: inventory.active_data_streams.length,
      huntTotal: hunt.length,
      huntEcs,
      huntOff,
      rulesEnabled: inventory.rule_inventory.enabled,
      rulesTotal: inventory.rule_inventory.total,
      entities,
    },
    biggest,
    hunt: huntRows,
    primitives,
    joins,
    primitiveGlossary,
    joinGlossary,
    response,
    responseNote,
    intelSources: terrain.intel_sources,
    mirrors: (terrain.classified_indices ?? [])
      .filter((o) => o.mirror_of)
      .map((o) => ({ name: o.name, mirror_of: o.mirror_of! })),
    integrations: inventory.integration_presence.installed,
    blindSpots: terrain.blind_spots,
    capabilities: {
      entity_analytics: capabilities.entity_analytics,
      attack_discovery: capabilities.attack_discovery,
      cases: capabilities.cases,
      correlation_corpus: capabilities.correlation_corpus,
    },
    defend,
    thirdParty: endpoint_posture.third_party.map((t) => t.vendor),
  };
}

function bigNote(
  name: string,
  huntNames: Set<string>,
  intelSet: Set<string>,
  primByName: Map<string, number>
): string {
  if (huntNames.has(name)) {
    const p = primByName.get(name) ?? 0;
    return p ? `${p}-primitive hunt target` : "hunt target";
  }
  if (intelSet.has(name)) return "intel / enrichment (match target)";
  return "operational / non-hunt";
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// --- The emitted canvas component -------------------------------------------
// A fixed, self-contained `.canvas.tsx` that reads the inlined `DATA` literal
// (`/*__DATA__*/ null` is replaced with the JSON payload at render time).
//
// The template is embedded in the module on purpose (rather than read from a
// file at runtime): `renderProfileCanvas` is the visual sibling of
// `renderProfileMarkdown` and its output is returned inline in *every*
// `profile-environment` tool response. The packaged server ships `dist/` only
// (no `scripts/`), so it cannot depend on a template file being present — the
// canvas must be produced with zero file IO.

const CANVAS_TEMPLATE = String.raw`/*
 * Generated by profile-environment (renderProfileCanvas). Self-contained Cursor
 * Canvas — imports only from "cursor/canvas", all data inlined, no network.
 * Regenerate by re-running the profiler rather than editing by hand.
 */
import {
  BarChart,
  Callout,
  Card,
  CardBody,
  CardHeader,
  CollapsibleSection,
  Divider,
  Grid,
  H1,
  H2,
  H3,
  Pill,
  Row,
  Spacer,
  Stack,
  Stat,
  Table,
  Text,
  useHostTheme,
} from "cursor/canvas";

interface Kv { key: string; n: number; }
interface GlossaryItem { key: string; n: number; desc: string; fields: string; }
interface HuntRow { name: string; schema: "ecs" | "off_schema"; dataClass: string; docs: number | null; prims: number; keys: number; lineage: string; }
interface Big { name: string; docs: number; note: string; }
interface BriefData {
  cluster: string;
  scopeId: string;
  scopeLevel: string;
  generatedAt: string;
  isSample: boolean;
  errors: number;
  summaryLine: string;
  notes: string[];
  stats: { dataStreams: number; huntTotal: number; huntEcs: number; huntOff: number; rulesEnabled: number; rulesTotal: number; entities: number; };
  biggest: Big[];
  hunt: HuntRow[];
  primitives: Kv[];
  joins: Kv[];
  primitiveGlossary: GlossaryItem[];
  joinGlossary: GlossaryItem[];
  response: Kv[];
  responseNote: string;
  intelSources: string[];
  mirrors: { name: string; mirror_of: string }[];
  integrations: string[];
  blindSpots: string[];
  capabilities: { entity_analytics: boolean; attack_discovery: boolean; cases: boolean; correlation_corpus: boolean; };
  defend: { policy: string; os: string; protections: string }[];
  thirdParty: string[];
}

const DATA: BriefData = /*__DATA__*/ null as unknown as BriefData;

const MONO = { fontFamily: "monospace" };

function fmt(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n >= 1e9) return (n / 1e9).toFixed(2) + "B";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(0) + "K";
  return String(n);
}

function ElasticGlyph({ size = 26 }: { size?: number }) {
  const theme = useHostTheme();
  return (
    <span aria-hidden="true" style={{ display: "inline-flex", color: theme.text.primary }}>
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M23.9506 12.4984C23.9527 11.5265 23.6542 10.5777 23.0961 9.78204C22.538 8.98635 21.7475 8.38267 20.8329 8.05369C20.9165 7.62975 20.9586 7.19872 20.9588 6.76664C20.9593 5.33599 20.5061 3.94206 19.6645 2.78515C18.8228 1.62826 17.6361 0.767973 16.2748 0.327936C14.9135 -0.112099 13.4478 -0.109226 12.0882 0.336144C10.7287 0.781513 9.54534 1.64645 8.70826 2.80664C8.09097 2.32848 7.33466 2.06452 6.55389 2.05472C5.77314 2.04491 5.01045 2.2898 4.38134 2.75229C3.75222 3.21479 3.29095 3.86969 3.0674 4.61782C2.84384 5.36595 2.87015 6.16656 3.14238 6.8984C2.22542 7.23206 1.43269 7.83861 0.870884 8.63641C0.309073 9.43422 0.00515049 10.385 2.34805e-05 11.3608C-0.00305405 12.3366 0.296461 13.2893 0.857326 14.0879C1.41819 14.8864 2.21282 15.4914 3.13179 15.8195C3.05214 16.2435 3.01275 16.6741 3.01414 17.1054C3.01158 18.5358 3.46368 19.9298 4.30518 21.0864C5.14666 22.2429 6.33397 23.1021 7.69564 23.5398C9.05729 23.9775 10.5228 23.9711 11.8806 23.5214C13.2384 23.0718 14.4181 22.2022 15.2494 21.0384C15.8649 21.5186 16.6204 21.7849 17.4009 21.7969C18.1815 21.8089 18.9447 21.566 19.5747 21.1049C20.2047 20.6438 20.6669 19.9898 20.8915 19.242C21.1161 18.4944 21.0906 17.6938 20.8188 16.9619C21.734 16.6265 22.5246 16.0189 23.0845 15.2211C23.6442 14.4232 23.9465 13.4731 23.9506 12.4984ZM9.27296 3.52899C10.0442 2.40726 11.1788 1.586 12.4853 1.20381C13.7919 0.821635 15.1902 0.901957 16.4444 1.43121C17.6986 1.96048 18.7316 2.90626 19.3694 4.10891C20.0071 5.31156 20.2104 6.69741 19.9447 8.03252L14.6576 12.6631L9.41649 10.2749L8.39297 8.09017L9.27296 3.52899ZM6.62238 2.94075C7.24393 2.94062 7.84828 3.14484 8.34238 3.52193L7.54943 7.60311L3.95885 6.75487C3.80314 6.32609 3.75287 5.86614 3.81229 5.41386C3.87172 4.96158 4.03908 4.53022 4.30026 4.15621C4.56145 3.78221 4.90878 3.47653 5.31293 3.26499C5.71708 3.05344 6.1662 2.94224 6.62238 2.94075ZM0.925906 11.3713C0.931192 10.5387 1.19621 9.72838 1.68401 9.05351C2.17182 8.37865 2.85807 7.87284 3.64708 7.60664L7.58826 8.53722L8.51296 10.5149L3.47414 15.0725C2.72441 14.7865 2.07928 14.2793 1.62421 13.6184C1.16915 12.9574 0.925627 12.1738 0.925906 11.3713ZM14.7012 20.3348C13.9892 21.3831 12.9599 22.1753 11.7643 22.5953C10.5688 23.0152 9.27013 23.0407 8.05905 22.668C6.84795 22.2953 5.78828 21.5441 5.03568 20.5247C4.28307 19.5053 3.8772 18.2714 3.87767 17.0042C3.87822 16.6092 3.91764 16.2152 3.99532 15.8278L9.14826 11.1643L14.4094 13.5619L15.5741 15.7878L14.7012 20.3348ZM17.3341 20.9231C16.7144 20.9209 16.1126 20.7142 15.6224 20.3348L16.4035 16.2666L19.9918 17.1054C20.1479 17.5339 20.1986 17.9934 20.1396 18.4455C20.0808 18.8976 19.914 19.3289 19.6534 19.7031C19.3928 20.0772 19.0461 20.3831 18.6425 20.5951C18.2388 20.8069 17.79 20.9187 17.3341 20.9207V20.9231ZM20.3035 16.2513L16.3529 15.3278L15.3035 13.3278L20.4706 8.80075C21.2209 9.08447 21.8672 9.58986 22.3234 10.2497C22.7796 10.9096 23.0242 11.6926 23.0247 12.4948C23.0173 13.3258 22.7512 14.1336 22.2635 14.8065C21.7759 15.4792 21.0908 15.9834 20.3035 16.2489V16.2513Z" fill="currentColor"/>
      </svg>
    </span>
  );
}

function Glossary({ items }: { items: GlossaryItem[] }) {
  return (
    <Stack gap={2}>
      {items.map((it) => (
        <div key={it.key}>
          <CollapsibleSection
            title={it.key}
            count={it.n}
            trailing={<Text size="small" tone="tertiary">indices</Text>}
          >
            <Stack gap={6} style={{ paddingBottom: 8 }}>
              <Text tone="secondary" size="small">{it.desc}</Text>
              <Text size="small" tone="tertiary">Triggered by fields like</Text>
              <Text size="small" style={MONO}>{it.fields}</Text>
            </Stack>
          </CollapsibleSection>
        </div>
      ))}
    </Stack>
  );
}

export default function EnvironmentBrief() {
  const d = DATA;
  const caption =
    "Source: profile-environment · " + d.scopeLevel + " " + d.cluster + " · " + d.generatedAt.slice(0, 10);

  return (
    <Stack gap={20} style={{ padding: 24, maxWidth: 1120 }}>
      <Stack gap={4}>
        <Row align="center" gap={12}>
          <ElasticGlyph />
          <H1>{d.cluster} — hunt readiness brief</H1>
          <Spacer />
          <Pill size="sm">scope {d.scopeId.slice(0, 8)}</Pill>
          <Pill size="sm">{d.errors === 0 ? "0 collection errors" : d.errors + " collection errors"}</Pill>
        </Row>
        <Text tone="tertiary" size="small">{caption}</Text>
      </Stack>

      {d.isSample && (
        <Callout tone="warning" title="Sample / demo data">
          This deployment carries the sample-data marker — treat it as a Showroom, not a real customer environment.
        </Callout>
      )}

      <Callout tone="info" title="What this cluster is">
        <Stack gap={6}>
          <Text>{d.summaryLine}</Text>
          {d.notes.length > 0 && (
            <Stack gap={2}>
              {d.notes.map((n) => (
                <div key={n}><Text tone="secondary" size="small">• {n}</Text></div>
              ))}
            </Stack>
          )}
        </Stack>
      </Callout>

      <Grid columns={4} gap={12}>
        <Stat value={String(d.stats.dataStreams)} label="Data streams" />
        <Stat value={d.stats.huntTotal + " (" + d.stats.huntEcs + " ECS / " + d.stats.huntOff + " off)"} label="Hunt indices" />
        <Stat
          value={d.stats.rulesEnabled.toLocaleString() + " / " + d.stats.rulesTotal.toLocaleString()}
          label="Rules enabled / total"
          tone={d.stats.rulesTotal > 0 && d.stats.rulesEnabled / d.stats.rulesTotal < 0.25 ? "warning" : undefined}
        />
        <Stat
          value={d.stats.entities.toLocaleString()}
          label="Entities (risk engine)"
          tone={d.stats.entities === 0 ? "danger" : undefined}
        />
      </Grid>

      {d.biggest.length > 0 && (
        <Stack gap={8}>
          <H2>Biggest data by volume</H2>
          <Text tone="secondary" size="small">
            Volume is a poor proxy for hunt value — the profiler ranks hunt targets by huntable breadth, not size.
          </Text>
          <Table
            headers={["Index", "Docs", "Role"]}
            columnAlign={["left", "right", "left"]}
            rows={d.biggest.map((b) => [
              <Text as="span" style={MONO}>{b.name}</Text>,
              fmt(b.docs),
              <Text as="span" tone="secondary">{b.note}</Text>,
            ])}
          />
        </Stack>
      )}

      {d.hunt.length > 0 && (
        <Stack gap={8}>
          <H2>Top hunt targets</H2>
          <Text tone="secondary" size="small">
            Ranked by derived hunt-primitive richness. ECS = standard logs-*/.alerts naming (the happy path); off = custom-named.
          </Text>
          <Table
            headers={["Index", "Schema", "Class", "Docs", "Primitives", "Join keys", "Lineage"]}
            columnAlign={["left", "left", "left", "right", "right", "right", "left"]}
            rowTone={d.hunt.map((h) => (h.lineage === "full" ? "success" : h.lineage === "parent_only" ? "warning" : undefined))}
            rows={d.hunt.map((h) => [
              <Text as="span" style={MONO} truncate>{h.name}</Text>,
              <Pill size="sm" active={h.schema === "ecs"}>{h.schema === "ecs" ? "ECS" : "off"}</Pill>,
              <Pill size="sm">{h.dataClass}</Pill>,
              fmt(h.docs),
              String(h.prims),
              String(h.keys),
              h.lineage,
            ])}
          />
        </Stack>
      )}

      {(d.primitives.length > 0 || d.joins.length > 0) && (
        <Grid columns={2} gap={16}>
          {d.primitives.length > 0 && (
            <Card>
              <CardHeader>Hunt-primitive coverage</CardHeader>
              <CardBody>
                <BarChart
                  horizontal
                  showValues
                  height={300}
                  categories={d.primitives.map((p) => p.key)}
                  series={[{ name: "Hunt indices", data: d.primitives.map((p) => p.n), tone: "info" }]}
                />
                <Text tone="tertiary" size="small">x-axis: # of hunt indices supporting each primitive. {caption}</Text>
              </CardBody>
            </Card>
          )}
          {d.joins.length > 0 && (
            <Card>
              <CardHeader>Joinability — indices per pivot key</CardHeader>
              <CardBody>
                <BarChart
                  horizontal
                  showValues
                  height={300}
                  categories={d.joins.map((j) => j.key)}
                  series={[{ name: "Hunt indices", data: d.joins.map((j) => j.n), tone: "success" }]}
                />
                <Text tone="tertiary" size="small">x-axis: # of hunt indices carrying each join key (mutually joinable). {caption}</Text>
              </CardBody>
            </Card>
          )}
        </Grid>
      )}

      {(d.primitiveGlossary.length > 0 || d.joinGlossary.length > 0) && (
        <Stack gap={8}>
          <H2>Field glossary</H2>
          <Text tone="secondary" size="small">
            Click any row to see what the technique detects and which field shapes the profiler keys on. Counts match the charts above.
          </Text>
          <Grid columns={2} gap={24} align="start">
            {d.primitiveGlossary.length > 0 && (
              <Stack gap={6}>
                <H3>Hunt primitives</H3>
                <Glossary items={d.primitiveGlossary} />
              </Stack>
            )}
            {d.joinGlossary.length > 0 && (
              <Stack gap={6}>
                <H3>Join keys</H3>
                <Glossary items={d.joinGlossary} />
              </Stack>
            )}
          </Grid>
        </Stack>
      )}

      {d.response.length > 0 && (
        <Stack gap={8}>
          <H2>Response capabilities</H2>
          {d.responseNote && <Text tone="secondary" size="small">{d.responseNote}</Text>}
          <Grid columns={4} gap={12}>
            {d.response.map((r) => (
              <div key={r.key}><Stat value={String(r.n)} label={r.key} /></div>
            ))}
          </Grid>
        </Stack>
      )}

      {d.defend.length > 0 && (
        <Stack gap={8}>
          <H2>Endpoint protection posture</H2>
          <Table
            headers={["Policy", "OS", "Protections (intended)"]}
            rows={d.defend.map((p) => [
              <Text as="span">{p.policy}</Text>,
              p.os,
              <Text as="span" tone="secondary" size="small">{p.protections}</Text>,
            ])}
          />
          {d.thirdParty.length > 0 && (
            <Text tone="secondary" size="small">Third-party endpoint present: {d.thirdParty.join(", ")}</Text>
          )}
        </Stack>
      )}

      {(d.intelSources.length > 0 || d.mirrors.length > 0) && (
        <Grid columns={2} gap={16}>
          {d.intelSources.length > 0 && (
            <Stack gap={8}>
              <H2>Intel / enrichment sources</H2>
              <Text tone="secondary" size="small">Match telemetry against these — not hunt targets.</Text>
              <Stack gap={4}>
                {d.intelSources.map((s) => (
                  <div key={s}><Text size="small" style={MONO}>{s}</Text></div>
                ))}
              </Stack>
            </Stack>
          )}
          {d.mirrors.length > 0 && (
            <Stack gap={8}>
              <H2>Duplicate mirrors collapsed</H2>
              <Text tone="secondary" size="small">Byte-for-byte reindex copies removed from the hunt list.</Text>
              <Stack gap={4}>
                {d.mirrors.map((m) => (
                  <div key={m.name}>
                    <Text size="small">
                      <Text as="span" style={MONO}>{m.name}</Text>
                      <Text as="span" tone="tertiary"> → {m.mirror_of}</Text>
                    </Text>
                  </div>
                ))}
              </Stack>
            </Stack>
          )}
        </Grid>
      )}

      {d.blindSpots.length > 0 && (
        <>
          <Divider />
          <Stack gap={8}>
            <H2>Coverage gaps</H2>
            {d.blindSpots.map((b) => (
              <div key={b}><Callout tone="danger">{b}</Callout></div>
            ))}
          </Stack>
        </>
      )}

      {d.integrations.length > 0 && (
        <Stack gap={8}>
          <H2>Installed integrations</H2>
          <Row gap={8} wrap>
            {d.integrations.map((i) => (
              <div key={i}><Pill size="sm">{i}</Pill></div>
            ))}
          </Row>
          <Text tone="tertiary" size="small">
            Cases: {d.capabilities.cases ? "yes" : "no"} · Entity Analytics: {d.capabilities.entity_analytics ? "yes" : "no"} · Attack Discovery: {d.capabilities.attack_discovery ? "yes" : "no"} · Correlation corpus: {d.capabilities.correlation_corpus ? "yes" : "no"}.
          </Text>
        </Stack>
      )}
    </Stack>
  );
}
`;
