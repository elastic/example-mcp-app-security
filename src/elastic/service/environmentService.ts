/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from "crypto";
import type { EsqlResult } from "../../shared/types.js";
import {
  applyCatalog,
  emptyCatalog,
  signatureFor,
  type CatalogData,
  type ClassificationCatalog,
} from "../../shared/classification-catalog.js";
import { PRIMITIVES_SUPPORTED_BY_CLASS } from "../../shared/environment-profile.js";
import type {
  ActiveDataStream,
  Capabilities,
  CapabilityDomain,
  DataClass,
  DefendPolicyPosture,
  DefendProtection,
  EndpointPosture,
  EntityCounts,
  EnvironmentInventory,
  EnvironmentProfile,
  AffordanceConfidence,
  AffordanceSource,
  FieldFact,
  FieldReality,
  IdentityFields,
  IdentityResolution,
  HuntableFieldGroup,
  HuntPrimitive,
  IndexAffordances,
  IndexRole,
  IntegrationPresence,
  IocClass,
  JoinKey,
  JoinKeyKind,
  LineageSignals,
  MatchedAtomic,
  OffSchemaIndex,
  PopulatedField,
  PrimitiveSupport,
  ProcessTreeCapability,
  RuleFields,
  SchemaAlignment,
  ProfileScope,
  ProtectionMode,
  ProtectionName,
  ResponseCapabilities,
  ResponseConnector,
  RuleInventory,
  ScopeLevel,
  Terrain,
  ThirdPartyEndpoint,
} from "../../shared/environment-profile.js";
import type {
  EnvironmentClient,
  RawActionConnector,
  RawPackagePolicy,
} from "../client/environmentClient.js";

export interface ProfileEnvironmentOptions {
  /** Scope granularity; defaults to `deployment` (single-cluster leaf). */
  readonly level?: ScopeLevel;
  /** Kibana space id, when scoping to one tenant. */
  readonly space?: string;
  /** Index pattern, when scoping to one feed. */
  readonly indexPattern?: string;
}

/** One human/LLM-approved classification the tool writes back to the catalog. */
export interface ClassificationApproval {
  /** Index name (for readability in the catalog). */
  readonly name: string;
  /** Shape signature from the profile output — the catalog key. */
  readonly signature: string;
  /** Approved capabilities. `source` defaults to `"human"` when omitted. */
  readonly affordances: Omit<IndexAffordances, "source"> & {
    readonly source?: AffordanceSource;
  };
  /** Optional analyst note explaining the correction. */
  readonly note?: string;
}

const PROTECTIONS: ProtectionName[] = [
  "malware",
  "ransomware",
  "memory_protection",
  "behavior_protection",
];

/** Time window for terrain population probes — bounds cost and reflects recency. */
const TERRAIN_LOOKBACK = "30 days";

/**
 * How many off-schema candidates to inspect with `_field_caps`. Field caps is
 * cheap metadata (flat cost vs doc volume), so we probe well beyond the biggest
 * few — raw volume is a poor proxy for hunt value (operational indices like
 * `*_ilm_stats` are huge but useless; threat-intel/EDR corpora are mid-sized
 * but gold). We inspect broadly, then rank the *results* by huntable breadth.
 */
const OFF_SCHEMA_PROBE_LIMIT = 60;

/** How many candidates to select purely by volume vs. purely by huntable name. */
const PROBE_TOP_BY_VOLUME = 40;
const PROBE_TOP_BY_NAME = 40;

/** How many hunt-target indices (ECS + off-schema) to surface (ranked by breadth). */
const HUNT_DISPLAY_LIMIT = 40;

/** Run async work in bounded-concurrency chunks to avoid connection storms. */
async function inChunks<T, R>(
  items: T[],
  size: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(...(await Promise.all(items.slice(i, i + size).map(fn))));
  }
  return out;
}

/**
 * Canonical aliases for prime huntable data that lives behind dot-prefixed
 * backing indices (excluded from plain-index enumeration). Probing the alias
 * yields one merged entry instead of dozens of backing indices. `.siem-signals-*`
 * is intentionally omitted: on migrated clusters it aliases the same union as
 * `.alerts-security.alerts-*`, so probing both would double-count.
 */
const KNOWN_ALERT_INDEX_PATTERNS = [".alerts-security.alerts-*"];

/** Cap fields listed per huntable category so a wide index doesn't flood output. */
const HUNTABLE_FIELDS_PER_CATEGORY = 20;

/**
 * Deterministic classifier for discovering huntable material inside non-ECS
 * indices. Matched in order (first match wins), so more specific categories
 * precede general ones. `family` links a category back to a telemetry family so
 * blind-spot logic can credit off-schema coverage; categories without a family
 * are pure observables (hashes, urls, intel enrichments).
 *
 * Kept as data (not inline logic) so the same field list always yields the same
 * classification on a fresh run.
 */
interface HuntCategoryMatcher {
  readonly category: string;
  readonly family?: string;
  readonly types?: string[];
  readonly nameRe?: RegExp;
}

const HUNT_CATEGORIES: HuntCategoryMatcher[] = [
  { category: "hash", nameRe: /(?:^|[._])(?:md5|sha1|sha256|sha512|imphash|ssdeep|mmh3|jarm|ja3|ja4)(?:$|[._])|fingerprint|(?:^|[._])hash(?:$|[._])/i },
  { category: "command_line", family: "process", nameRe: /command[_.]?line|cmd[_.]?line|(?:^|[._])command(?:$|[._])/i },
  { category: "executable", family: "process", nameRe: /exe[_.]?(?:name|path)|(?:^|[._])exe(?:$|[._])|process[._](?:name|executable)|(?:^|[._])image(?:$|[._])|binary[_.]?(?:name|path)/i },
  { category: "process", family: "process", nameRe: /(?:^|[._])process(?:$|[._])|parent[._]|(?:^|[._])p?pid(?:$|[._])/i },
  { category: "ip", family: "network", types: ["ip"], nameRe: /(?:^|[._])ip(?:$|[._])|ip[_.]?addr|(?:^|[._])addr(?:ess)?(?:$|[._])/i },
  { category: "port", family: "network", nameRe: /(?:^|[._])port(?:$|[._])/i },
  { category: "domain", family: "dns", nameRe: /(?:^|[._])domain|fqdn|nameserver|hostname/i },
  { category: "dns", family: "dns", nameRe: /(?:^|[._])dns(?:$|[._])|pdns|resolv/i },
  { category: "url", nameRe: /(?:^|[._])url(?:$|[._])|(?:^|[._])uri(?:$|[._])/i },
  { category: "file", family: "file", nameRe: /(?:^|[._])file(?:$|[._])|file[_.]?(?:name|path)|(?:^|[._])path(?:$|[._])/i },
  { category: "registry", nameRe: /registry|regkey|reg[_.]?path/i },
  { category: "user", family: "authentication", nameRe: /(?:^|[._])user|account|logon|principal|(?:^|[._])email(?:$|[._])/i },
  { category: "host", family: "host", nameRe: /(?:^|[._])host|endpoint|(?:^|[._])device|machine|agent[._](?:name|id|version)/i },
  { category: "network", family: "network", nameRe: /network|connection|(?:^|[._])conn(?:$|[._])|(?:^|[._])flow(?:$|[._])|bytes[_.]?(?:in|out|sent|received)/i },
  { category: "intel", nameRe: /virustotal|(?:^|[._])vt(?:$|[._])|reputation|malicious|suspicious|shodan|(?:^|[._])threat|abuse/i },
];

/**
 * Security-relevant index/stream *name* tokens. A stream whose name matches is
 * always worth probing even when its volume is unknown — some tiers (frozen /
 * searchable-snapshot backing indices) report null in `_cat/indices` and the
 * data-stream stats API, so a pure volume gate silently drops rich streams like
 * `alert_telemetry_*` / `alert_timelines_*`. Name is the resilient fallback.
 */
const HUNT_NAME_RE =
  /alert|signal|siem|edr|endpoint|telemetry|timeline|detection|threat|intel|ioc|indicator|malware|behavior|hunt|process|network|dns|auth|identity|cloudtrail|audit|cti|anomal|sysmon|winlog|logon|event/i;

/**
 * Index-name tokens that mark an intelligence / enrichment source (IOC feeds,
 * reputation, CTI, external scans) rather than environment telemetry. Note
 * `telemetry` is deliberately NOT a telemetry signal — it's a local naming
 * convention here (e.g. `custom_telemetry_wardenseye` is an external HTTP prober,
 * not telemetry).
 */
const INTEL_NAME_RE =
  /(?:^|[._-])(?:indicator|indicators|ioc|iocs|threat[_-]?intel|threatintel|reputation|enrichment|enrich|cti|feed|feeds|taxii|misp|otx|abuse|watchlist|blocklist|blocklists|denylist|allowlist|stix|intel)(?:[._-]|$)/i;

/**
 * Canonical hunt fields grouped by telemetry family. Each family probes one
 * index pattern; a family with no matching data is a blind spot, not a probe
 * failure.
 */
const FIELD_FAMILIES: { family: string; pattern: string; fields: string[] }[] = [
  { family: "host", pattern: "logs-*", fields: ["host.name", "host.os.platform", "host.ip"] },
  { family: "process", pattern: "logs-endpoint.events.process-*", fields: ["process.name", "process.command_line", "process.parent.name"] },
  { family: "network", pattern: "logs-endpoint.events.network-*,logs-network_traffic.*", fields: ["source.ip", "destination.ip", "network.protocol"] },
  { family: "dns", pattern: "logs-endpoint.events.network-*,logs-*.dns-*", fields: ["dns.question.name"] },
  { family: "file", pattern: "logs-endpoint.events.file-*", fields: ["file.path", "file.hash.sha256"] },
  { family: "authentication", pattern: "logs-*", fields: ["user.name", "event.outcome"] },
  { family: "cloud", pattern: "logs-aws.*,logs-azure.*,logs-gcp.*,logs-o365*,logs-google_workspace.*", fields: ["cloud.provider", "cloud.account.id", "event.action"] },
];

/** Third-party endpoint vendor -> installed package name(s). */
const THIRD_PARTY_ENDPOINT: {
  vendor: ThirdPartyEndpoint["vendor"];
  packages: string[];
}[] = [
  { vendor: "crowdstrike", packages: ["crowdstrike"] },
  { vendor: "sentinel_one", packages: ["sentinel_one"] },
  {
    vendor: "ms_defender_endpoint",
    packages: ["microsoft_defender_endpoint", "m365_defender"],
  },
];

/**
 * Kibana connector type id -> capability. LLM connectors are intentionally
 * excluded; they are not a response surface.
 */
const CONNECTOR_MAP: Record<
  string,
  { domain: CapabilityDomain; actions: string[]; reveals?: string }
> = {
  ".crowdstrike": { domain: "endpoint", actions: ["isolate_host", "run_command"], reveals: "crowdstrike" },
  ".sentinelone": { domain: "endpoint", actions: ["isolate_host", "run_script"], reveals: "sentinel_one" },
  ".microsoft_defender_endpoint": { domain: "endpoint", actions: ["isolate_host"], reveals: "ms_defender_endpoint" },
  ".servicenow": { domain: "ticketing", actions: ["create_ticket"], reveals: "servicenow" },
  ".servicenow-sir": { domain: "ticketing", actions: ["create_security_incident"], reveals: "servicenow" },
  ".servicenow-itom": { domain: "ticketing", actions: ["create_event"], reveals: "servicenow" },
  ".jira": { domain: "ticketing", actions: ["create_issue"], reveals: "jira" },
  ".thehive": { domain: "ticketing", actions: ["create_case", "create_alert"], reveals: "thehive" },
  ".swimlane": { domain: "ticketing", actions: ["create_record"], reveals: "swimlane" },
  ".resilient": { domain: "ticketing", actions: ["create_incident"], reveals: "ibm_resilient" },
  ".cases-webhook": { domain: "ticketing", actions: ["create_case"] },
  ".tines": { domain: "automation", actions: ["trigger_story"], reveals: "tines" },
  ".torq": { domain: "automation", actions: ["trigger_workflow"], reveals: "torq" },
  ".d3security": { domain: "automation", actions: ["trigger_workflow"], reveals: "d3_security" },
  // Enrichment / intel lookups — a capability, not a notification surface.
  ".virustotal": { domain: "enrich", actions: ["lookup"], reveals: "virustotal" },
  // Generic automation / integration surfaces.
  ".webhook": { domain: "automation", actions: ["http_request"] },
  ".github": { domain: "automation", actions: ["invoke"], reveals: "github" },
  ".index": { domain: "automation", actions: ["index_document"] },
  // Cases connector creates/updates Kibana cases.
  ".case": { domain: "ticketing", actions: ["create_case"] },
  ".email": { domain: "notify", actions: ["send_email"] },
  ".slack": { domain: "notify", actions: ["post_message"] },
  ".slack_api": { domain: "notify", actions: ["post_message"] },
  ".teams": { domain: "notify", actions: ["post_message"] },
  ".pagerduty": { domain: "notify", actions: ["trigger_incident"] },
  ".opsgenie": { domain: "notify", actions: ["create_alert"] },
  ".xmatters": { domain: "notify", actions: ["trigger"] },
  ".server-log": { domain: "other", actions: ["invoke"] },
};

const EXCLUDED_CONNECTOR_TYPES = new Set([
  ".gen-ai",
  ".bedrock",
  ".gemini",
  ".inference",
  ".observability-ai-assistant",
]);

interface EnvironmentServiceOptions {
  readonly environmentClient: EnvironmentClient;
  /**
   * Optional sticky-verdict store. When present, approved classifications are
   * re-applied to matching index shapes on every run, and {@link
   * EnvironmentService.approveClassifications} can persist new approvals.
   */
  readonly catalog?: ClassificationCatalog;
}

/**
 * Runs an IPB/IPOE inventory pass and assembles a leaf {@link EnvironmentProfile}.
 *
 * Every probe is isolated: a failure degrades its section (and is recorded in
 * `collection_errors`) rather than failing the whole profile. This mirrors the
 * guiding principle that the profile is evidence about a messy environment, not
 * a guarantee that every probe succeeded.
 */
export class EnvironmentService {
  constructor(private readonly options: EnvironmentServiceOptions) {}

  async profileEnvironment(
    opts: ProfileEnvironmentOptions = {}
  ): Promise<EnvironmentProfile> {
    const errors: string[] = [];
    const client = this.options.environmentClient;

    const scope = this.buildScope(client.clusterName, opts);

    const inventory = await this.safe(
      errors,
      "inventory",
      () => this.buildInventory(errors),
      emptyInventory()
    );
    const endpoint_posture = await this.safe(
      errors,
      "endpoint_posture",
      () => this.buildEndpointPosture(inventory.integration_presence),
      { defend: [], third_party: [] }
    );
    const response_capabilities = await this.safe(
      errors,
      "response_capabilities",
      () => this.buildResponseCapabilities(),
      { connectors: [] }
    );
    const terrain = await this.safe(
      errors,
      "terrain",
      () => this.buildTerrain(inventory),
      emptyTerrain()
    );
    const capabilities = await this.safe(
      errors,
      "capabilities",
      () => this.buildCapabilities(inventory),
      emptyCapabilities()
    );

    return {
      scope,
      generated_at: new Date().toISOString(),
      inventory,
      endpoint_posture,
      response_capabilities,
      terrain,
      capabilities,
      collection_errors: errors,
    };
  }

  /**
   * Persist approved (human- or LLM-confirmed) classifications to the catalog.
   * Each approval is keyed by the index shape {@link signatureFor}, so on the
   * next run any index with a matching shape adopts the sticky verdict. This is
   * the write half of the human-in-the-loop: the tool passes back the affordances
   * the analyst approved (or corrected), stamped `source: "human"`.
   *
   * No-ops (returns the current catalog) when no catalog store is configured.
   */
  async approveClassifications(
    approvals: ClassificationApproval[]
  ): Promise<CatalogData> {
    const store = this.options.catalog;
    if (!store) return emptyCatalog();
    const current = await store.load().catch(() => emptyCatalog());
    const entries = { ...current.entries };
    const now = new Date().toISOString();
    for (const a of approvals) {
      if (!a.signature) continue;
      entries[a.signature] = {
        signature: a.signature,
        name: a.name,
        affordances: { ...a.affordances, source: a.affordances.source ?? "human" },
        approved_at: now,
        ...(a.note ? { note: a.note } : {}),
      };
    }
    const next: CatalogData = { version: current.version, entries };
    await store.save(next);
    return next;
  }

  private buildScope(
    clusterName: string,
    opts: ProfileEnvironmentOptions
  ): ProfileScope {
    const level: ScopeLevel =
      opts.level ??
      (opts.space ? "space" : opts.indexPattern ? "datastream" : "deployment");
    const ref: ProfileScope["ref"] = {
      deployment: clusterName,
      ...(opts.space ? { space: opts.space } : {}),
      ...(opts.indexPattern ? { index_pattern: opts.indexPattern } : {}),
    };
    const scope_id = createHash("sha1")
      .update(JSON.stringify({ level, ref }))
      .digest("hex")
      .slice(0, 16);
    return { level, ref, scope_id };
  }

  /**
   * Assemble the inventory. Each probe is isolated and records into `errors`
   * (prefixed `inventory.*`) on failure; a single failed probe degrades only
   * its slice, never the whole inventory.
   */
  private async buildInventory(errors: string[]): Promise<EnvironmentInventory> {
    const client = this.options.environmentClient;

    const dataStreams = await this.safe(
      errors,
      "inventory.data_streams",
      () => this.buildDataStreams(),
      []
    );
    // Data streams are only half the story: a lot of huntable data lives in
    // plain indices (exports, reindexes, imports) that `GET /_data_stream`
    // never returns. Fold those in so terrain/off-schema discovery can see them.
    const standalone = await this.safe(
      errors,
      "inventory.standalone_indices",
      () => this.buildStandaloneIndices(dataStreams),
      []
    );
    // Detection alerts live behind dot-prefixed backing indices skipped above;
    // probe their canonical alias so this prime hunt surface is represented.
    const alertAliases = await this.safe(
      errors,
      "inventory.alert_indices",
      () => this.probeAlertAliases(),
      []
    );
    const active_data_streams = [...dataStreams, ...standalone, ...alertAliases];
    const installed = await this.safe(
      errors,
      "inventory.integrations",
      async () => (await client.getInstalledPackages()).map((p) => p.name),
      []
    );
    const integration_presence = buildIntegrationPresence(installed);
    const os_mix = await this.safe(
      errors,
      "inventory.os_mix",
      () => this.probeOsMix(),
      {}
    );
    const entity_counts = await this.safe(
      errors,
      "inventory.entity_counts",
      () => this.probeEntityCounts(),
      { host: 0, user: 0, service: 0, generic: 0 }
    );
    const rule_inventory = await this.safe(
      errors,
      "inventory.rule_inventory",
      () => this.buildRuleInventory(),
      { total: 0, enabled: 0, disabled: 0 }
    );

    return {
      active_data_streams,
      integration_presence,
      deployed_tech: {
        cloud_providers: cloudProviders(integration_presence),
        os_mix,
      },
      entity_counts,
      rule_inventory,
    };
  }

  private async buildDataStreams(): Promise<ActiveDataStream[]> {
    const client = this.options.environmentClient;
    const [streams, stats] = await Promise.all([
      client.getDataStreams(),
      client.getDataStreamStats().catch(() => []),
    ]);

    const statByName = new Map(stats.map((s) => [s.data_stream, s]));

    // Best-effort doc counts by summing backing indices (`.ds-<name>-<date>-<gen>`).
    const docCountByStream = new Map<string, number>();
    try {
      const rows = await client.catDocCounts(".ds-*");
      for (const stream of streams) {
        let total = 0;
        for (const row of rows) {
          if (row.index.startsWith(`.ds-${stream.name}-`)) {
            total += Number(row["docs.count"] || 0);
          }
        }
        docCountByStream.set(stream.name, total);
      }
    } catch {
      // Doc counts are best-effort; leave undefined on failure.
    }

    return streams.map((s) => {
      const stat = statByName.get(s.name);
      const docs = docCountByStream.get(s.name);
      const metaDescription =
        s._meta?.description ??
        (s._meta?.package?.name
          ? `package=${s._meta.package.name}${s._meta.managed_by ? `; managed_by=${s._meta.managed_by}` : ""}`
          : s._meta?.managed_by
            ? `managed_by=${s._meta.managed_by}`
            : undefined);
      return {
        name: s.name,
        dataset: parseDataset(s.name),
        integration: s._meta?.package?.name ?? s.template,
        doc_count: docs,
        store_size_bytes: stat?.store_size_bytes,
        last_seen: stat?.maximum_timestamp,
        meta_description: metaDescription,
      };
    });
  }

  /**
   * Discover standalone (non-data-stream) indices holding data. Skips internal
   * dot-indices and `.ds-*` data-stream backing indices (already represented by
   * their stream), and anything already listed as a data stream. Each surviving
   * index becomes an off-schema candidate for terrain/huntable-field discovery.
   */
  private async buildStandaloneIndices(
    dataStreams: ActiveDataStream[]
  ): Promise<ActiveDataStream[]> {
    const rows = await this.options.environmentClient.catIndices();
    const known = new Set(dataStreams.map((d) => d.name));
    return rows
      .filter((r) => {
        const name = r.index ?? "";
        return (
          name &&
          // Skip internal dot-indices and every data-stream backing index —
          // including ILM-managed `shrink-*`/`partial-*`/`restored-*` variants,
          // which embed `.ds-` but don't start with a dot.
          !name.startsWith(".") &&
          !name.includes(".ds-") &&
          !known.has(name) &&
          Number(r["docs.count"] ?? 0) > 0
        );
      })
      .map((r) => ({
        name: r.index,
        dataset: parseDataset(r.index),
        doc_count: Number(r["docs.count"] ?? 0),
        store_size_bytes: Number(r["store.size"] ?? 0) || undefined,
      }));
  }

  /**
   * Probe the canonical alert aliases (dot-prefixed, so excluded from plain
   * index enumeration) via a tolerant `_count`. Each non-empty alias becomes a
   * single inventory entry rather than dozens of backing indices.
   */
  private async probeAlertAliases(): Promise<ActiveDataStream[]> {
    const out: ActiveDataStream[] = [];
    for (const pattern of KNOWN_ALERT_INDEX_PATTERNS) {
      const doc_count = await this.options.environmentClient.count(pattern);
      if (doc_count > 0) {
        out.push({ name: pattern, integration: "detection_alerts", doc_count });
      }
    }
    return out;
  }

  private async probeOsMix(): Promise<Record<string, number>> {
    const result = await this.options.environmentClient.runEsql(
      "FROM logs-* | WHERE host.os.platform IS NOT NULL " +
        "| STATS hosts = COUNT_DISTINCT(host.name) BY platform = host.os.platform " +
        "| LIMIT 25"
    );
    return esqlToRecord(result, "platform", "hosts");
  }

  private async probeEntityCounts(): Promise<EntityCounts> {
    const zero: EntityCounts = { host: 0, user: 0, service: 0, generic: 0 };
    // Matches both Entity Store v1 (`.entities.v1.latest.security_<type>_*`) and
    // v2 (unified `.entities.v2.latest.security_<space>`). v2 reports capitalized
    // `entity.type` values (e.g. "Host"), so fold case-insensitively.
    let result: EsqlResult;
    try {
      result = await this.options.environmentClient.runEsql(
        "FROM .entities.*.latest* | STATS c = COUNT(*) BY type = entity.type | LIMIT 25"
      );
    } catch (e) {
      // When no entity-store index exists (Entity Analytics never enabled), the
      // pattern matches zero indices and ES|QL rejects `entity.type` as an
      // unknown column. That's an absent capability, not a collection failure —
      // degrade to zero counts. Any other error (auth, transport) still bubbles.
      if (isMissingEntityStoreError(e)) return zero;
      throw e;
    }
    const raw = esqlToRecord(result, "type", "c");
    const byType: Record<string, number> = {};
    for (const [k, v] of Object.entries(raw)) {
      const key = k.toLowerCase();
      byType[key] = (byType[key] ?? 0) + v;
    }
    return {
      host: byType.host ?? 0,
      user: byType.user ?? 0,
      service: byType.service ?? 0,
      generic: byType.generic ?? 0,
    };
  }

  private async buildRuleInventory(): Promise<RuleInventory> {
    const client = this.options.environmentClient;
    const [total, enabled] = await Promise.all([
      client.countRules(),
      client.countRules("alert.attributes.enabled: true"),
    ]);
    return { total, enabled, disabled: Math.max(0, total - enabled) };
  }

  private async buildEndpointPosture(
    presence: IntegrationPresence
  ): Promise<EndpointPosture> {
    const client = this.options.environmentClient;
    const defend = presence.endpoint
      ? parseDefendPolicies(await client.getPackagePolicies("endpoint"))
      : [];

    const installed = presence.installed;
    const third_party: ThirdPartyEndpoint[] = THIRD_PARTY_ENDPOINT.map((v) => ({
      vendor: v.vendor,
      present: v.packages.some((p) => installed.includes(p)),
      telemetry_datasets: v.packages.filter((p) => installed.includes(p)),
    })).filter((t) => t.present);

    return { defend, third_party };
  }

  private async buildResponseCapabilities(): Promise<ResponseCapabilities> {
    const connectors = await this.options.environmentClient.getConnectors();
    return { connectors: mapConnectors(connectors) };
  }

  /**
   * Probe which canonical hunt fields are actually populated (not just mapped)
   * and derive human-readable gaps. A family whose index is absent or empty is
   * a blind spot; only unexpected failures propagate as collection errors.
   */
  private async buildTerrain(inventory: EnvironmentInventory): Promise<Terrain> {
    const client = this.options.environmentClient;
    const populated_ecs_fields: PopulatedField[] = [];
    const populatedFamilies = new Set<string>();

    for (const { family, pattern, fields } of FIELD_FAMILIES) {
      try {
        const fieldsForEsql = fields
          .map((f, i) => `f${i} = COUNT(\`${f}\`)`)
          .join(", ");
        const result = await client.runEsql(
          `FROM ${pattern} | WHERE @timestamp > NOW() - ${TERRAIN_LOOKBACK} ` +
            `| STATS total = COUNT(*), ${fieldsForEsql}`
        );
        const row = result.values[0] ?? [];
        const colIdx = (name: string) =>
          result.columns.findIndex((c) => c.name === name);
        const total = Number(row[colIdx("total")] ?? 0);
        if (total === 0) continue;

        const caps = await client
          .getFieldCaps(pattern, fields)
          .catch(() => ({} as Record<string, Record<string, unknown>>));

        fields.forEach((field, i) => {
          const count = Number(row[colIdx(`f${i}`)] ?? 0);
          const detected_types = Object.keys(caps[field] ?? {});
          populated_ecs_fields.push({
            field,
            family,
            population_ratio: total > 0 ? round(count / total) : 0,
            detected_types,
            type_conflict: detected_types.length > 1,
          });
          if (count > 0) populatedFamilies.add(family);
        });
      } catch {
        // Missing index / no @timestamp => the family is a blind spot, handled below.
      }
    }

    // Hunt indices a worker should actually target: ECS-shaped streams that
    // *hold data*, ranked by volume. Empty `logs-*`/system streams (common on
    // analytics or freshly-provisioned clusters) are dropped so workers don't
    // point at nothing.
    const resolved_hunt_indices = [...inventory.active_data_streams]
      .filter(
        (d) =>
          (d.name.startsWith("logs-") || d.name.startsWith(".alerts-security")) &&
          (d.doc_count ?? 0) > 0
      )
      .sort((a, b) => (b.doc_count ?? 0) - (a.doc_count ?? 0))
      .map((d) => d.name);

    const offSchema = inventory.active_data_streams.filter(
      (d) =>
        !d.name.startsWith("logs-") &&
        !d.name.startsWith("metrics-") &&
        !d.name.startsWith(".alerts")
    );
    const off_schema_indices = offSchema.map((d) => d.name);

    // Where the data actually is: probe the mappings of the non-ECS streams for
    // huntable material (cheap `_field_caps` metadata only — no scans over
    // billion-doc indices). This is what saves a hunt worker on a cluster whose
    // real telemetry lives in custom-named indices. Alert aliases are included
    // so their (rich) field map is recovered too. We probe broadly (not just the
    // biggest few) because raw volume is a poor proxy for hunt value.
    const alertStreams = inventory.active_data_streams.filter((d) =>
      KNOWN_ALERT_INDEX_PATTERNS.includes(d.name)
    );
    const offSchemaByVolume = [...offSchema]
      .filter((d) => (d.doc_count ?? d.store_size_bytes ?? 0) > 0)
      .sort(
        (a, b) =>
          (b.doc_count ?? 0) - (a.doc_count ?? 0) ||
          (b.store_size_bytes ?? 0) - (a.store_size_bytes ?? 0)
      );
    // ECS happy-path hunt streams (`logs-*` / `.alerts*` / `.entities*`) are
    // first-class hunt targets — probe them with the same field-shape classifier
    // so a normal customer deployment gets full per-index primitives, join keys,
    // and lineage, not just aggregate ECS coverage.
    const ecsHunt = inventory.active_data_streams.filter((d) =>
      isEcsHuntStream(d.name)
    );
    // Select probe candidates by volume UNION huntable-name, so streams whose
    // size is unreported (frozen/searchable-snapshot tiers → null in cat/stats)
    // are still inspected via `_field_caps` (metadata, tier-independent).
    const probeSet = selectProbeCandidates([
      ...offSchema,
      ...ecsHunt,
      ...alertStreams,
    ]);
    const probedRaw = await this.probeOffSchema(probeSet);

    // Apply sticky catalog verdicts over the heuristic skeleton: an index whose
    // shape matches an approved entry adopts the human/LLM-confirmed affordances
    // (source preserved), so approvals persist and reruns stay deterministic.
    const catalog = this.options.catalog
      ? await this.options.catalog.load().catch(() => emptyCatalog())
      : emptyCatalog();
    const probed = probedRaw.map((o) =>
      o.affordances
        ? { ...o, affordances: applyCatalog(catalog, o.signature, o.affordances) }
        : o
    );

    // Collapse duplicate mirrors: within a normalized dataset family, indices
    // with equal (nonzero) doc volume are reindex copies (confirmed live —
    // `export-<X>` is a byte-for-byte mirror of `<X>`). Keep one canonical per
    // mirror-group and flag the rest so they stay visible in the review but are
    // not surfaced twice in the hunt list / roll-ups.
    const mirrorOf = detectMirrors(probed);
    const annotated = probed.map((o) =>
      mirrorOf.has(o.name) ? { ...o, mirror_of: mirrorOf.get(o.name)! } : o
    );
    const offSchemaFamilies = offSchemaFamilyCoverage(annotated);

    // Hunt targets vs. enrichment sources is now an *affordance* decision, so
    // human/LLM overrides in the catalog flow straight through to the buckets.
    // A hunt target is `huntable`; a pure match/enrich source is `matchable`/
    // `enrichable` but not `huntable` (IOC feeds, reputation, external scans).
    const withMaterial = annotated.filter(
      (o) => (o.huntable_fields?.length ?? 0) > 0
    );
    const isHuntTarget = (o: OffSchemaIndex) => o.affordances?.huntable === true;
    const isEnrichmentSource = (o: OffSchemaIndex) =>
      !isHuntTarget(o) &&
      (o.affordances?.matchable === true || o.affordances?.enrichable === true);
    // Only canonical (non-mirror) members feed the surfaced lists and roll-ups.
    const canonical = withMaterial.filter((o) => !o.mirror_of);

    const intel_sources = canonical
      .filter(isEnrichmentSource)
      .sort((a, b) => (b.doc_count ?? 0) - (a.doc_count ?? 0))
      .map((o) => o.name);

    // `ioc_match` / `enrichment_match` are field-shape capabilities: any hunt target
    // carrying matchable observables (ip/domain/url/hash/…) supports them. In-cluster
    // source availability does NOT gate the capability — it only sets the mode:
    // `in_cluster` (self-serviced match/enrich loop) vs `byo` (worker supplies the
    // indicator/enrichment feed: ti-loupe / MISP / external service / cross-cluster).
    // A cluster full of raw observables but no in-cluster TI is still a strong
    // ioc_match target for a worker that brings its own indicators.
    const intelAvailable = intel_sources.length > 0;
    const enrichAvailable = canonical.some(
      (o) => isEnrichmentSource(o) && o.affordances?.enrichable === true
    );
    const augment = (o: OffSchemaIndex): OffSchemaIndex => {
      if (!isHuntTarget(o)) return o;
      const extra = matchAndEnrichPrimitives(o, intelAvailable, enrichAvailable);
      return extra.length
        ? { ...o, primitives: [...(o.primitives ?? []), ...extra] }
        : o;
    };
    const withMaterialAug = withMaterial.map(augment);
    const canonicalAug = withMaterialAug.filter((o) => !o.mirror_of);

    // Surface hunt-target streams — ECS happy-path AND off-schema — with
    // discovered material, ranked by breadth of observable categories (then
    // volume), so operational noise sinks and telemetry/alert corpora rise.
    const byBreadthThenVol = (a: OffSchemaIndex, b: OffSchemaIndex) =>
      (b.huntable_fields?.length ?? 0) - (a.huntable_fields?.length ?? 0) ||
      (b.doc_count ?? 0) - (a.doc_count ?? 0);
    const ranked = canonicalAug
      .filter(isHuntTarget)
      .sort(byBreadthThenVol)
      .slice(0, HUNT_DISPLAY_LIMIT);

    // Backfill real doc counts via `_count` for surfaced streams whose volume was
    // unreported (frozen tiers). Record confirmed zeros too, so a mapping that
    // exists but holds no data (e.g. provisioned-but-unused `*_v2` alert streams)
    // drops out of the hunt list and the review — a distinct signal from an
    // unreportable frozen tier (count throws → left as-is).
    const backfilled = (
      await inChunks(ranked, 8, async (o) => {
        if ((o.doc_count ?? 0) > 0) return o;
        const c = await this.options.environmentClient
          .count(o.name)
          .catch(() => undefined);
        return c === undefined ? o : { ...o, doc_count: c };
      })
    ).sort(byBreadthThenVol);
    const emptyNames = new Set(
      backfilled.filter((o) => o.doc_count === 0).map((o) => o.name)
    );
    // First-class, unified hunt catalog (ECS happy path + off-schema). Attach
    // FIELD REALITY to each — the addressable ground truth (actual paths, nested
    // detection, cast hints, IOC-match field lists, rule metadata) the hunt
    // generator needs to emit runnable, grounded ES|QL with no live probing.
    const huntWithReality = await inChunks(
      backfilled.filter((o) => !emptyNames.has(o.name)),
      6,
      async (o) => {
        const field_reality = await this.buildFieldReality(o).catch(
          () => undefined
        );
        return field_reality ? { ...o, field_reality } : o;
      }
    );
    // Identity terrain: populated direct anchors, populated join keys, and the
    // cross-index resolution fabric (agent.id → host.name/user.name, etc.). Uses
    // the field reality above plus a bounded population probe per index.
    const hunt_indices = await this.buildIdentity(huntWithReality);
    // Off-schema subset — the "where is my data hiding" view.
    const high_volume_off_schema = hunt_indices.filter(
      (o) => o.schema_alignment === "off_schema"
    );
    const huntable_off_schema_indices = high_volume_off_schema.map((o) => o.name);

    // Canonical classification skeleton (hunt targets + intel sources + flagged
    // mirrors), ranked low-confidence first so the human review naturally leads
    // with the calls most in need of a second look. Confirmed-empty streams are
    // excluded so the review isn't cluttered with datasets that hold no data.
    const confRank = { low: 0, medium: 1, high: 2 } as const;
    const classified_indices = withMaterialAug
      .filter((o) => !emptyNames.has(o.name))
      .sort(
        (a, b) =>
          confRank[a.affordances?.confidence ?? "high"] -
          confRank[b.affordances?.confidence ?? "high"]
      );

    // Roll-ups span the whole hunt catalog (ECS + off-schema), ranked by volume.
    const byVolDesc = [...hunt_indices].sort(
      (a, b) => (b.doc_count ?? 0) - (a.doc_count ?? 0)
    );
    const process_tree_indices = {
      full: byVolDesc
        .filter((o) => o.lineage?.capability === "full")
        .map((o) => o.name),
      parent_only: byVolDesc
        .filter((o) => o.lineage?.capability === "parent_only")
        .map((o) => o.name),
    };

    // Generalized hunt-primitive matrix: for each primitive, the hunt-target
    // indices that support it, ranked by volume. The worker-facing answer to
    // "who can I sequence / correlate auth / beacon-analyze / identity-pivot on?"
    const primitive_matrix: Partial<Record<HuntPrimitive, string[]>> = {};
    for (const p of HUNT_PRIMITIVES) {
      const names = byVolDesc
        .filter((o) => o.primitives?.some((ps) => ps.primitive === p))
        .map((o) => o.name);
      if (names.length) primitive_matrix[p] = names;
    }

    // Joinability fabric: for each join key, the hunt indices carrying it (all
    // mutually joinable on that key), ranked by volume — the pivots a worker uses
    // to sequence, deduplicate, match across primitives, and cue follow-up hunts.
    const by_key: Partial<Record<JoinKeyKind, string[]>> = {};
    for (const o of byVolDesc) {
      for (const jk of o.join_keys ?? []) {
        const list = (by_key[jk.kind] ??= []);
        if (!list.includes(o.name)) list.push(o.name);
      }
    }

    // Cross-index field-presence map: canonical field → the hunt indices that
    // carry it (present + addressable), ranked by volume. Lets a multi-index
    // `FROM` avoid erroring on a column absent from one member, and grounds the
    // blind-spot rule (an observable is blind only if NO class-appropriate hunt
    // index carries it — the generator reads this, not a coarse family flag).
    const field_presence: Record<string, string[]> = {};
    for (const o of byVolDesc) {
      const fr = o.field_reality;
      if (!fr) continue;
      for (const [canonical, fact] of Object.entries(fr.fields)) {
        if (fact.present) (field_presence[canonical] ??= []).push(o.name);
      }
    }

    return {
      populated_ecs_fields,
      resolved_hunt_indices,
      hunt_indices,
      off_schema_indices,
      high_volume_off_schema,
      classified_indices,
      huntable_off_schema_indices,
      intel_sources,
      process_tree_indices,
      primitive_matrix,
      ioc_match_self_serviced: intelAvailable,
      enrichment_self_serviced: enrichAvailable,
      joinability: { by_key },
      primitives_supported_by_class: PRIMITIVES_SUPPORTED_BY_CLASS,
      field_presence,
      blind_spots: deriveBlindSpots(
        inventory,
        populatedFamilies,
        offSchemaFamilies,
        offSchemaByVolume
      ),
    };
  }

  /**
   * Inspect the mappings of non-ECS data streams / standalone indices / alert
   * aliases and mine them for huntable material. Uses `_field_caps` (metadata)
   * rather than ES|QL counts so cost stays flat even against billion-doc
   * indices, and classifies every field deterministically so a fresh run
   * rediscovers the same material. Probes broadly (up to `OFF_SCHEMA_PROBE_LIMIT`)
   * since field_caps is cheap and hunt value doesn't track doc volume.
   */
  private async probeOffSchema(
    candidates: ActiveDataStream[]
  ): Promise<OffSchemaIndex[]> {
    const canonicalFields = new Set(FIELD_FAMILIES.flatMap((f) => f.fields));
    const top = candidates.slice(0, OFF_SCHEMA_PROBE_LIMIT);

    return inChunks(top, 8, async (ds) => {
      const [caps, metaDescription] = await Promise.all([
        this.options.environmentClient
          .getFieldCaps(ds.name, ["*"])
          .catch(() => ({} as Record<string, Record<string, unknown>>)),
        // Stage 0: backfill `_meta` purpose hint for candidates that didn't carry
        // one from the data-stream listing (standalone indices, aliases).
        ds.meta_description
          ? Promise.resolve(ds.meta_description)
          : this.options.environmentClient
              .getMappingsMeta(ds.name)
              .then((m) => metaToDescription(Object.values(m)[0]))
              .catch(() => undefined),
      ]);
      const fieldNames = Object.keys(caps);
      const { total_fields, timestamp_fields, huntable_fields } =
        classifyHuntableFields(caps);
      const data_class = classifyDataClass(ds.name, fieldNames, metaDescription);
      const lineage = classifyLineage(fieldNames);
      const primitives = classifyPrimitives(fieldNames, timestamp_fields, lineage);
      const join_keys = classifyJoinKeys(fieldNames);
      const signals = computeIndexSignals(
        ds.name,
        fieldNames,
        huntable_fields,
        metaDescription
      );
      const role = classifyIndexRole(signals);
      const affordances = deriveAffordances(role, signals, lineage.capability);
      const signature = signatureFor(
        ds.name,
        huntable_fields.flatMap((g) => g.fields)
      );
      return {
        name: ds.name,
        role,
        affordances,
        signature,
        family: familyKey(ds.name),
        schema_alignment: schemaAlignmentFor(ds.name),
        data_class,
        doc_count: ds.doc_count,
        store_size_bytes: ds.store_size_bytes,
        last_seen: ds.last_seen,
        ecs_hunt_fields_mapped: fieldNames
          .filter((f) => canonicalFields.has(f))
          .sort(),
        total_fields,
        timestamp_fields,
        huntable_fields,
        ...(join_keys.length ? { join_keys } : {}),
        ...(metaDescription ? { meta_description: metaDescription } : {}),
        ...(lineage.capability !== "none" ? { lineage } : {}),
        ...(primitives.length ? { primitives } : {}),
      } satisfies OffSchemaIndex;
    });
  }

  /**
   * Compute persisted FIELD REALITY for one hunt index: fetch `_field_caps`
   * (types + `nested` detection) and one sample doc (example values / multivalue),
   * then resolve every canonical hunt field to its real addressable path. Returns
   * undefined when the index has no mappings (nothing to ground a hunt on).
   */
  private async buildFieldReality(
    index: OffSchemaIndex
  ): Promise<FieldReality | undefined> {
    const client = this.options.environmentClient;
    const [caps, sample] = await Promise.all([
      client
        .getFieldCaps(index.name, ["*"])
        .catch(() => ({}) as Record<string, Record<string, unknown>>),
      client
        .getSampleDoc(index.name)
        .catch(() => ({}) as Record<string, unknown>),
    ]);
    if (Object.keys(caps).length === 0) return undefined;
    return computeFieldReality(index.data_class, caps, sample);
  }

  /**
   * Measure population ratio (populated docs / total) for a bounded set of
   * addressable fields on one index, via a single ES|QL `STATS COUNT` query. Used
   * to distinguish mapped-but-empty identity fields (e.g. `user.name` at ~0%) from
   * genuinely populated anchors / join keys. Returns an empty map on failure so
   * callers fall back to sample-doc presence.
   */
  private async probeFieldPopulation(
    index: string,
    fields: string[]
  ): Promise<Map<string, number>> {
    const out = new Map<string, number>();
    const uniq = [...new Set(fields)].slice(0, POPULATION_PROBE_FIELD_CAP);
    if (!uniq.length) return out;
    try {
      const cols = uniq.map((f, i) => `f${i} = COUNT(\`${f}\`)`).join(", ");
      const result = await this.options.environmentClient.runEsql(
        `FROM ${index} | STATS total = COUNT(*), ${cols}`
      );
      const row = result.values[0] ?? [];
      const colIdx = (name: string) =>
        result.columns.findIndex((c) => c.name === name);
      const total = Number(row[colIdx("total")] ?? 0);
      if (total <= 0) return out;
      uniq.forEach((f, i) => {
        const idx = colIdx(`f${i}`);
        if (idx >= 0) out.set(f, Number(row[idx] ?? 0) / total);
      });
    } catch {
      // Missing @timestamp / type conflicts / absent index → treat as unmeasured.
      return out;
    }
    return out;
  }

  /**
   * Attach identity terrain to each hunt index: measure population ratios for its
   * identity anchors + join keys, resolve direct anchors, stamp join-key ratios,
   * then stitch the cross-index resolution fabric so an index missing identity is
   * routed through a populated join key to indices that carry it.
   */
  private async buildIdentity(
    hunt: OffSchemaIndex[]
  ): Promise<OffSchemaIndex[]> {
    // Phase A: per-index population probe → ratios + identity profile.
    const ratiosByName = new Map<string, Map<string, number>>();
    const withRatios = await inChunks(hunt, 6, async (o) => {
      const fr = o.field_reality;
      const anchorFields = IDENTITY_ANCHORS.flatMap((a) =>
        a.canonicals
          .map((c) => fr?.fields[c])
          .filter((f): f is FieldFact => Boolean(f?.present && f.esql_addressable))
          .map((f) => f.actual_path)
      );
      const joinFields = (o.join_keys ?? []).map((jk) => jk.field);
      const ratios = await this.probeFieldPopulation(o.name, [
        ...anchorFields,
        ...joinFields,
      ]);
      ratiosByName.set(o.name, ratios);
      // Stamp measured population ratios onto join keys.
      const join_keys = o.join_keys?.map((jk) => {
        const r = ratios.get(jk.field);
        return r === undefined ? jk : { ...jk, population_ratio: r };
      });
      return join_keys ? { ...o, join_keys } : o;
    });

    // Phase B: build profiles, then stitch the cross-index resolution fabric.
    const profiles = withRatios.map((o) =>
      buildIdentityProfile(o, ratiosByName.get(o.name) ?? new Map())
    );
    const byName = new Map(profiles.map((p) => [p.name, p]));
    return withRatios.map((o) => {
      const self = byName.get(o.name)!;
      const identity_fields: IdentityFields = {
        direct: self.direct,
        join_keys: self.populatedJoinFields,
        resolves_via: resolveIdentityVia(self, profiles),
      };
      return { ...o, identity_fields };
    });
  }

  /** Evidence-based detection of advanced capabilities actually in use. */
  private async buildCapabilities(
    inventory: EnvironmentInventory
  ): Promise<Capabilities> {
    const client = this.options.environmentClient;
    const errors: string[] = [];

    const entity_analytics =
      inventory.entity_counts.host +
        inventory.entity_counts.user +
        inventory.entity_counts.service +
        inventory.entity_counts.generic >
      0;

    const cases =
      (await this.safe(errors, "cap.cases", () => client.countCases(), 0)) > 0;
    const correlation_corpus =
      (await this.safe(
        errors,
        "cap.correlation",
        () => client.count("ti-reports*"),
        0
      )) > 0;
    const is_sample_data =
      (await this.safe(
        errors,
        "cap.sample_data",
        () =>
          client.count("logs-*,.alerts-security*", {
            query: { term: { tags: "elastic-security-sample-data" } },
          }),
        0
      )) > 0;
    const attack_discovery = await this.safe(
      errors,
      "cap.attack_discovery",
      async () => hasGenerations(await client.getAttackDiscoveryGenerations()),
      false
    );

    return {
      entity_analytics,
      attack_discovery,
      cases,
      correlation_corpus,
      is_sample_data,
    };
  }

  /** Run a probe, recording any failure and returning a fallback. */
  private async safe<T>(
    errors: string[],
    label: string,
    fn: () => Promise<T>,
    fallback: T
  ): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      errors.push(`${label}: ${e instanceof Error ? e.message : String(e)}`);
      return fallback;
    }
  }
}

function emptyTerrain(): Terrain {
  return {
    populated_ecs_fields: [],
    resolved_hunt_indices: [],
    off_schema_indices: [],
    high_volume_off_schema: [],
    huntable_off_schema_indices: [],
    hunt_indices: [],
    intel_sources: [],
    process_tree_indices: { full: [], parent_only: [] },
    primitive_matrix: {},
    joinability: { by_key: {} },
    blind_spots: [],
  };
}

/**
 * Signals used to classify process parent/child (lineage) capability, matched
 * against a mapping's field names across all casings (ECS `process.parent.*`,
 * Elastic-Endpoint `Events.process.*` / `Target.process.*`, and vendor variants
 * like CrowdStrike `ParentCommandLine`). Ordered by join strength so `join_fields`
 * lists the best key first.
 */
const LINEAGE_SIGNALS: {
  key:
    | "parent_join_key"
    | "ancestry_array"
    | "session_leaders"
    | "child_id"
    | "parent_attrs"
    | "ppid"
    | "parent_command_line";
  re: RegExp;
  /** A concrete join field is worth listing for a worker to use. */
  join?: boolean;
}[] = [
  { key: "parent_join_key", re: /(?:^|\.)process\.parent\.entity_id$|parent\.Ext\.real\.entity_id$/i, join: true },
  { key: "ancestry_array", re: /(?:^|\.)process\.Ext\.ancestry$/i, join: true },
  { key: "session_leaders", re: /(?:entry|session|group)_leader\.entity_id$/i, join: true },
  { key: "child_id", re: /(?:^|\.)process\.entity_id$/i },
  { key: "parent_attrs", re: /process\.parent\.(?:name|executable)$/i },
  { key: "ppid", re: /(?:^|\.)ppid$|unique_ppid$/i, join: true },
  { key: "parent_command_line", re: /parent\.command_line$|parent_command_line$|parent_cmdline$|parentcommandline$/i },
];

/**
 * Flatten a harvested index `_meta` object into a short purpose hint. Prefers a
 * human `description`, else composes from `managed_by`/`package`. Undefined when
 * `_meta` carries nothing useful.
 */
function metaToDescription(
  meta: Record<string, unknown> | undefined
): string | undefined {
  if (!meta) return undefined;
  const desc = typeof meta.description === "string" ? meta.description : undefined;
  if (desc) return desc;
  const pkg =
    meta.package && typeof meta.package === "object"
      ? (meta.package as { name?: unknown }).name
      : undefined;
  const managedBy =
    typeof meta.managed_by === "string" ? meta.managed_by : undefined;
  const parts: string[] = [];
  if (typeof pkg === "string") parts.push(`package=${pkg}`);
  if (managedBy) parts.push(`managed_by=${managedBy}`);
  return parts.length > 0 ? parts.join("; ") : undefined;
}

/** Structural + name signals used to derive both role and affordances. */
interface IndexSignals {
  readonly empty: boolean;
  readonly alertFields: boolean;
  readonly intelName: boolean;
  readonly intelSchema: boolean;
  readonly ownedAsset: boolean;
  readonly events: boolean;
  readonly reputation: boolean;
  /** Atomic-indicator observable categories present (hash/ip/domain/url/file). */
  readonly matchObservables: boolean;
  /** Behavioral observation categories present (process/network/file/host/dns/auth). */
  readonly telemetryObservables: boolean;
  /** Purpose hint from index/template `_meta.description`, when harvested. */
  readonly metaDescription?: string;
}

function computeIndexSignals(
  name: string,
  fieldNames: string[],
  huntableFields: HuntableFieldGroup[],
  metaDescription?: string
): IndexSignals {
  const has = (re: RegExp) => fieldNames.some((n) => re.test(n));
  const cats = new Set(huntableFields.map((g) => g.category));
  // Test name and meta independently so token anchors (`$`) still fire on the
  // bare index name.
  const meta = metaDescription ?? "";
  const nameOrMeta = (re: RegExp) => re.test(name) || (!!meta && re.test(meta));
  return {
    empty: huntableFields.length === 0,
    alertFields: has(/(?:^|\.)kibana\.alert\./i) || has(/(?:^|\.)signal\./i),
    intelName: nameOrMeta(INTEL_NAME_RE),
    intelSchema:
      has(/(?:^|\.)threat\.indicator\./i) ||
      has(/(?:^|\.)threat\.feed/i) ||
      has(/(?:^|\.)(?:stix|misp|taxii)/i),
    ownedAsset:
      has(/(?:^|\.)agent\.id$/i) ||
      has(/(?:^|\.)host\.id$/i) ||
      has(/(?:^|\.)host\.hostname$/i) ||
      has(/(?:^|\.)host\.name$/i),
    events:
      has(/(?:^|\.)event\.(?:category|kind|action)$/i) ||
      has(/(?:^|\.)process\.name$/i) ||
      has(/(?:^|\.)destination\.ip$/i),
    reputation:
      has(/(?:^|[._])(?:reputation|verdict|disposition)(?:$|[._])/i) ||
      nameOrMeta(/reputation|enrichment|enrich|(?:^|[._-])cti(?:$|[._-])/i),
    matchObservables: ["hash", "ip", "domain", "url", "file", "registry"].some(
      (c) => cats.has(c)
    ),
    telemetryObservables: [
      "process",
      "command_line",
      "executable",
      "network",
      "file",
      "host",
      "dns",
      "user",
    ].some((c) => cats.has(c)),
    metaDescription,
  };
}

/**
 * Classify an index's hunting role from its name + field structure. Deterministic
 * and evidence-based, mirroring the manual triage: detection output first, then
 * intelligence/enrichment sources (which carry huntable *fields* but are match-
 * list inputs, not hunt targets), then environment telemetry.
 *
 * Intelligence is identified by an intel name token, or by threat-intel schema
 * (`threat.indicator.*` / `threat.feed` / STIX) with **no owned-asset anchor**
 * (`agent.id` / `host.id` / `host.name`) — the tell that the index describes
 * external observables rather than the customer's own hosts. `.alerts`/`signal.*`
 * win first because indicator-match rules stamp `threat.indicator.*` onto alerts.
 */
function classifyIndexRole(s: IndexSignals): IndexRole {
  if (s.empty) return "reference";
  if (s.alertFields) return "alerts";
  if (s.intelName || (s.intelSchema && !s.ownedAsset)) return "intelligence";
  if (s.ownedAsset || s.events) return "telemetry";
  return "unknown";
}

/**
 * Derive the multi-label affordance skeleton from the same signals. `huntable`
 * excludes intelligence (you don't hunt on an IOC feed); `matchable`/`enrichable`
 * mark match-list / enrichment inputs; `pivotable` reflects lineage capability.
 * Confidence records how strongly the structure agreed, so the LLM/human stages
 * know which verdicts to re-examine. Deliberately conservative: the residue it is
 * unsure about is exactly what the later stages confirm.
 */
function deriveAffordances(
  role: IndexRole,
  s: IndexSignals,
  lineageCapability: ProcessTreeCapability
): IndexAffordances {
  const evidence: string[] = [];
  const note = (cond: boolean, msg: string) => {
    if (cond) evidence.push(msg);
  };

  const isIntel = role === "intelligence";
  const huntable =
    !isIntel &&
    !s.empty &&
    (s.alertFields || s.ownedAsset || s.events || s.telemetryObservables);
  const matchable = s.intelSchema || s.intelName || isIntel;
  const enrichable = s.reputation;
  const pivotable = lineageCapability !== "none";

  note(s.alertFields, "detection-output fields (kibana.alert.*/signal.*)");
  note(s.ownedAsset, "owned-asset anchor (agent.id/host.*)");
  note(s.events && !s.alertFields, "event/observation fields");
  note(s.intelSchema, "threat-intel schema (threat.indicator.*/feed/STIX)");
  note(s.intelName, "intel name/meta token");
  note(s.reputation, "reputation/enrichment signals");
  note(pivotable, `process lineage: ${lineageCapability}`);
  if (s.metaDescription) evidence.push(`_meta: ${s.metaDescription.slice(0, 120)}`);

  // Confidence = how decisively structure (not just a name token) settled it.
  let confidence: AffordanceConfidence;
  if (s.empty || s.alertFields) confidence = "high";
  else if (isIntel)
    confidence =
      s.intelSchema && !s.ownedAsset
        ? "high"
        : s.intelName && (s.ownedAsset || s.events)
          ? "low" // name says intel, structure says telemetry — needs confirm
          : "medium";
  else if (role === "telemetry")
    confidence = s.ownedAsset && s.events ? "high" : "medium";
  else confidence = "low"; // unknown

  return {
    huntable,
    matchable,
    enrichable,
    pivotable,
    confidence,
    evidence,
    source: "heuristic",
  };
}

/**
 * Derive process-lineage capability from a field list. Deterministic: same
 * mapping always yields the same verdict. `full` requires a stable child id plus
 * a real join key (parent entity_id, ancestry array, or session leaders);
 * `parent_only` means parent attributes/cmdline/ppid exist but no join key.
 */
function classifyLineage(fieldNames: string[]): LineageSignals {
  const present: Record<string, boolean> = {};
  const join_fields: string[] = [];
  for (const { key, re, join } of LINEAGE_SIGNALS) {
    const matches = fieldNames.filter((n) => re.test(n));
    present[key] = present[key] || matches.length > 0;
    if (join && matches.length && join_fields.length < 6) {
      // Prefer plain ECS-cased fields first for a stable, worker-friendly hint.
      join_fields.push(...matches.sort((a, b) => a.length - b.length).slice(0, 1));
    }
  }
  const child_id = !!present.child_id;
  const parent_join_key = !!present.parent_join_key;
  const ancestry_array = !!present.ancestry_array;
  const session_leaders = !!present.session_leaders;
  const ppid = !!present.ppid;
  const parent_attrs = !!present.parent_attrs;
  const parent_command_line = !!present.parent_command_line;

  const hasJoin = parent_join_key || ancestry_array || session_leaders;
  const capability: ProcessTreeCapability =
    child_id && hasJoin
      ? "full"
      : parent_attrs || parent_command_line || ppid
        ? "parent_only"
        : "none";

  return {
    capability,
    child_id,
    parent_attrs,
    parent_join_key,
    ancestry_array,
    session_leaders,
    ppid,
    parent_command_line,
    join_fields,
  };
}

/** All hunt primitives, in the order they should be surfaced. */
const HUNT_PRIMITIVES: HuntPrimitive[] = [
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
  // Foundational (composable; always-available or field + a source).
  "ioc_match",
  "frequency_analysis",
  "enrichment_match",
  "known_good_diff",
  "string_analysis",
];

/**
 * Derive supported hunting primitives from an index's field shape. Deterministic
 * and evidence-based, generalizing {@link classifyLineage} to the broader set of
 * hunt techniques Elastic ships behavioral/ML detections for. `process_lineage`
 * is taken from the already-computed lineage; the rest are detected from field
 * names. Returns only supported primitives, each with the concrete fields a
 * worker would build on.
 */
function classifyPrimitives(
  fieldNames: string[],
  timestampFields: string[],
  lineage: LineageSignals
): PrimitiveSupport[] {
  const has = (re: RegExp) => fieldNames.some((n) => re.test(n));
  const pick = (re: RegExp, n = 4): string[] =>
    fieldNames
      .filter((x) => re.test(x))
      .sort((a, b) => a.length - b.length)
      .slice(0, n);
  const hasTime = timestampFields.length > 0 || has(/(?:^|\.)@?timestamp$/i);

  const out: PrimitiveSupport[] = [];
  const add = (
    primitive: HuntPrimitive,
    confidence: AffordanceConfidence,
    fields: string[]
  ) => {
    if (fields.length || primitive === "process_lineage")
      out.push({ primitive, confidence, fields: fields.slice(0, 6) });
  };

  // process_lineage — reuse the tiered lineage verdict.
  if (lineage.capability !== "none") {
    add(
      "process_lineage",
      lineage.capability === "full" ? "high" : "medium",
      lineage.join_fields
    );
  }

  // temporal_sequence — EQL `sequence by <entity> with maxspan`: time + a join
  // entity + event typing. The backbone of Elastic's behavioral rules.
  const seqEntity = pick(
    /(?:^|\.)(process\.entity_id|host\.id|host\.name|user\.name|user\.id|source\.ip|destination\.ip)$/i
  );
  const eventTyping = has(/(?:^|\.)event\.(category|action|type|code)$/i);
  if (hasTime && seqEntity.length && eventTyping) {
    const strong = has(/(?:^|\.)process\.entity_id$/i) && has(/(?:^|\.)event\.category$/i);
    add("temporal_sequence", strong ? "high" : "medium", seqEntity);
  }

  // auth_lateral — logon/RDP correlation: source ip + user + host/target + an
  // auth/outcome/logon signal.
  const srcIp = has(/(?:^|\.)source\.ip$/i);
  const authUser = pick(/(?:^|\.)(user\.name|user\.id|source\.user\.name|winlog\.event_data\.targetusername)$/i);
  const authSignal = has(
    /(?:^|\.)(winlog\.(logon|event_id)|event\.code|logon\.type|event\.outcome|authentication)/i
  );
  const hostTarget = has(/(?:^|\.)(host\.name|host\.id|destination\.ip|destination\.domain)$/i);
  if (srcIp && authUser.length && (authSignal || hostTarget)) {
    add("auth_lateral", authSignal ? "high" : "medium", [
      ...pick(/(?:^|\.)source\.ip$/i, 1),
      ...authUser,
    ]);
  }

  // network_beaconing — periodic C2: a destination + bytes/flow (or the shipped
  // `beacon_stats.*` model output) + time.
  const beaconModel = has(/(?:^|\.)beacon_stats\./i);
  const dest = pick(/(?:^|\.)(destination\.(ip|domain|address)|beacon_stats\.[a-z_]+)$/i);
  const bytes = has(/(?:^|\.)(network\.bytes|source\.bytes|destination\.bytes|network\.community_id)$/i);
  if (beaconModel || (dest.length && (bytes || hasTime))) {
    add("network_beaconing", beaconModel || (dest.length && bytes) ? "high" : "medium", dest);
  }

  // dns_analytics — DGA / tunneling: the DNS question is enough to hunt on.
  const dns = pick(/(?:^|\.)dns\.question\.(name|registered_domain|subdomain)$/i);
  if (dns.length || has(/(?:^|\.)dns\.question\./i)) {
    add("dns_analytics", dns.length ? "high" : "medium", dns.length ? dns : pick(/(?:^|\.)dns\.question\./i));
  }

  // cloud_identity — Okta/AWS/Azure/GCP/O365 identity plane: session replay,
  // assume-role, MFA, password spray. Terrance's domain.
  const cloudAudit = pick(
    /(?:^|\.)(okta\.[a-z_.]+|aws\.cloudtrail\.[a-z_.]+|azure\.(signinlogs|auditlogs|activitylogs)\.[a-z_.]+|o365\.[a-z_.]+|google_workspace\.[a-z_.]+|gcp\.audit\.[a-z_.]+)$/i
  );
  const identityKeys = has(
    /(?:^|\.)(user_identity\.(arn|type)|assumed_role|okta\.actor\.id|okta\.debug_context\.debug_data\.dt_?hash|azure\.signinlogs\.properties\.user_principal_name)/i
  );
  if (cloudAudit.length || identityKeys) {
    add("cloud_identity", identityKeys || cloudAudit.length ? "high" : "medium", cloudAudit);
  }

  // geo_impossible_travel — rare geo / velocity per user (okta rare-region etc.).
  const geo = pick(/(?:^|\.)(source|client)\.(geo\.[a-z_]+|as\.[a-z_.]+)$/i);
  const geoUser = has(/(?:^|\.)(user\.name|user\.id|okta\.actor\.id)$/i);
  if (geo.length && geoUser) add("geo_impossible_travel", "medium", geo);

  // egress_exfil — volume out per user/host (ded package).
  const exfilBytes = pick(/(?:^|\.)(source\.bytes|destination\.bytes|network\.bytes)$/i);
  const exfilEntity = has(/(?:^|\.)(user\.name|user\.id|host\.name|host\.id)$/i);
  if (exfilBytes.length && exfilEntity) add("egress_exfil", "medium", exfilBytes);

  // file_integrity — create/modify/delete on file paths (fim package).
  const filePath = pick(/(?:^|\.)file\.(path|name|target_path)$/i);
  if (filePath.length && (has(/(?:^|\.)event\.(action|type)$/i) || hasTime)) {
    add("file_integrity", "medium", filePath);
  }

  // code_signature — unsigned/untrusted binary hunts (tradecraft scoring).
  const sig = pick(/(?:^|\.)(file|process)\.code_signature\./i);
  if (sig.length) add("code_signature", "high", sig);

  // ---- Foundational tactics (composable; derived from field shape alone) ----
  // These need no behavioral shape — just a field to interrogate. `ioc_match` and
  // `enrichment_match` are ALSO foundational but source-gated, so they're stamped
  // on at the terrain level (see {@link sourceGatedPrimitives}), not here.

  // frequency_analysis — stack-count / rare-term / outlier over any populated
  // categorical field. Effectively always-available once a categorical exists;
  // confidence tracks whether a high-cardinality field is present.
  const categorical = pick(
    /(?:^|\.)(process\.(name|executable|command_line)|file\.(name|path)|user\.name|host\.name|dns\.question\.name|destination\.(domain|ip)|source\.ip|url\.(domain|full)|user_agent\.original|event\.action|registry\.(path|key))$/i,
    6
  );
  if (categorical.length) {
    const highCard = has(
      /(?:^|\.)(process\.(command_line|name)|dns\.question\.name|url\.(domain|full)|user_agent\.original|file\.path)$/i
    );
    add("frequency_analysis", highCard ? "high" : "medium", categorical);
  }

  // string_analysis — substring / tokenization / entropy over long free-text
  // observables (command lines, urls, UAs, registry paths, DNS questions).
  const freeText = pick(
    /(?:^|\.)(process\.command_line|command[_.]?line|url\.(full|original|path|query)|user_agent\.original|registry\.(path|key)|file\.path|dns\.question\.name)$/i,
    6
  );
  if (freeText.length) add("string_analysis", "medium", freeText);

  // known_good_diff — baseline / allowlist / new-term / first-seen differencing.
  // Needs either an explicit first-seen anchor (high) or a stable key to baseline
  // per (medium).
  const firstSeen = pick(
    /(?:^|\.)(first_seen|firstseen|first_observed|first[_.]?time|seen_first)$/i,
    3
  );
  const baselineKey = pick(
    /(?:^|\.)(host\.(id|name)|user\.(name|id)|agent\.id|process\.entity_id|entity\.id)$/i,
    3
  );
  if (firstSeen.length || baselineKey.length) {
    add(
      "known_good_diff",
      firstSeen.length ? "high" : "medium",
      firstSeen.length ? [...firstSeen, ...baselineKey] : baselineKey
    );
  }

  return out;
}

/** Observable-field categories that can be matched against intel / enrichment. */
const OBSERVABLE_CATEGORIES = new Set(["hash", "ip", "domain", "dns", "url"]);

/**
 * The concrete observable fields (hash / ip / domain / dns / url) an index carries,
 * best-first, plus whether any is a hash (exact-match, high-precision → higher
 * `ioc_match` confidence). Read from the already-classified
 * {@link OffSchemaIndex.huntable_fields} so it works uniformly for ECS and
 * off-schema indices.
 */
function observableFields(o: OffSchemaIndex): {
  fields: string[];
  hasHash: boolean;
} {
  const groups = o.huntable_fields ?? [];
  const fields = [
    ...new Set(
      groups
        .filter((g) => OBSERVABLE_CATEGORIES.has(g.category))
        .flatMap((g) => g.fields)
    ),
  ].slice(0, 6);
  const hasHash = groups.some(
    (g) => g.category === "hash" && g.fields.length > 0
  );
  return { fields, hasHash };
}

/**
 * The corpus-matching foundational primitives (`ioc_match` / `enrichment_match`).
 * Capability is a per-index FIELD-SHAPE fact: any hunt target carrying matchable
 * observables (ip/domain/url/hash/dns) supports both — you can always match those
 * columns against an indicator/enrichment corpus. In-cluster source availability is
 * NOT a gate; it only sets {@link PrimitiveSupport.source_mode}:
 *   - `in_cluster` — the cluster ships an intel/match ({@link Terrain.intel_sources})
 *     or enrichable verdict source, so the loop is self-serviced.
 *   - `byo` — fully matchable, but the worker supplies the feed (ti-loupe / MISP /
 *     external service / cross-cluster intel).
 * `hasHash` still lifts `ioc_match` confidence (exact-match, high precision).
 * Deterministic — no field-value reads.
 */
function matchAndEnrichPrimitives(
  o: OffSchemaIndex,
  intelAvailable: boolean,
  enrichAvailable: boolean
): PrimitiveSupport[] {
  const { fields, hasHash } = observableFields(o);
  if (!fields.length) return [];
  return [
    {
      primitive: "ioc_match",
      confidence: hasHash ? "high" : "medium",
      fields,
      source_mode: intelAvailable ? "in_cluster" : "byo",
    },
    {
      primitive: "enrichment_match",
      confidence: "medium",
      fields,
      source_mode: enrichAvailable ? "in_cluster" : "byo",
    },
  ];
}

/** Ordered join keys + the fields that carry each, best (most stable) first. */
const JOIN_KEY_SIGNALS: { kind: JoinKeyKind; res: RegExp[] }[] = [
  { kind: "agent", res: [/(?:^|\.)agent\.id$/i] },
  {
    kind: "host",
    res: [
      /(?:^|\.)host\.id$/i,
      /(?:^|\.)host\.name$/i,
      /(?:^|\.)host\.hostname$/i,
    ],
  },
  { kind: "host_ip", res: [/(?:^|\.)host\.ip$/i] },
  { kind: "user", res: [/(?:^|\.)user\.id$/i, /(?:^|\.)user\.name$/i] },
  { kind: "process", res: [/(?:^|\.)process\.entity_id$/i] },
  { kind: "session", res: [/(?:entry|session|group)_leader\.entity_id$/i] },
  {
    kind: "network",
    res: [/(?:^|\.)source\.ip$/i, /(?:^|\.)destination\.ip$/i],
  },
  {
    kind: "cloud",
    res: [/(?:^|\.)cloud\.instance\.id$/i, /(?:^|\.)cloud\.account\.id$/i],
  },
  { kind: "container", res: [/(?:^|\.)container\.id$/i] },
  {
    kind: "event",
    res: [
      /(?:^|\.)kibana\.alert\.uuid$/i,
      /(?:^|\.)event\.id$/i,
      /(?:^|\.)trace\.id$/i,
    ],
  },
];

/**
 * Derive the stable keys an index can be joined / deduplicated / sequenced /
 * pivoted on, from its field shape. Deterministic; returns the first concrete
 * field found per key kind (best-first per {@link JOIN_KEY_SIGNALS}).
 */
function classifyJoinKeys(fieldNames: string[]): JoinKey[] {
  const out: JoinKey[] = [];
  for (const { kind, res } of JOIN_KEY_SIGNALS) {
    for (const re of res) {
      const field = fieldNames.find((n) => re.test(n));
      if (field) {
        out.push({ kind, field });
        break;
      }
    }
  }
  return out;
}

/**
 * ECS happy-path vs. off-schema, from the index name. Standard `logs-*` /
 * `.alerts*` / `.entities*` naming is ECS; everything else (custom-named
 * standalone indices, vendor exports) is off-schema — where data tends to hide.
 */
function schemaAlignmentFor(name: string): SchemaAlignment {
  return /^(?:logs-|\.alerts|\.internal\.alerts|\.entities)/i.test(name)
    ? "ecs"
    : "off_schema";
}

/** ECS-aligned hunt streams worth probing (excludes `metrics-*` / backing indices). */
function isEcsHuntStream(name: string): boolean {
  return (
    /^(?:logs-|\.alerts|\.entities)/i.test(name) && !name.includes(".ds-")
  );
}

/**
 * Classify an index's {@link DataClass} — the most decisive terrain signal, since
 * it gates which primitives are even possible. Deterministic, name + field-shape
 * based (no LLM), order-sensitive:
 *  1. `alert`  — detection-engine output (`.alerts` alias/backing, or `kibana.alert.*`
 *                / `signal.rule.*` metadata fields).
 *  2. `detonation` — sandbox/detonation results (name/meta).
 *  3. `telemetry_aggregate` — rolled-up counts/summaries (name/meta).
 *  4. `raw_event` — per-event rows: `event.category|action|type|code`, or
 *                process/network/file/dns/registry eventing fields (top-level OR
 *                nested under an `*.event.*` container).
 * Falls back to `telemetry_aggregate` when nothing else matches.
 */
function classifyDataClass(
  name: string,
  fieldNames: string[],
  metaDescription?: string
): DataClass {
  const nameMeta = `${name} ${metaDescription ?? ""}`;
  const has = (re: RegExp) => fieldNames.some((n) => re.test(n));
  // The canonical security-alerts alias/backing is always `alert`, regardless of
  // name tokens.
  if (/^\.(?:internal\.)?alerts/i.test(name)) return "alert";
  if (/detonat|sandbox|cuckoo/i.test(nameMeta)) return "detonation";
  // A `*_telemetry_*` / aggregate NAME wins over alert-metadata *fields*: rollups
  // of detection alerts (e.g. `detections_alert_telemetry_elastic`) carry
  // `kibana.alert.rule.*` columns but are aggregates, not per-alert docs.
  if (/telemetry|aggregat|summary|rollup|metric|_stats?\b|_counts?\b/i.test(nameMeta)) {
    return "telemetry_aggregate";
  }
  // Per-alert docs (no telemetry name) carrying detection-engine metadata.
  if (has(/(?:^|\.)kibana\.alert\./i) || has(/(?:^|\.)signal\.rule\./i)) {
    return "alert";
  }
  if (
    has(/(?:^|\.)event\.(?:category|action|type|code)$/i) ||
    has(/(?:^|\.)(?:process|network|dns|file|registry)\.[a-z_]/i)
  ) {
    return "raw_event";
  }
  return "telemetry_aggregate";
}

/**
 * Canonical/ECS hunt fields the field-reality resolver looks for. Suffix-matched
 * against an index's REAL field names, so a nested/prefixed container (e.g.
 * `timeline.event.process.command_line`) resolves back to its ECS canonical.
 */
const CANONICAL_HUNT_FIELDS: readonly string[] = [
  // process / lineage / command line
  "process.command_line",
  "process.parent.command_line",
  "process.name",
  "process.executable",
  "process.entity_id",
  "process.parent.entity_id",
  "process.Ext.ancestry",
  "process.pid",
  "process.parent.pid",
  "process.hash.sha256",
  // identity anchors (host / user / tenant)
  "host.name",
  "host.id",
  "host.hostname",
  "user.name",
  "user.id",
  "user.email",
  "user.domain",
  "cloud.account.id",
  "cloud.tenant.id",
  // network / dns / url
  "source.ip",
  "destination.ip",
  "host.ip",
  "dns.question.name",
  "destination.domain",
  "url.domain",
  "url.full",
  "url.original",
  // file / hash / registry
  "file.path",
  "file.name",
  "file.hash.sha256",
  "file.hash.md5",
  "file.hash.sha1",
  "registry.path",
  "registry.key",
  // threat / TI enrichment
  "threat.indicator.ip",
  "threat.indicator.url.full",
  "threat.indicator.url.domain",
  "threat.indicator.file.hash.sha256",
  "threat.enrichments.matched.atomic",
  // rule / technique metadata (alerts)
  "rule.name",
  "threat.technique.id",
  "threat.technique.subtechnique.id",
];

/** Which canonical fields feed each IOC-match class (order = generator OR order). */
const IOC_CLASS_CANONICALS: Record<IocClass, readonly string[]> = {
  ip: ["source.ip", "destination.ip", "host.ip", "threat.indicator.ip"],
  domain: [
    "dns.question.name",
    "destination.domain",
    "url.domain",
    "threat.indicator.url.domain",
  ],
  url: ["url.full", "url.original", "threat.indicator.url.full"],
  hash: [
    "file.hash.sha256",
    "file.hash.sha1",
    "file.hash.md5",
    "process.hash.sha256",
    "threat.indicator.file.hash.sha256",
  ],
  file_path: ["file.path", "process.executable", "file.name"],
  registry: ["registry.path", "registry.key"],
  named_pipe: [], // resolved by name-regex scan (paths vary wildly)
  mutex: [], // resolved by name-regex scan
};

/**
 * Fields that are conventionally multivalue even when a 1-doc sample shows a
 * single value — hunts MUST use DSL terms aggs, not ES|QL `IN` (which silently
 * drops multivalue rows).
 */
const KNOWN_MULTIVALUE_RE =
  /(?:^|\.)(?:threat\.technique\.id|threat\.technique\.subtechnique\.id|technique\.id|subtechnique\.id|process\.args|process\.Ext\.ancestry|dns\.answers|related\.(?:ip|hash|user|hosts)|threat\.tactic\.id|tags|host\.ip)$/i;

/** Identity anchor canonicals per category, best-first (first populated one wins). */
const IDENTITY_ANCHORS: {
  category: "host" | "user" | "tenant";
  canonicals: string[];
}[] = [
  { category: "host", canonicals: ["host.name", "host.id", "host.hostname"] },
  { category: "user", canonicals: ["user.name", "user.id", "user.email"] },
  {
    category: "tenant",
    canonicals: ["cloud.account.id", "cloud.tenant.id", "user.domain"],
  },
];

/** Canonical identity-anchor field names — resolved strictly (no foreign fallback). */
const IDENTITY_ANCHOR_CANONICALS = new Set(
  IDENTITY_ANCHORS.flatMap((a) => a.canonicals)
);

/** Min population ratio for an identity anchor / join key to count as usable. */
const IDENTITY_POPULATED_MIN = 0.01;
/** Cap fields per population probe so one STATS query stays bounded. */
const POPULATION_PROBE_FIELD_CAP = 24;

/**
 * Per-index identity terrain distilled from field reality + population ratios.
 * Internal to terrain building; the cross-index {@link IdentityResolution} fabric
 * is stitched from these.
 */
interface IdentityProfile {
  readonly name: string;
  readonly direct: {
    host: string | null;
    user: string | null;
    tenant: string | null;
  };
  /** Join fields present AND populated on this index (best-first). */
  readonly populatedJoinFields: string[];
}

/**
 * Decide whether a canonical field is populated on an index. Prefers a measured
 * population ratio (from the ES|QL probe); falls back to the sample doc's
 * example-value presence when no ratio is available (probe failed / empty).
 */
function isPopulated(
  fact: FieldFact | undefined,
  ratio: number | undefined
): boolean {
  if (!fact?.present || !fact.esql_addressable) return false;
  if (ratio !== undefined) return ratio >= IDENTITY_POPULATED_MIN;
  return fact.example_value != null;
}

/**
 * Build one index's identity profile: the first populated anchor per category and
 * the join fields that are present + populated. `ratios` maps actual field path →
 * populated fraction (may be empty, then sample presence is used).
 */
function buildIdentityProfile(
  o: OffSchemaIndex,
  ratios: Map<string, number>
): IdentityProfile {
  const fr = o.field_reality;
  const direct: IdentityProfile["direct"] = {
    host: null,
    user: null,
    tenant: null,
  };
  for (const { category, canonicals } of IDENTITY_ANCHORS) {
    for (const canon of canonicals) {
      const fact = fr?.fields[canon];
      if (fact && isPopulated(fact, ratios.get(fact.actual_path))) {
        direct[category] = fact.actual_path;
        break;
      }
    }
  }
  const factByPath = new Map<string, FieldFact>();
  if (fr) {
    for (const f of Object.values(fr.fields)) {
      if (f.present) factByPath.set(f.actual_path, f);
    }
  }
  const populatedJoinFields = (o.join_keys ?? [])
    .filter((jk) => {
      const r = ratios.get(jk.field);
      if (r !== undefined) return r >= IDENTITY_POPULATED_MIN;
      // Unmeasured: use sample presence when the join field is in field reality;
      // otherwise keep it (it was derived from a real mapped field).
      const fact = factByPath.get(jk.field);
      return fact ? isPopulated(fact, undefined) : true;
    })
    .map((jk) => jk.field);
  return { name: o.name, direct, populatedJoinFields };
}

/**
 * Stitch the cross-index resolution fabric for one index: for each populated join
 * field it carries, find other hunt indices sharing that field (populated) that
 * carry identity THIS index lacks, and record what they yield.
 */
function resolveIdentityVia(
  self: IdentityProfile,
  others: IdentityProfile[]
): IdentityResolution[] {
  const missing = (["host", "user", "tenant"] as const).filter(
    (c) => self.direct[c] === null
  );
  if (!missing.length) return [];
  const out: IdentityResolution[] = [];
  for (const key of self.populatedJoinFields) {
    const to: string[] = [];
    const yields = new Set<string>();
    for (const other of others) {
      if (other.name === self.name) continue;
      if (!other.populatedJoinFields.includes(key)) continue;
      const provides = missing.filter((c) => other.direct[c] !== null);
      if (!provides.length) continue;
      to.push(other.name);
      for (const c of provides) yields.add(other.direct[c]!);
    }
    if (to.length && yields.size) {
      out.push({ key, from: self.name, to, yields: [...yields] });
    }
  }
  return out;
}

/** First (representative) mapping type reported by `_field_caps` for a path. */
function esTypeOf(
  caps: Record<string, Record<string, unknown>>,
  path: string
): string {
  return Object.keys(caps[path] ?? {})[0] ?? "unknown";
}

/**
 * The nearest ancestor of `path` mapped as `nested` (which makes `path`
 * non-ES|QL-addressable — the generator must use `_search`), or null. `nested`
 * containers are surfaced by `_field_caps` with type `nested`, so this needs no
 * extra mapping round-trip.
 */
function nestedAncestorOf(
  caps: Record<string, Record<string, unknown>>,
  path: string
): string | null {
  const segs = path.split(".");
  for (let i = segs.length - 1; i >= 1; i--) {
    const anc = segs.slice(0, i).join(".");
    if (esTypeOf(caps, anc) === "nested") return anc;
  }
  return null;
}

/**
 * Sub-object namespaces that indicate a suffix match belongs to a DIFFERENT
 * entity than the canonical field (e.g. `process.Ext.code_signature.host.name`
 * is the signer's host, not the event host; `threat.indicator.file.hash.sha256`
 * is an IOC, not the observed file). Applied to the PREFIX (the part before the
 * canonical suffix), so canonicals that legitimately contain `Ext` still resolve.
 */
const FOREIGN_ENTITY_PREFIX_RE =
  /(?:^|\.)(?:Ext|code_signature|geo|as|related|threat|indicator|enrichments)(?:\.|$)/i;

/**
 * Resolve a canonical field to its REAL addressable path in this index: exact
 * match first, else the shallowest real field whose path ends in `.<canonical>`
 * (so prefixed/nested containers resolve). Suffix matches that dive through a
 * foreign entity sub-object are de-prioritized. When `strict` (identity anchors),
 * a foreign-only match returns null rather than a wrong-entity path.
 */
function resolveActualPath(
  canonical: string,
  names: string[],
  nameSet: Set<string>,
  strict = false
): string | null {
  if (nameSet.has(canonical)) return canonical;
  const suffix = "." + canonical;
  const cands = names.filter((n) => n.endsWith(suffix));
  if (!cands.length) return null;
  const clean = cands.filter(
    (n) => !FOREIGN_ENTITY_PREFIX_RE.test(n.slice(0, n.length - suffix.length))
  );
  // Strict (identity): never resolve to a foreign-entity path — prefer the join
  // fabric over a wrong anchor.
  const pool = clean.length ? clean : strict ? [] : cands;
  if (!pool.length) return null;
  // Shallowest path (fewest segments) is closest to the real anchor.
  return pool.sort(
    (a, b) => a.split(".").length - b.split(".").length || a.length - b.length
  )[0];
}

/** Read a value from a sample `_source` by dotted path (flattened key OR nested walk). */
function rawValueAtPath(doc: Record<string, unknown>, path: string): unknown {
  if (Object.prototype.hasOwnProperty.call(doc, path)) return doc[path];
  let cur: unknown = doc;
  for (const seg of path.split(".")) {
    if (Array.isArray(cur)) cur = cur[0];
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

/** Stringify + truncate a sample value for the field-reality `example_value`. */
function exampleValueOf(raw: unknown): string | null {
  const v = Array.isArray(raw) ? raw[0] : raw;
  if (v == null) return null;
  const s = typeof v === "object" ? JSON.stringify(v) : String(v);
  return s.length > 120 ? s.slice(0, 117) + "…" : s;
}

/**
 * Compute the persisted FIELD REALITY for one index from `_field_caps` (types +
 * `nested` detection) and one sample doc (example values / multivalue). This is
 * the ground truth a hunt generator needs to emit runnable, grounded ES|QL with
 * no live probing of its own. Deterministic; recomputed on every refresh.
 */
function computeFieldReality(
  dataClass: DataClass | undefined,
  caps: Record<string, Record<string, unknown>>,
  sample: Record<string, unknown>
): FieldReality {
  const names = Object.keys(caps);
  const nameSet = new Set(names);
  const fields: Record<string, FieldFact> = {};

  for (const canonical of CANONICAL_HUNT_FIELDS) {
    // Identity anchors resolve strictly (no foreign-entity fallback) so a missing
    // host/user routes through the join fabric instead of a wrong-entity path.
    const actual = resolveActualPath(
      canonical,
      names,
      nameSet,
      IDENTITY_ANCHOR_CANONICALS.has(canonical)
    );
    if (!actual) {
      fields[canonical] = {
        present: false,
        actual_path: canonical,
        es_type: "unknown",
        esql_addressable: false,
        nested_parent: null,
        multivalue: false,
        cast_hint: null,
        example_value: null,
      };
      continue;
    }
    const es_type = esTypeOf(caps, actual);
    const selfNested = es_type === "nested";
    const ancestorNested = nestedAncestorOf(caps, actual);
    const nested_parent = ancestorNested ?? (selfNested ? actual : null);
    const raw = rawValueAtPath(sample, actual);
    fields[canonical] = {
      present: true,
      actual_path: actual,
      es_type,
      esql_addressable: nested_parent === null,
      nested_parent,
      multivalue:
        (Array.isArray(raw) && raw.length > 1) ||
        KNOWN_MULTIVALUE_RE.test(canonical),
      cast_hint: es_type === "ip" ? "::keyword" : null,
      example_value: exampleValueOf(raw),
    };
  }

  // Addressable + cast IOC-match expressions per class (nested/absent excluded),
  // in the order a generator should OR them.
  const iocFor = (canon: readonly string[]): string[] => {
    const out: string[] = [];
    for (const c of canon) {
      const f = fields[c];
      if (f?.present && f.esql_addressable) {
        out.push(f.actual_path + (f.cast_hint ?? ""));
      }
    }
    return out;
  };
  const byNameRe = (re: RegExp): string[] =>
    names
      .filter(
        (n) =>
          re.test(n) &&
          esTypeOf(caps, n) !== "nested" &&
          nestedAncestorOf(caps, n) === null &&
          !(/\.(keyword|text)$/.test(n) &&
            nameSet.has(n.replace(/\.(keyword|text)$/, "")))
      )
      .sort();
  const ioc_match_fields: Record<IocClass, string[]> = {
    ip: iocFor(IOC_CLASS_CANONICALS.ip),
    domain: iocFor(IOC_CLASS_CANONICALS.domain),
    url: iocFor(IOC_CLASS_CANONICALS.url),
    hash: iocFor(IOC_CLASS_CANONICALS.hash),
    file_path: iocFor(IOC_CLASS_CANONICALS.file_path),
    registry: iocFor(IOC_CLASS_CANONICALS.registry),
    named_pipe: byNameRe(/pipe/i),
    mutex: byNameRe(/mutex/i),
  };

  const atomic = fields["threat.enrichments.matched.atomic"];
  const matched_atomic: MatchedAtomic | null = atomic?.present
    ? {
        field: atomic.actual_path,
        access: atomic.esql_addressable ? "esql" : "search_nested",
      }
    : null;

  let rule_fields: RuleFields | null = null;
  const ruleName = fields["rule.name"];
  if (dataClass === "alert" && ruleName?.present) {
    const tech = fields["threat.technique.id"];
    const subtech = fields["threat.technique.subtechnique.id"];
    rule_fields = {
      rule_name: ruleName.actual_path,
      technique_id: {
        field: tech?.actual_path ?? "threat.technique.id",
        multivalue: tech?.multivalue ?? true,
        populated: Boolean(tech?.present && tech.example_value != null),
      },
      subtechnique_id: {
        field: subtech?.actual_path ?? "threat.technique.subtechnique.id",
        multivalue: subtech?.multivalue ?? true,
        populated: Boolean(subtech?.present && subtech.example_value != null),
      },
    };
  }

  return { fields, ioc_match_fields, matched_atomic, rule_fields };
}

/**
 * Normalize an index name to its dataset *family*: strip transform prefixes
 * (`export-`, `reindexed-v8-`, `restored-`, `partial-`, `shrink-<id>-`, possibly
 * stacked) and trailing date / generation / version suffixes. So `X`,
 * `export-X`, `reindexed-v8-X-2021.10.15-000002` all collapse to `x` — the key
 * for mirror detection.
 */
function familyKey(name: string): string {
  let n = name.toLowerCase();
  n = n.replace(/^(?:export-|reindexed-v\d+-|restored-|partial-|shrink-[a-z0-9]+-)+/g, "");
  n = n.replace(/[-_.]\d{4}[._-]\d{2}[._-]\d{2}(?:[-_.]\d+)*$/g, "");
  n = n.replace(/[-_.]\d{6,}$/g, "");
  n = n.replace(/[-_]v\d+$/g, "");
  n = n.replace(/-0{2,}\d+$/g, "");
  return n;
}

/** True when a name carries a transform prefix (i.e., a derived copy, not the base). */
const TRANSFORM_PREFIX_RE = /^(?:export-|reindexed-v\d+-|restored-|partial-|shrink-)/i;

/**
 * Detect reindex mirrors: within a normalized {@link familyKey}, indices that
 * share an identical nonzero doc volume are copies of one logical dataset. Maps
 * each mirror's name -> the canonical it mirrors. Deterministic. Only equal-count
 * members of the *same* family collapse — different-count members (e.g. raw vs
 * cleaned stages, or a sampled `export-`) stay independent.
 */
function detectMirrors(indices: OffSchemaIndex[]): Map<string, string> {
  const byFamily = new Map<string, OffSchemaIndex[]>();
  for (const o of indices) {
    const fam = o.family ?? familyKey(o.name);
    (byFamily.get(fam) ?? byFamily.set(fam, []).get(fam)!).push(o);
  }
  const mirrorOf = new Map<string, string>();
  for (const group of byFamily.values()) {
    if (group.length < 2) continue;
    const byCount = new Map<number, OffSchemaIndex[]>();
    for (const o of group) {
      const c = o.doc_count ?? 0;
      if (c <= 0) continue;
      (byCount.get(c) ?? byCount.set(c, []).get(c)!).push(o);
    }
    for (const dupes of byCount.values()) {
      if (dupes.length < 2) continue;
      const canonical = pickCanonical(dupes);
      for (const o of dupes)
        if (o.name !== canonical) mirrorOf.set(o.name, canonical);
    }
  }
  return mirrorOf;
}

/** Pick the canonical of a mirror group: prefer un-prefixed, then shortest name. */
function pickCanonical(dupes: OffSchemaIndex[]): string {
  const base = dupes.filter((o) => !TRANSFORM_PREFIX_RE.test(o.name));
  const pool = base.length ? base : dupes;
  return [...pool].sort(
    (a, b) => a.name.length - b.name.length || a.name.localeCompare(b.name)
  )[0].name;
}

/** category -> telemetry family, derived once from the classifier config. */
const CATEGORY_FAMILY: Record<string, string> = Object.fromEntries(
  HUNT_CATEGORIES.filter((c) => c.family).map((c) => [c.category, c.family!])
);

/**
 * Classify a field-caps mapping into huntable observable categories using only
 * field names and types. Deterministic: same mapping always yields the same
 * groups (sorted, capped), so a fresh profiling run rediscovers identical
 * material. Skips internal (`_*`) fields and redundant `.keyword`/`.text`
 * multi-field leaves.
 */
function classifyHuntableFields(caps: Record<string, Record<string, unknown>>): {
  total_fields: number;
  timestamp_fields: string[];
  huntable_fields: HuntableFieldGroup[];
} {
  const names = Object.keys(caps).filter((n) => !n.startsWith("_"));
  const nameSet = new Set(names);
  const fields = names
    .filter((n) => {
      // Drop `foo.keyword`/`foo.text` when the base field `foo` is also present.
      const m = n.match(/^(.*)\.(keyword|text)$/);
      return !(m && nameSet.has(m[1]));
    })
    .sort();

  const timestamp_fields: string[] = [];
  const byCategory = new Map<string, string[]>();

  for (const field of fields) {
    const types = Object.keys(caps[field] ?? {});
    if (types.includes("date") || types.includes("date_nanos")) {
      timestamp_fields.push(field);
    }
    const match = HUNT_CATEGORIES.find(
      (c) =>
        (c.types && c.types.some((t) => types.includes(t))) ||
        (c.nameRe && c.nameRe.test(field))
    );
    if (match) {
      const list = byCategory.get(match.category) ?? [];
      list.push(field);
      byCategory.set(match.category, list);
    }
  }

  const huntable_fields: HuntableFieldGroup[] = [];
  for (const { category } of HUNT_CATEGORIES) {
    const list = byCategory.get(category);
    if (list && list.length) {
      huntable_fields.push({
        category,
        fields: list.slice(0, HUNTABLE_FIELDS_PER_CATEGORY),
      });
    }
  }

  return {
    total_fields: names.length,
    timestamp_fields: timestamp_fields.slice(0, 10),
    huntable_fields,
  };
}

/**
 * Choose which off-schema streams/indices to inspect with `_field_caps`. Union
 * of the top streams by volume AND the top streams whose *name* is security-
 * relevant — the latter rescues rich streams whose size is unreported by
 * `_cat/indices` / the stats API (frozen & searchable-snapshot tiers), which a
 * pure volume gate would silently drop. Deterministic ordering (volume desc,
 * then name) so a fresh run inspects the same set.
 */
function selectProbeCandidates(
  candidates: ActiveDataStream[]
): ActiveDataStream[] {
  const vol = (d: ActiveDataStream) => d.doc_count ?? d.store_size_bytes ?? 0;
  const byVol = (a: ActiveDataStream, b: ActiveDataStream) =>
    vol(b) - vol(a) || a.name.localeCompare(b.name);

  const topByVolume = candidates
    .filter((d) => vol(d) > 0)
    .sort(byVol)
    .slice(0, PROBE_TOP_BY_VOLUME);
  // Rescue set: huntable-named streams with NO reported volume. These are exactly
  // the ones volume-ranking can't reach, so they get dedicated slots instead of
  // competing (and losing) against volume-bearing streams for name slots.
  const rescueByName = candidates
    .filter((d) => vol(d) === 0 && HUNT_NAME_RE.test(d.name))
    .sort((a, b) => a.name.localeCompare(b.name))
    .slice(0, PROBE_TOP_BY_NAME);

  const seen = new Set<string>();
  const out: ActiveDataStream[] = [];
  for (const d of [...topByVolume, ...rescueByName]) {
    if (seen.has(d.name)) continue;
    seen.add(d.name);
    out.push(d);
  }
  return out.slice(0, OFF_SCHEMA_PROBE_LIMIT);
}

/**
 * Which telemetry families are present inside the high-volume off-schema streams
 * — via canonical ECS names *or* semantically-classified huntable categories.
 * Lets blind-spot logic distinguish "no data" from "present but not
 * ECS-normalized".
 */
function offSchemaFamilyCoverage(offSchema: OffSchemaIndex[]): Set<string> {
  const families = new Set<string>();

  const mappedEcs = new Set(offSchema.flatMap((o) => o.ecs_hunt_fields_mapped));
  for (const { family, fields } of FIELD_FAMILIES) {
    if (fields.some((f) => mappedEcs.has(f))) families.add(family);
  }

  for (const o of offSchema) {
    for (const group of o.huntable_fields ?? []) {
      const family = CATEGORY_FAMILY[group.category];
      if (family) families.add(family);
    }
  }
  return families;
}

function emptyCapabilities(): Capabilities {
  return {
    entity_analytics: false,
    attack_discovery: false,
    cases: false,
    correlation_corpus: false,
    is_sample_data: false,
  };
}

/**
 * Turn missing telemetry families + integrations into analyst-readable gaps.
 *
 * Crucially, a family is only a true blind spot when it is populated *nowhere*.
 * When canonical fields are mapped in high-volume off-schema streams, the gap is
 * not "no telemetry" but "telemetry present, just not ECS-normalized" — a very
 * different instruction to a hunt worker (widen your index set / remap fields
 * rather than give up).
 */
function deriveBlindSpots(
  inventory: EnvironmentInventory,
  populatedFamilies: Set<string>,
  offSchemaFamilies: Set<string>,
  offSchemaByVolume: ActiveDataStream[]
): string[] {
  const gaps: string[] = [];
  const hasEcs = (family: string) => populatedFamilies.has(family);
  const hasOff = (family: string) => offSchemaFamilies.has(family);
  const endpointFamilies = ["process", "file"];
  const hasEndpointEcs = endpointFamilies.some(hasEcs);
  const hasEndpointOff = endpointFamilies.some(hasOff);

  // Surface the elephant in the room: bulk data hiding in non-ECS streams.
  if (offSchemaByVolume.length > 0) {
    const biggest = offSchemaByVolume[0];
    gaps.push(
      `bulk of data lives in ${offSchemaByVolume.length} non-ECS ` +
        `stream(s) not covered by ECS field probes (largest: ` +
        `${biggest.name}${biggest.doc_count != null ? ` ~${biggest.doc_count.toLocaleString("en-US")} docs` : ""})`
    );
  }

  if (inventory.rule_inventory.total > 0 && !hasEndpointEcs) {
    gaps.push(
      hasEndpointOff
        ? "endpoint event telemetry present only in off-schema indices (not ECS-normalized) — ECS-field hunts will miss it"
        : "alerts present but little/no raw endpoint event telemetry"
    );
  }
  if (!hasEcs("network") && !hasEcs("dns") && !hasOff("network") && !hasOff("dns")) {
    gaps.push("no network telemetry");
  }
  if (
    inventory.deployed_tech.cloud_providers.length === 0 &&
    !hasEcs("cloud") &&
    !hasOff("cloud")
  ) {
    gaps.push("no cloud audit logs");
  }
  if (
    !inventory.integration_presence.endpoint &&
    !hasEndpointEcs &&
    !hasEndpointOff
  ) {
    gaps.push("no endpoint integration / host telemetry");
  }
  for (const { family } of FIELD_FAMILIES) {
    if (hasEcs(family)) continue;
    gaps.push(
      hasOff(family)
        ? `${family} telemetry present only in off-schema indices (not ECS-normalized)`
        : `no ${family} telemetry in the last 30 days`
    );
  }
  return [...new Set(gaps)];
}

/** Read whichever envelope key the attack-discovery generations route returns. */
function hasGenerations(envelope: unknown): boolean {
  if (!envelope || typeof envelope !== "object") return false;
  const e = envelope as Record<string, unknown>;
  const list = e.generations ?? e.data;
  return Array.isArray(list) && list.length > 0;
}

function round(n: number): number {
  return Math.round(n * 1000) / 1000;
}

function emptyInventory(): EnvironmentInventory {
  return {
    active_data_streams: [],
    integration_presence: buildIntegrationPresence([]),
    deployed_tech: { cloud_providers: [], os_mix: {} },
    entity_counts: { host: 0, user: 0, service: 0, generic: 0 },
    rule_inventory: { total: 0, enabled: 0, disabled: 0 },
  };
}

function buildIntegrationPresence(installed: string[]): IntegrationPresence {
  const has = (pred: (n: string) => boolean) => installed.some(pred);
  return {
    aws: has((n) => n === "aws" || n.startsWith("aws_")),
    azure: has((n) => n.startsWith("azure") || n === "o365"),
    gcp: has((n) => n.startsWith("gcp") || n === "google_cloud"),
    endpoint: installed.includes("endpoint"),
    network_traffic: installed.includes("network_traffic"),
    vulnerability: has(
      (n) =>
        n.includes("vuln") ||
        n.includes("tenable") ||
        n.includes("qualys") ||
        n.includes("rapid7")
    ),
    alerts: installed.includes("security_detection_engine"),
    fleet: has((n) => n === "fleet_server" || n === "elastic_agent"),
    installed,
  };
}

function cloudProviders(presence: IntegrationPresence): string[] {
  const out: string[] = [];
  if (presence.aws) out.push("aws");
  if (presence.azure) out.push("azure");
  if (presence.gcp) out.push("gcp");
  return out;
}

/** Parse the `<dataset>` from a `<type>-<dataset>-<namespace>` data-stream name. */
function parseDataset(name: string): string | undefined {
  const parts = name.split("-");
  if (parts.length >= 3) return parts.slice(1, -1).join("-");
  return undefined;
}

function parseDefendPolicies(
  policies: RawPackagePolicy[]
): DefendPolicyPosture[] {
  const out: DefendPolicyPosture[] = [];

  for (const policy of policies) {
    const inputs = Array.isArray(policy.inputs) ? policy.inputs : [];
    for (const input of inputs) {
      const value = (input as Record<string, unknown>)?.config as
        | { policy?: { value?: Record<string, unknown> } }
        | undefined;
      const osConfigs = value?.policy?.value;
      if (!osConfigs) continue;

      for (const os of ["windows", "mac", "linux"] as const) {
        const osConfig = osConfigs[os] as Record<string, unknown> | undefined;
        if (!osConfig) continue;

        const protections: DefendProtection[] = [];
        for (const p of PROTECTIONS) {
          const mode = (osConfig[p] as { mode?: string } | undefined)?.mode;
          if (isProtectionMode(mode)) {
            protections.push({ protection: p, intended_mode: mode });
          }
        }

        const events = osConfig.events as Record<string, boolean> | undefined;
        const captured_event_categories = events
          ? Object.entries(events)
              .filter(([, on]) => on === true)
              .map(([k]) => k)
          : [];

        if (protections.length) {
          out.push({
            policy_id: policy.id,
            policy_name: policy.name,
            os,
            protections,
            captured_event_categories,
          });
        }
      }
    }
  }

  return out;
}

function isProtectionMode(mode: unknown): mode is ProtectionMode {
  return mode === "off" || mode === "detect" || mode === "prevent";
}

function mapConnectors(connectors: RawActionConnector[]): ResponseConnector[] {
  const out: ResponseConnector[] = [];
  for (const c of connectors) {
    if (EXCLUDED_CONNECTOR_TYPES.has(c.connector_type_id)) continue;
    const mapped = CONNECTOR_MAP[c.connector_type_id];
    out.push({
      id: c.id,
      type: c.connector_type_id,
      name: c.name,
      capability_domain: mapped?.domain ?? "other",
      actions: mapped?.actions ?? ["invoke"],
      ...(mapped?.reveals ? { reveals_third_party_tech: mapped.reveals } : {}),
    });
  }
  return out;
}

/** Fold a two-column ES|QL STATS result into a `{ key: numericValue }` record. */
function esqlToRecord(
  result: EsqlResult,
  keyCol: string,
  valueCol: string
): Record<string, number> {
  const keyIdx = result.columns.findIndex((c) => c.name === keyCol);
  const valIdx = result.columns.findIndex((c) => c.name === valueCol);
  if (keyIdx === -1 || valIdx === -1) return {};

  const out: Record<string, number> = {};
  for (const row of result.values) {
    const key = row[keyIdx];
    const val = row[valIdx];
    if (key == null) continue;
    out[String(key)] = Number(val ?? 0);
  }
  return out;
}

/**
 * True when an ES|QL error indicates the entity-store index simply isn't there.
 * With no matching index the query has no schema, so ES rejects `entity.type`
 * with a `verification_exception` / "Unknown column [entity.type]". We treat
 * that as "Entity Analytics not enabled" rather than a collection failure.
 */
function isMissingEntityStoreError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message.includes("Unknown column [entity.type]") ||
    (message.includes("verification_exception") && message.includes("entity.type"))
  );
}
