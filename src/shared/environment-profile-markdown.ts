/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  EnvironmentProfile,
  HuntIndexProfile,
  HuntPrimitive,
  IocClass,
  JoinKeyKind,
} from "./environment-profile.js";

/** Display order + representative field for the joinability fabric. */
const JOIN_KEY_ORDER: JoinKeyKind[] = [
  "host",
  "host_ip",
  "user",
  "agent",
  "process",
  "session",
  "network",
  "cloud",
  "container",
  "event",
];

const JOIN_KEY_FIELD: Record<JoinKeyKind, string> = {
  host: "`host.name` / `host.id`",
  host_ip: "`host.ip`",
  user: "`user.name` / `user.id`",
  agent: "`agent.id`",
  process: "`process.entity_id`",
  session: "`entry_leader.entity_id`",
  network: "`source.ip` / `destination.ip`",
  cloud: "`cloud.instance.id` / `cloud.account.id`",
  container: "`container.id`",
  event: "`event.id` / `kibana.alert.uuid`",
};

/** Display order + one-line "what it enables" for the hunt-primitive matrix. */
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

const PRIMITIVE_BLURB: Record<HuntPrimitive, string> = {
  // Foundational.
  ioc_match: "match observables (hash/ip/domain/url) against intel sources",
  frequency_analysis: "stack-count / rare-term / outlier over categorical fields",
  enrichment_match: "join observables to an enrichable reputation/CTI verdict",
  known_good_diff: "baseline / allowlist / new-term / first-seen differencing",
  string_analysis: "substring / token / entropy analysis of free-text observables",
  // Terrain-gated behavioral.
  process_lineage: "walk process parent/child trees",
  temporal_sequence: "EQL `sequence by` across ordered events",
  auth_lateral: "correlate logon failure→success / RDP lateral movement",
  network_beaconing: "detect periodic C2 beaconing",
  dns_analytics: "DGA / DNS-tunneling analysis on questions",
  cloud_identity: "pivot cloud identity (Okta/AWS/Azure sessions, assume-role)",
  geo_impossible_travel: "rare-geo / impossible-travel per user",
  egress_exfil: "egress volume anomalies per user/host",
  file_integrity: "file create/modify/delete monitoring",
  code_signature: "unsigned / untrusted binary hunts",
};

/**
 * Render an {@link EnvironmentProfile} as an analyst-readable Markdown document.
 *
 * This is the human-facing artifact the `profile-environment` workflow saves to
 * the workspace (`environment-profile.md`) for review, edit, and reuse by other
 * skills. The full machine-readable profile is embedded verbatim in a fenced
 * JSON block at the end so downstream tooling has a lossless copy.
 */
export function renderProfileMarkdown(profile: EnvironmentProfile): string {
  const {
    scope,
    inventory,
    endpoint_posture,
    response_capabilities,
    terrain,
    capabilities,
    collection_errors,
  } = profile;

  const lines: string[] = [];
  const cluster = scope.ref.deployment ?? "unknown";

  lines.push(`# Environment Profile — ${cluster}`);
  lines.push("");
  if (capabilities.is_sample_data) {
    lines.push(
      "> **Note:** this deployment carries the sample/demo data marker. " +
        "Treat it as a Showroom, not a real customer environment."
    );
    lines.push("");
  }
  lines.push(`- **Cluster:** \`${cluster}\``);
  lines.push(`- **Scope:** ${scope.level} (\`${scope.scope_id}\`)`);
  lines.push(`- **Generated:** ${profile.generated_at}`);
  lines.push("");

  lines.push("## Data sources");
  lines.push("");
  if (inventory.active_data_streams.length === 0) {
    lines.push("_No active data streams discovered._");
  } else {
    lines.push("| Data stream | Docs | Last seen |");
    lines.push("|---|---|---|");
    for (const ds of [...inventory.active_data_streams].slice(0, 40)) {
      lines.push(
        `| \`${ds.name}\` | ${fmtNum(ds.doc_count)} | ${fmtDate(ds.last_seen)} |`
      );
    }
    if (inventory.active_data_streams.length > 40) {
      lines.push(`| _…and ${inventory.active_data_streams.length - 40} more_ | | |`);
    }
  }
  lines.push("");

  const p = inventory.integration_presence;
  lines.push("## Integrations & deployed tech");
  lines.push("");
  lines.push(`- **Integrations installed:** ${p.installed.length}`);
  lines.push(`- **Cloud providers:** ${listOrNone(inventory.deployed_tech.cloud_providers)}`);
  lines.push(`- **OS mix:** ${recordOrNone(inventory.deployed_tech.os_mix)}`);
  lines.push(
    `- **Endpoint:** ${yn(p.endpoint)} · **Network:** ${yn(p.network_traffic)} · **Vulnerability:** ${yn(p.vulnerability)}`
  );
  lines.push(
    `- **Entities:** host ${inventory.entity_counts.host}, user ${inventory.entity_counts.user}, service ${inventory.entity_counts.service}, generic ${inventory.entity_counts.generic}`
  );
  lines.push(
    `- **Detection rules:** ${inventory.rule_inventory.enabled} enabled / ${inventory.rule_inventory.total} total`
  );
  lines.push("");

  lines.push("## Endpoint protection posture (intended)");
  lines.push("");
  if (endpoint_posture.defend.length === 0) {
    lines.push("_No Elastic Defend policies detected._");
  } else {
    lines.push("| Policy | OS | Protections |");
    lines.push("|---|---|---|");
    for (const d of endpoint_posture.defend) {
      const modes = d.protections
        .map((pr) => `${pr.protection}=${pr.intended_mode}`)
        .join(", ");
      lines.push(`| ${d.policy_name} | ${d.os} | ${modes} |`);
    }
  }
  if (endpoint_posture.third_party.length) {
    lines.push("");
    lines.push(
      `Third-party endpoint (presence only): ${endpoint_posture.third_party
        .map((t) => t.vendor)
        .join(", ")}`
    );
  }
  lines.push("");

  lines.push("## Response capabilities (SOAR / connectors)");
  lines.push("");
  if (response_capabilities.connectors.length === 0) {
    lines.push("_No response connectors configured._");
  } else {
    lines.push("| Connector | Domain | Actions |");
    lines.push("|---|---|---|");
    for (const c of response_capabilities.connectors) {
      lines.push(`| ${c.name} | ${c.capability_domain} | ${c.actions.join(", ")} |`);
    }
  }
  lines.push("");

  lines.push("## Field terrain (populated, not just mapped)");
  lines.push("");
  const populated = terrain.populated_ecs_fields.filter((f) => f.population_ratio > 0);
  if (populated.length === 0) {
    lines.push("_No canonical hunt fields populated in the probe window._");
  } else {
    lines.push("| Field | Family | Populated | Type conflict |");
    lines.push("|---|---|---|---|");
    for (const f of terrain.populated_ecs_fields) {
      lines.push(
        `| \`${f.field}\` | ${f.family} | ${pct(f.population_ratio)} | ${f.type_conflict ? "yes (" + f.detected_types.join("/") + ")" : "no"} |`
      );
    }
  }
  lines.push("");

  const hunt = terrain.hunt_indices ?? [];
  if (hunt.length > 0) {
    lines.push("## Hunt indices (ECS + off-schema)");
    lines.push("");
    lines.push(
      "_The unified, first-class hunt-target catalog — ECS happy-path streams and " +
        "off-schema indices alike — ranked by huntable breadth then volume. `ECS` " +
        "= standard `logs-*`/`.alerts*` naming; `off` = custom-named._"
    );
    lines.push("");
    lines.push("| Index | Schema | Class | Docs | Primitives | Join keys |");
    lines.push("|---|---|---|---|---|---|");
    for (const o of hunt) {
      const prims = (o.primitives ?? []).map((p) => p.primitive).join(", ") || "—";
      const keys =
        (o.join_keys ?? []).map((j) => j.kind).join(", ") || "—";
      lines.push(
        `| \`${o.name}\` | ${o.schema_alignment === "ecs" ? "ECS" : "off"} | ${o.data_class ?? "—"} | ${fmtNum(o.doc_count)} | ${prims} | ${keys} |`
      );
    }
    lines.push("");
    renderFieldReality(lines, hunt);
  }

  if (terrain.high_volume_off_schema.length > 0) {
    lines.push("## High-volume off-schema data");
    lines.push("");
    lines.push(
      "_Non-ECS streams holding significant data. ECS field probes above do " +
        "not cover these; huntable material was discovered by field semantics._"
    );
    lines.push("");
    if (terrain.huntable_off_schema_indices.length > 0) {
      lines.push(
        `**Hunt here too (ranked):** ${terrain.huntable_off_schema_indices
          .map((n) => `\`${n}\``)
          .join(", ")}`
      );
      lines.push("");
    }
    lines.push("| Data stream | Role | Docs | Size | Fields | Huntable material |");
    lines.push("|---|---|---|---|---|---|");
    for (const o of terrain.high_volume_off_schema) {
      const huntable = (o.huntable_fields ?? []).length
        ? (o.huntable_fields ?? [])
            .map((g) => `${g.category} (${g.fields.length})`)
            .join(", ")
        : "none discovered";
      lines.push(
        `| \`${o.name}\` | ${o.role ?? "—"} | ${fmtNum(o.doc_count)} | ${fmtBytes(o.store_size_bytes)} | ${fmtNum(o.total_fields)} | ${huntable} |`
      );
    }
    lines.push("");
    // Per-index field detail so a worker can build a concrete hunt field map.
    for (const o of terrain.high_volume_off_schema) {
      if (!(o.huntable_fields ?? []).length) continue;
      lines.push(`<details><summary><code>${o.name}</code> — discovered fields</summary>`);
      lines.push("");
      if (o.timestamp_fields?.length) {
        lines.push(
          `- **time anchors:** ${o.timestamp_fields.map((f) => `\`${f}\``).join(", ")}`
        );
      }
      for (const g of o.huntable_fields ?? []) {
        lines.push(
          `- **${g.category}:** ${g.fields.map((f) => `\`${f}\``).join(", ")}`
        );
      }
      lines.push("");
      lines.push("</details>");
      lines.push("");
    }
  }

  const mirrors = (terrain.classified_indices ?? []).filter((o) => o.mirror_of);
  if (mirrors.length) {
    lines.push("## Duplicate mirrors collapsed");
    lines.push("");
    lines.push(
      "_Reindex copies (equal doc volume within a dataset family) removed from " +
        "the hunt list so the same data isn't surfaced twice. Hunt the canonical._"
    );
    lines.push("");
    for (const o of mirrors) {
      lines.push(`- \`${o.name}\` → mirror of \`${o.mirror_of}\``);
    }
    lines.push("");
  }

  const classified = (
    terrain.classified_indices ?? terrain.high_volume_off_schema
  ).filter((o) => o.affordances);
  if (classified.length > 0) {
    lines.push("## Classification review (approve / correct)");
    lines.push("");
    lines.push(
      "_Heuristic skeleton for each off-schema index: what a worker may do with " +
        "it (**H**unt · **M**atch · **E**nrich · **P**ivot), how sure the heuristic " +
        "is, and why. **Low-confidence rows are listed first** — review those, then " +
        "approve or correct before workers rely on them._"
    );
    lines.push("");
    lines.push("| Index | H | M | E | P | Confidence | Source | Evidence |");
    lines.push("|---|---|---|---|---|---|---|---|");
    const rank = { low: 0, medium: 1, high: 2 } as const;
    const sorted = [...classified].sort(
      (a, b) => rank[a.affordances!.confidence] - rank[b.affordances!.confidence]
    );
    for (const o of sorted) {
      const a = o.affordances!;
      lines.push(
        `| \`${o.name}\` | ${chk(a.huntable)} | ${chk(a.matchable)} | ${chk(a.enrichable)} | ${chk(a.pivotable)} | ${a.confidence} | ${a.source} | ${a.evidence.join("; ") || "—"} |`
      );
    }
    lines.push("");
  }

  if (terrain.intel_sources.length > 0) {
    lines.push("## Intelligence / enrichment sources (not hunt targets)");
    lines.push("");
    lines.push(
      "_IOC feeds, reputation, and external-scan indices. Match telemetry " +
        "**against** these; do not hunt **on** them._"
    );
    lines.push("");
    for (const n of terrain.intel_sources) lines.push(`- \`${n}\``);
    lines.push("");
  }

  const tree = terrain.process_tree_indices;
  const lineageIdx = terrain.high_volume_off_schema.filter((o) => o.lineage);
  if (tree.full.length || tree.parent_only.length) {
    lines.push("## Process lineage (parent/child)");
    lines.push("");
    lines.push(
      "_Which indices support process-tree reconstruction. `full` = stable child " +
        "id plus a join key (parent entity_id / ancestry / session leaders); " +
        "`parent_only` = parent attributes but no reliable join._"
    );
    lines.push("");
    if (tree.full.length) {
      lines.push(
        `**Full tree (ranked):** ${tree.full.map((n) => `\`${n}\``).join(", ")}`
      );
      lines.push("");
    }
    if (tree.parent_only.length) {
      lines.push(
        `**Parent-only:** ${tree.parent_only.map((n) => `\`${n}\``).join(", ")}`
      );
      lines.push("");
    }
    lines.push("| Index | Capability | child id | parent join | ancestry | leaders | ppid | join fields |");
    lines.push("|---|---|---|---|---|---|---|---|");
    for (const o of lineageIdx) {
      const l = o.lineage!;
      lines.push(
        `| \`${o.name}\` | ${l.capability} | ${yn(l.child_id)} | ${yn(l.parent_join_key)} | ${yn(l.ancestry_array)} | ${yn(l.session_leaders)} | ${yn(l.ppid)} | ${l.join_fields.map((f) => `\`${f}\``).join(", ") || "—"} |`
      );
    }
    lines.push("");
  }

  const matrix = terrain.primitive_matrix ?? {};
  const matrixEntries = PRIMITIVE_ORDER.filter((p) => (matrix[p] ?? []).length);
  if (matrixEntries.length) {
    lines.push("## Hunt-primitive matrix");
    lines.push("");
    lines.push(
      "_Composable hunt tactics the environment can support, derived from field " +
        "shape / affordances / available sources (never from ATT&CK). Spans " +
        "foundational tactics (IOC match, frequency analysis, enrichment, " +
        "known-good diff, string analysis) and terrain-gated behavioral ones " +
        "(lineage, sequencing, beaconing, …). For each primitive, the hunt-target " +
        "indices that support it, ranked by volume._"
    );
    lines.push("");
    lines.push("| Primitive | What it enables | Indices |");
    lines.push("|---|---|---|");
    for (const p of matrixEntries) {
      const idx = (matrix[p] ?? []).map((n) => `\`${n}\``).join(", ");
      lines.push(`| \`${p}\` | ${PRIMITIVE_BLURB[p]} | ${idx} |`);
    }
    lines.push("");
  }

  const byKey = terrain.joinability?.by_key ?? {};
  const joinEntries = JOIN_KEY_ORDER.filter((k) => (byKey[k] ?? []).length);
  if (joinEntries.length) {
    lines.push("## Joinability (pivot / sequence / dedup fabric)");
    lines.push("");
    lines.push(
      "_For each join key, the hunt indices that carry it — all mutually joinable " +
        "on that key. Use for **sequencing** (`process`/`session`), **dedup** " +
        "(`event`), **matching across primitives** and **cueing follow-up hunts** " +
        "(`host`/`user`/`agent`/`network`)._"
    );
    lines.push("");
    lines.push("| Join key | Field | Indices |");
    lines.push("|---|---|---|");
    for (const k of joinEntries) {
      const names = (byKey[k] ?? []).map((n) => `\`${n}\``).join(", ");
      lines.push(`| \`${k}\` | ${JOIN_KEY_FIELD[k]} | ${names} |`);
    }
    lines.push("");
  }

  lines.push("## Coverage gaps");
  lines.push("");
  if (terrain.blind_spots.length === 0) {
    lines.push("_No notable gaps detected._");
  } else {
    for (const gap of terrain.blind_spots) lines.push(`- ${gap}`);
  }
  lines.push("");

  lines.push("## Advanced capabilities in use");
  lines.push("");
  lines.push(`- **Entity Analytics:** ${yn(capabilities.entity_analytics)}`);
  lines.push(`- **Attack Discovery:** ${yn(capabilities.attack_discovery)}`);
  lines.push(`- **Cases:** ${yn(capabilities.cases)}`);
  lines.push(`- **Correlation corpus:** ${yn(capabilities.correlation_corpus)}`);
  lines.push("");

  lines.push("## Not inspected");
  lines.push("");
  if (collection_errors.length === 0) {
    lines.push("_All sections inspected successfully._");
  } else {
    for (const err of collection_errors) lines.push(`- ${err}`);
  }
  lines.push("");

  lines.push("## Machine-readable profile");
  lines.push("");
  lines.push("```json");
  lines.push(JSON.stringify(profile, null, 2));
  lines.push("```");
  lines.push("");

  return lines.join("\n");
}

const IOC_CLASS_ORDER: IocClass[] = [
  "ip",
  "domain",
  "url",
  "hash",
  "file_path",
  "registry",
  "named_pipe",
  "mutex",
];

/**
 * Per hunt-index FIELD REALITY: the addressable ground truth a hunt generator
 * needs. Surfaces only the "gotcha" facts (relocated / nested / multivalue / cast)
 * plus the precomputed IOC-match field lists, matched-indicator accessor, and
 * rule metadata — so the analyst can eyeball what a hunt would actually query.
 */
function renderFieldReality(lines: string[], hunt: HuntIndexProfile[]): void {
  const withReality = hunt.filter((o) => o.field_reality);
  if (!withReality.length) return;

  lines.push("### Field reality (addressable ground truth)");
  lines.push("");
  lines.push(
    "_Resolved per hunt index from `_field_caps` + a sample doc. `actual_path` is " +
      "the REAL path to query (may differ from the ECS name); `nested` fields need " +
      "`_search`; `mv` fields need DSL terms aggs, not ES|QL `IN`; `ip` fields cast " +
      "with `::keyword` to match string IOC lists._"
  );
  lines.push("");

  for (const o of withReality) {
    const fr = o.field_reality!;
    const facts = Object.entries(fr.fields).filter(([, f]) => f.present);
    // Only the fields with something worth flagging (relocated, nested, mv, cast).
    const notable = facts.filter(
      ([canon, f]) =>
        f.actual_path !== canon ||
        !f.esql_addressable ||
        f.multivalue ||
        f.cast_hint
    );
    lines.push(
      `<details><summary><code>${o.name}</code> — ${o.data_class ?? "?"} · ${facts.length} canonical fields</summary>`
    );
    lines.push("");
    if (notable.length) {
      lines.push("| Canonical | actual_path | type | ES\\|QL | nested | mv | cast |");
      lines.push("|---|---|---|---|---|---|---|");
      for (const [canon, f] of notable) {
        lines.push(
          `| \`${canon}\` | \`${f.actual_path}\` | ${f.es_type} | ${chk(f.esql_addressable)} | ${f.nested_parent ? `\`${f.nested_parent}\`` : "·"} | ${chk(f.multivalue)} | ${f.cast_hint ?? "·"} |`
        );
      }
      lines.push("");
    }
    const iocLines = IOC_CLASS_ORDER.filter(
      (c) => (fr.ioc_match_fields[c] ?? []).length
    ).map((c) => `- **${c}**: ${fr.ioc_match_fields[c].map((x) => `\`${x}\``).join(", ")}`);
    if (iocLines.length) {
      lines.push("IOC-match fields (addressable + cast):");
      lines.push(...iocLines);
      lines.push("");
    }
    if (fr.matched_atomic) {
      lines.push(
        `Matched indicator: \`${fr.matched_atomic.field}\` (${fr.matched_atomic.access})`
      );
      lines.push("");
    }
    if (fr.rule_fields) {
      const t = fr.rule_fields.technique_id;
      const s = fr.rule_fields.subtechnique_id;
      lines.push(
        `Rule fields: name \`${fr.rule_fields.rule_name}\`; technique \`${t.field}\`` +
          ` (mv ${yn(t.multivalue)}, populated ${yn(t.populated)}); subtechnique \`${s.field}\`` +
          ` (mv ${yn(s.multivalue)}, populated ${yn(s.populated)})`
      );
      lines.push("");
    }
    const id = o.identity_fields;
    if (id) {
      const d = id.direct;
      lines.push(
        `Identity — direct: host ${anchor(d.host)}, user ${anchor(d.user)}, tenant ${anchor(d.tenant)}; ` +
          `join keys: ${id.join_keys.map((k) => `\`${k}\``).join(", ") || "—"}`
      );
      for (const r of id.resolves_via) {
        lines.push(
          `- resolves via \`${r.key}\` → ${r.to.map((n) => `\`${n}\``).join(", ")} ` +
            `yields ${r.yields.map((y) => `\`${y}\``).join(", ")}`
        );
      }
      lines.push("");
    }
    lines.push("</details>");
    lines.push("");
  }
}

function anchor(v: string | null): string {
  return v ? `\`${v}\`` : "—";
}

function yn(v: boolean): string {
  return v ? "yes" : "no";
}

function chk(v: boolean): string {
  return v ? "✓" : "·";
}

function fmtNum(n?: number): string {
  return n == null ? "—" : n.toLocaleString("en-US");
}

function fmtDate(ms?: number): string {
  return ms == null ? "—" : new Date(ms).toISOString().slice(0, 10);
}

function fmtBytes(bytes?: number): string {
  if (bytes == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let n = bytes;
  let u = 0;
  while (n >= 1024 && u < units.length - 1) {
    n /= 1024;
    u++;
  }
  return `${n.toFixed(u === 0 ? 0 : 1)} ${units[u]}`;
}

function pct(ratio: number): string {
  return `${Math.round(ratio * 100)}%`;
}

function listOrNone(items: string[]): string {
  return items.length ? items.join(", ") : "none";
}

function recordOrNone(rec: Record<string, number>): string {
  const entries = Object.entries(rec);
  return entries.length
    ? entries.map(([k, v]) => `${k} (${v})`).join(", ")
    : "none";
}
