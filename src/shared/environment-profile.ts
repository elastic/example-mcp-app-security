/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * The `EnvironmentProfile` is the product of an IPB/IPOE pass over a customer's
 * Elastic deployment. Agentic security workers (hunts, threat-emulation,
 * correlation, risk scoring, response) subscribe to it so their operations are
 * grounded in what is actually deployed and observable rather than hardcoded
 * assumptions about the terrain.
 *
 * Guiding principle: treat the profile as **evidence, not ground truth**. A
 * messy deployment is defined by the gap between intended capability and
 * effective capability (rule exceptions, endpoint allow-lists, ingest drops,
 * retention floors, low field-population). This iteration collects and surfaces
 * the raw signals; it deliberately does not yet derive covered/degraded/blind
 * verdicts (see {@link EnvironmentProfile.coverage_signals}).
 */

/** Coarse-to-fine addressing so a leaf profile can roll up into an overarching one. */
export type ScopeLevel = "fleet" | "deployment" | "space" | "datastream";

/**
 * A generic addressable target. Topology is mixed in the field (separate
 * deployments, Kibana spaces, cross-cluster search), so scope is not tied to a
 * single mechanism.
 */
export interface ProfileScope {
  readonly level: ScopeLevel;
  /** How the profiler reached this target. Any combination may be present. */
  readonly ref: {
    /** Connection / deployment identifier (e.g. the bound cluster name). */
    readonly deployment?: string;
    /** Remote cluster name when reached via cross-cluster search. */
    readonly remote_cluster?: string;
    /** Kibana space id when the scope is a single tenant space. */
    readonly space?: string;
    /** Datastream or index pattern when the scope is narrowed to one feed. */
    readonly index_pattern?: string;
  };
  /** Stable identity for caching and rollup keys: hash of `{ level, ref }`. */
  readonly scope_id: string;
  /** Links a leaf to its overarching profile, when aggregated. */
  readonly parent_id?: string;
}

export interface ActiveDataStream {
  readonly name: string;
  /** Parsed `<type>-<dataset>-<namespace>` dataset, when derivable. */
  readonly dataset?: string;
  /** Owning integration / package, when known from data-stream metadata. */
  readonly integration?: string;
  readonly doc_count?: number;
  readonly store_size_bytes?: number;
  /** Max `@timestamp` seen (ms epoch) — data freshness. */
  readonly last_seen?: number;
  /**
   * Purpose hint harvested from index/template/data-stream `_meta`
   * (`description` / `managed_by`), when available — a deterministic signal for
   * role/affordance classification before reaching for an LLM.
   */
  readonly meta_description?: string;
}

/** Presence of security-relevant integrations, plus the full installed list. */
export interface IntegrationPresence {
  readonly aws: boolean;
  readonly azure: boolean;
  readonly gcp: boolean;
  readonly endpoint: boolean;
  readonly network_traffic: boolean;
  readonly vulnerability: boolean;
  readonly alerts: boolean;
  readonly fleet: boolean;
  /** Every installed integration package name (superset of the flags above). */
  readonly installed: string[];
}

export interface DeployedTech {
  readonly cloud_providers: string[];
  /** host.os.platform -> host count. */
  readonly os_mix: Record<string, number>;
}

export interface EntityCounts {
  readonly host: number;
  readonly user: number;
  readonly service: number;
  readonly generic: number;
}

export interface RuleInventory {
  readonly total: number;
  readonly enabled: number;
  readonly disabled: number;
}

export interface EnvironmentInventory {
  readonly active_data_streams: ActiveDataStream[];
  readonly integration_presence: IntegrationPresence;
  readonly deployed_tech: DeployedTech;
  readonly entity_counts: EntityCounts;
  readonly rule_inventory: RuleInventory;
}

export type ProtectionName =
  | "malware"
  | "ransomware"
  | "memory_protection"
  | "behavior_protection";

export type ProtectionMode = "off" | "detect" | "prevent";

/** Intended posture for one Elastic Defend protection, per policy. */
export interface DefendProtection {
  readonly protection: ProtectionName;
  readonly intended_mode: ProtectionMode;
  /** Applied status (Step 2 / policy_response); undefined until terrain runs. */
  readonly applied?: "active" | "failed" | "degraded";
  readonly hosts_covered?: number;
}

export interface DefendPolicyPosture {
  readonly policy_id: string;
  readonly policy_name: string;
  readonly os: "windows" | "mac" | "linux";
  readonly protections: DefendProtection[];
  /** Endpoint event categories the policy is configured to collect. */
  readonly captured_event_categories: string[];
}

/**
 * Third-party endpoint tooling. Only presence + telemetry coverage are
 * observable; per-protection modes are not exposed the way Defend's are.
 */
export interface ThirdPartyEndpoint {
  readonly vendor: "crowdstrike" | "sentinel_one" | "ms_defender_endpoint";
  readonly present: boolean;
  readonly telemetry_datasets: string[];
}

export interface EndpointPosture {
  readonly defend: DefendPolicyPosture[];
  readonly third_party: ThirdPartyEndpoint[];
}

export type CapabilityDomain =
  | "endpoint"
  | "network"
  | "cloud"
  | "identity"
  | "ticketing"
  | "notify"
  /** Enrichment / intel lookups (e.g. VirusTotal). */
  | "enrich"
  /** Automation / integration surfaces (webhooks, GitHub, index writes). */
  | "automation"
  /** Configured but not classified into a known response domain. */
  | "other";

/**
 * A configured SOAR/connector capability. Doubles as a second signal for the
 * third-party endpoint/network/cloud/identity tooling a customer runs, and
 * defines what a worker can actually enforce.
 */
export interface ResponseConnector {
  readonly id: string;
  readonly type: string;
  readonly name: string;
  readonly capability_domain: CapabilityDomain;
  readonly actions: string[];
  /** The third-party tech this connector implies is deployed, when inferable. */
  readonly reveals_third_party_tech?: string;
}

export interface ResponseCapabilities {
  readonly connectors: ResponseConnector[];
}

// --- Later phases: typed now so the contract is stable; populated later. ---

/** Populated-field terrain (Step 2). */
export interface PopulatedField {
  readonly field: string;
  readonly family: string;
  readonly population_ratio: number;
  readonly detected_types: string[];
  /** True when the same field resolves to conflicting types across indices. */
  readonly type_conflict: boolean;
}

/**
 * A high-volume data stream that does not follow ECS naming (`logs-*` /
 * `metrics-*`). These frequently hold the bulk of a cluster's data (custom
 * exports, research telemetry) yet are invisible to convention-based ECS field
 * probes — the defining trap of a "messy" environment.
 */
/**
 * Huntable fields discovered inside an off-schema index, grouped by the
 * observable category they map to (process, ip, hash, domain, intel, …). This
 * is how a worker recovers a field map for data that doesn't use ECS names.
 */
export interface HuntableFieldGroup {
  readonly category: string;
  readonly fields: string[];
}

/**
 * How completely an index supports process parent/child (lineage) analysis:
 * - `full`     — a stable child id plus a real join key (parent entity_id,
 *                ancestry array, or session leaders) → arbitrary-depth trees.
 * - `parent_only` — parent attributes / command line / ppid present but no join
 *                key → single-hop pivots, no reliable tree reconstruction.
 * - `none`     — no lineage material.
 */
/**
 * The role an index plays for hunting. Only `telemetry` and `alerts` are hunt
 * *targets* (observations of the environment / detection output). `intelligence`
 * is a match-list / enrichment *source* (IOC feeds, reputation, external scan
 * results) — you match telemetry against it, you do not hunt on it. `reference`
 * is operational/metadata with no hunt value.
 */
export type IndexRole =
  | "telemetry"
  | "alerts"
  | "intelligence"
  | "reference"
  | "unknown";

export type AffordanceConfidence = "high" | "medium" | "low";

/** How an affordance verdict was reached (deterministic → model → human). */
export type AffordanceSource = "heuristic" | "llm" | "human";

/**
 * What an index affords a worker — a multi-label alternative to a single `role`,
 * since an index can be several things at once (an alert stream is both huntable
 * and matchable). This is the skeleton the LLM confirms and the human approves.
 *
 * - `huntable`   — run detection logic over it (owned-asset telemetry / alerts).
 * - `matchable`  — join telemetry against it (IOC feeds, extracted C2 configs).
 * - `enrichable` — adds context to an entity/observable (reputation, CTI verdicts).
 * - `pivotable`  — supports lineage / graph traversal (process trees, entity joins).
 */
export interface IndexAffordances {
  readonly huntable: boolean;
  readonly matchable: boolean;
  readonly enrichable: boolean;
  readonly pivotable: boolean;
  readonly confidence: AffordanceConfidence;
  /** Human-readable signals behind the verdict (structural facts, name tokens). */
  readonly evidence: string[];
  readonly source: AffordanceSource;
  /** Short natural-language "what this index is" (LLM/human stages only). */
  readonly characterization?: string;
}

export type ProcessTreeCapability = "full" | "parent_only" | "none";

/**
 * Deterministic lineage classification for one index, derived from its field map
 * (all casings: ECS `process.parent.*`, Elastic-Endpoint `Events.process.*`,
 * `Target.process.*`, vendor variants). This is the profiler-run version of the
 * hand-derived capability matrix.
 */
export interface LineageSignals {
  readonly capability: ProcessTreeCapability;
  /** Stable child id (`process.entity_id`, any casing). */
  readonly child_id: boolean;
  /** Parent attributes (`process.parent.name` / `.executable`). */
  readonly parent_attrs: boolean;
  /** Parent join key (`process.parent.entity_id`). */
  readonly parent_join_key: boolean;
  /** Ancestor id array (`process.Ext.ancestry`). */
  readonly ancestry_array: boolean;
  /** Sessions View leaders (`entry/session/group_leader.entity_id`). */
  readonly session_leaders: boolean;
  /** Numeric parent pid (`ppid` / `unique_ppid`). */
  readonly ppid: boolean;
  readonly parent_command_line: boolean;
  /** The concrete field(s) a worker should join on, best-first. */
  readonly join_fields: string[];
}

/**
 * Hunt primitives — the composable *tactics* a worker can run against grounded
 * telemetry, each derived deterministically from field shape / affordances the
 * same way {@link LineageSignals} is. A primitive names *a way of interrogating
 * fields*, not an ATT&CK technique: ATT&CK is descriptive, this vocabulary is
 * what the **terrain** analytically affords. Primitives COMPOSE — a hunt uses one
 * alone or several together (e.g. `frequency_analysis` to surface rare parents,
 * then `process_lineage` to walk them, then `ioc_match` to score the binaries).
 *
 * Two tiers:
 *
 * FOUNDATIONAL — available whenever a field exists (optionally plus an intel /
 * enrichment source), independent of behavioral shape. These are the tactics an
 * analyst reaches for first and were previously absent:
 *   - `ioc_match`          observable field (hash/ip/domain/url) × ≥1 intel/match
 *                          source ({@link Terrain.intel_sources}).
 *   - `frequency_analysis` stack-count / rare-term / outlier over any populated
 *                          categorical field. Effectively always-available once
 *                          the index has a huntable field; confidence tracks
 *                          field cardinality.
 *   - `enrichment_match`   observable joined against an enrichable verdict source
 *                          (reputation / CTI); needs an index with
 *                          {@link IndexAffordances.enrichable}.
 *   - `known_good_diff`    baseline / allowlist / new-term / first-seen
 *                          differencing; needs a stable key or a first-seen anchor.
 *   - `string_analysis`    substring / tokenization / entropy over free-text
 *                          observables (command lines, urls, UAs, registry paths).
 *
 * TERRAIN-GATED BEHAVIORAL — need a specific field shape; grounded in the
 * behavioral/ML detection packages Elastic ships (beaconing, lmd, pad, ded, dga,
 * okta/aws/azure identity, fim) plus the tradecraft GenAI-hunter pivots:
 *   process_lineage, temporal_sequence, auth_lateral, network_beaconing,
 *   dns_analytics, cloud_identity, geo_impossible_travel, egress_exfil,
 *   file_integrity, code_signature.
 *
 * Additive by contract: new tactics append; existing members are never renamed or
 * removed, and the {@link PrimitiveSupport} / {@link Terrain.primitive_matrix}
 * shapes are stable — only the set of possible keys grows.
 *
 * TODO(candidates): `threshold_aggregation` (subsumed by `frequency_analysis`
 * today), `asn_outlier` (a `geo_impossible_travel` sibling), and splitting
 * `new_term` out of `known_good_diff` — add each when a distinct field signal
 * justifies separating it.
 */
export type HuntPrimitive =
  // Terrain-gated behavioral (original set — unchanged).
  | "process_lineage"
  | "temporal_sequence"
  | "auth_lateral"
  | "network_beaconing"
  | "dns_analytics"
  | "cloud_identity"
  | "geo_impossible_travel"
  | "egress_exfil"
  | "file_integrity"
  | "code_signature"
  // Foundational (always-available, or field + a source).
  | "ioc_match"
  | "frequency_analysis"
  | "enrichment_match"
  | "known_good_diff"
  | "string_analysis";

export interface PrimitiveSupport {
  readonly primitive: HuntPrimitive;
  readonly confidence: AffordanceConfidence;
  /** Concrete fields a worker would build the primitive's query on, best-first. */
  readonly fields: string[];
  /**
   * For the corpus-matching primitives (`ioc_match`, `enrichment_match`) only:
   * where the corpus to match/enrich against comes from. `in_cluster` = a
   * self-serviced loop (the cluster ships an intel/enrichment source);
   * `byo` = the index is fully matchable but the worker must supply the
   * indicator/enrichment feed (ti-loupe / MISP / external service / cross-cluster).
   * Matchability itself is a per-index field-shape fact and is NOT gated on this;
   * absence of an in-cluster source downgrades the mode, never the capability.
   */
  readonly source_mode?: "in_cluster" | "byo";
}

/**
 * What KIND of data an index holds — the single most decisive terrain signal for
 * a hunt generator, because it gates which primitives are even *possible*:
 * - `raw_event` — per-event endpoint/network telemetry (process/file/dns/registry
 *   events). Enables lineage, sequencing, and command-line / file / registry
 *   hunts on live rows.
 * - `alert` — detection-engine output (`.alerts-security.*`): rule metadata,
 *   technique tags, matched indicators. Enables ioc_match / technique_association
 *   / entity_pivot; NOT raw eventing.
 * - `detonation` — sandbox / detonation results.
 * - `telemetry_aggregate` — rolled-up counts / summaries, not per-event rows.
 */
export type DataClass =
  | "raw_event"
  | "alert"
  | "detonation"
  | "telemetry_aggregate";

/**
 * Class-level hunt-capability vocabulary — a coarse gating view keyed by
 * {@link DataClass}. A SUPERSET of {@link HuntPrimitive}: it adds a few
 * class-capability labels the generator switches on (`commandline_match`,
 * `file_match`, `registry_match`, `technique_association`, `entity_pivot`) that
 * are not (yet) field-derived {@link HuntPrimitive}s. Kept as a superset so the
 * field-derived primitive vocabulary stays tight while the generator still gets
 * the exact capability strings it needs from a data class.
 */
export type DataClassPrimitive =
  | HuntPrimitive
  | "commandline_match"
  | "file_match"
  | "registry_match"
  | "technique_association"
  | "entity_pivot";

/**
 * Ground-truth map from data class to the tactics that class supports.
 * Authoritative and shared: both the profiler and the hunt generator import this
 * so a class always gates to the same capability set. Persisted on the profile as
 * {@link Terrain.primitives_supported_by_class}.
 */
export const PRIMITIVES_SUPPORTED_BY_CLASS: Record<
  DataClass,
  readonly DataClassPrimitive[]
> = {
  raw_event: [
    "process_lineage",
    "temporal_sequence",
    "commandline_match",
    "file_match",
    "registry_match",
    "ioc_match",
  ],
  alert: ["ioc_match", "technique_association", "entity_pivot"],
  detonation: ["ioc_match", "commandline_match", "file_match"],
  telemetry_aggregate: ["technique_association", "frequency_analysis"],
} as const;

/** IOC observable classes a generator ORs together per class within one hunt. */
export type IocClass =
  | "ip"
  | "domain"
  | "url"
  | "hash"
  | "file_path"
  | "registry"
  | "named_pipe"
  | "mutex";

/**
 * The addressable, query-ready reality of ONE canonical field in ONE index —
 * everything the generator needs to emit correct, runnable ES|QL (or know when to
 * fall back to `_search`) without probing the cluster itself.
 */
export interface FieldFact {
  readonly present: boolean;
  /**
   * The REAL addressable path to query — may be nested/prefixed relative to the
   * canonical ECS name (e.g. `timeline.event.process.command_line` for
   * `process.command_line`).
   */
  readonly actual_path: string;
  /** ES mapping type: `"ip"` | `"keyword"` | `"text"` | `"nested"` | … */
  readonly es_type: string;
  /** False when the field — or an ancestor — is `nested` (ES|QL can't address it). */
  readonly esql_addressable: boolean;
  /** The nested ancestor path that forces `_search` access, or null. */
  readonly nested_parent: string | null;
  /** True when values are multivalue — hunts must use DSL terms aggs, not ES|QL `IN`. */
  readonly multivalue: boolean;
  /** Cast needed to match a string IOC list, e.g. `"::keyword"` for an `ip` field. */
  readonly cast_hint: string | null;
  /** A sample value (truncated) proving population, or null. */
  readonly example_value: string | null;
}

/** Where a TI-match alert stores the matched indicator, and how to read it. */
export interface MatchedAtomic {
  readonly field: string;
  readonly access: "esql" | "search_nested";
}

/** Rule / detection metadata fields (alerts), with multivalue + population flags. */
export interface RuleFields {
  readonly rule_name: string;
  readonly technique_id: {
    readonly field: string;
    readonly multivalue: boolean;
    readonly populated: boolean;
  };
  readonly subtechnique_id: {
    readonly field: string;
    readonly multivalue: boolean;
    readonly populated: boolean;
  };
}

/**
 * How one hunt index recovers identity it LACKS by joining to indices that carry
 * it — the concrete edge of the identity fabric.
 */
export interface IdentityResolution {
  /** The concrete join field that bridges (present + populated on `from`). */
  readonly key: string;
  /** The index missing the identity (this hunt index). */
  readonly from: string;
  /** Indices that share `key` (populated) and carry identity `from` lacks. */
  readonly to: string[];
  /** Identity field paths recoverable by following the join (e.g. `host.name`). */
  readonly yields: string[];
}

/**
 * Identity terrain for one hunt index: the direct identity anchors it carries,
 * the join keys it can be pivoted on, and — crucially — how it resolves identity
 * it LACKS via the join fabric. "Present" means present AND populated: a
 * mapped-but-empty field (e.g. `user.name` at ~0% on a raw-event stream) is
 * treated as absent and routed through a populated join key instead. Populated
 * ratios live on {@link JoinKey.population_ratio} for the join keys.
 */
export interface IdentityFields {
  /** Directly present + populated identity anchor field paths, or null. */
  readonly direct: {
    readonly host: string | null;
    readonly user: string | null;
    readonly tenant: string | null;
  };
  /** Join keys present + populated on this index (concrete fields, best-first). */
  readonly join_keys: string[];
  /** Resolution fabric: bridge identity gaps by joining to other hunt indices. */
  readonly resolves_via: IdentityResolution[];
}

/**
 * Persisted FIELD REALITY for one hunt index — the ground truth a hunt generator
 * needs to emit runnable, grounded queries with no live probing. Computed
 * deterministically from `_field_caps` (types + `nested` detection) plus one
 * sample doc (example values / multivalue), and recomputed on every refresh.
 */
export interface FieldReality {
  /** Canonical/ECS field name → its addressable reality in THIS index. */
  readonly fields: Record<string, FieldFact>;
  /**
   * Precomputed, ordered, addressable + cast field expressions to OR together per
   * IOC class (e.g. `ip: ["source.ip::keyword", "destination.ip::keyword"]`).
   * Nested / non-addressable fields are excluded so the emitted ES|QL always runs.
   */
  readonly ioc_match_fields: Record<IocClass, string[]>;
  /** Where a TI-match alert keeps the matched indicator, and how to read it. */
  readonly matched_atomic: MatchedAtomic | null;
  /** Rule/technique metadata (alerts only), or null. */
  readonly rule_fields: RuleFields | null;
}

/**
 * Whether an index sits on the ECS happy path (standard `logs-*` / `.alerts-*` /
 * `.entities-*` naming + schema) or is off-schema (custom-named / non-ECS). ECS
 * indices are the primary hunt substrate; off-schema is where data "hides".
 */
export type SchemaAlignment = "ecs" | "off_schema";

/**
 * A stable key a worker can join, deduplicate, sequence, or pivot on. The `kind`
 * is the semantic entity (host, user, …); `field` is the concrete ECS field that
 * carries it. Grounds cross-index correlation ("who else has `host.name`?").
 */
export type JoinKeyKind =
  | "agent" //     agent.id — the sensor/agent installation
  | "host" //      host.name / host.id / host.hostname
  | "host_ip" //   host.ip
  | "user" //      user.name / user.id
  | "process" //   process.entity_id — sequencing / lineage
  | "session" //   entry_leader.entity_id — Sessions View
  | "network" //   source.ip / destination.ip
  | "cloud" //     cloud.instance.id / cloud.account.id
  | "container" // container.id
  | "event"; //    event.id / kibana.alert.uuid — dedup / exact-event match

export interface JoinKey {
  readonly kind: JoinKeyKind;
  /** The concrete field carrying this key (best-first if several). */
  readonly field: string;
  /**
   * Populated fraction (0–1), when measured (ECS happy-path indices). Absent when
   * only presence was determined from the mapping (cheap `_field_caps` path).
   */
  readonly population_ratio?: number;
}

/**
 * Cross-index joinability roll-up: the correlation fabric a worker uses to
 * sequence, deduplicate, match findings across primitives, and cue follow-up
 * hunts. `by_key` is the adjacency view — for each join key, every hunt index
 * that carries it (all mutually joinable on that key), ranked by volume.
 */
export interface Joinability {
  readonly by_key: Partial<Record<JoinKeyKind, string[]>>;
}

export interface OffSchemaIndex {
  readonly name: string;
  /**
   * Hunting role, derived from structure/name. Distinguishes hunt targets
   * (`telemetry`/`alerts`) from enrichment sources (`intelligence`) so a worker
   * doesn't try to hunt on an IOC feed or external-scan index. Coarse bucket;
   * see {@link OffSchemaIndex.affordances} for the multi-label view.
   */
  readonly role?: IndexRole;
  /**
   * Multi-label capabilities + confidence/evidence/source. The heuristic skeleton
   * populates this (`source: "heuristic"`); later stages confirm (`"llm"`) and
   * approve (`"human"`).
   */
  readonly affordances?: IndexAffordances;
  /**
   * Stable fingerprint of the index's *shape* (name + sorted huntable field
   * names). The catalog key: a sticky human/LLM verdict re-applies on reruns
   * only while the shape is unchanged; a material shape change invalidates it and
   * forces re-review. Echoed back by an approval so the write targets the right
   * entry.
   */
  readonly signature?: string;
  readonly doc_count?: number;
  readonly store_size_bytes?: number;
  /** Max `@timestamp` seen (ms epoch), when derivable. */
  readonly last_seen?: number;
  /** Canonical hunt fields that ARE mapped here despite the non-ECS name. */
  readonly ecs_hunt_fields_mapped: string[];
  /** Total mapped fields — a breadth signal for how rich the index is. */
  readonly total_fields?: number;
  /** Date-typed fields — candidate time anchors for recency/hunt queries. */
  readonly timestamp_fields?: string[];
  /**
   * Huntable fields discovered by name/type semantics (not exact ECS names),
   * grouped by observable category. The deterministic answer to "where is the
   * huntable material in this non-ECS index?".
   */
  readonly huntable_fields?: HuntableFieldGroup[];
  /** Process parent/child (lineage) capability, when process fields are present. */
  readonly lineage?: LineageSignals;
  /** Hunting primitives supported by this index's field shape (supported only). */
  readonly primitives?: PrimitiveSupport[];
  /** ECS happy-path vs. off-schema. Set on every probed hunt-index profile. */
  readonly schema_alignment?: SchemaAlignment;
  /** Stable keys this index can be joined / deduplicated / pivoted on. */
  readonly join_keys?: JoinKey[];
  /**
   * Normalized dataset family key (transform prefixes / date-gen-version suffixes
   * stripped), so raw/cleaned/export variants of one logical dataset group
   * together. Used for mirror detection.
   */
  readonly family?: string;
  /**
   * Set when this index is a duplicate mirror (equal doc volume within its
   * {@link OffSchemaIndex.family}) of another — names the canonical it mirrors.
   * Mirrors are kept for transparency but excluded from the huntable list and the
   * primitive/lineage roll-ups so the same data isn't surfaced twice.
   */
  readonly mirror_of?: string;
  /**
   * What kind of data this index holds — gates which primitives are possible.
   * Derived deterministically from field shape + name (see {@link DataClass}).
   */
  readonly data_class?: DataClass;
  /**
   * Addressable field ground-truth for the hunt generator — resolved actual paths,
   * ES types, nested/ES|QL-addressability, cast hints, IOC-match field lists, and
   * rule metadata (see {@link FieldReality}). Computed for hunt indices only.
   */
  readonly field_reality?: FieldReality;
  /**
   * Identity terrain: direct anchors, populated join keys, and the resolution
   * fabric this index uses to recover identity it lacks (see {@link IdentityFields}).
   */
  readonly identity_fields?: IdentityFields;
}

/**
 * Per-index hunt-target profile. Spans both ECS happy-path and off-schema indices
 * (see {@link OffSchemaIndex.schema_alignment}); the `OffSchemaIndex` name is
 * retained for back-compat but the record is schema-agnostic.
 */
export type HuntIndexProfile = OffSchemaIndex;

export interface Terrain {
  readonly populated_ecs_fields: PopulatedField[];
  /** ECS-shaped hunt streams that actually hold data, ranked by doc volume. */
  readonly resolved_hunt_indices: string[];
  /**
   * First-class, unified hunt-target catalog: every probed hunt index — ECS happy
   * path **and** off-schema — with its huntable fields, lineage, primitives, and
   * join keys, ranked by breadth then volume. The primary input a worker reads to
   * pick where to hunt; {@link Terrain.high_volume_off_schema} is the off-schema
   * subset kept for the "where is my data hiding" narrative.
   */
  readonly hunt_indices?: HuntIndexProfile[];
  readonly off_schema_indices: string[];
  /**
   * Highest-volume non-ECS data streams — where the data actually is when the
   * ECS field probes come back empty. Each notes whether canonical hunt fields
   * are nonetheless mapped, so a worker can decide whether it can hunt there.
   */
  readonly high_volume_off_schema: OffSchemaIndex[];
  /**
   * The full classification skeleton for every probed off-schema index that
   * carries material — hunt targets **and** intelligence/enrichment sources —
   * each with its {@link IndexAffordances}. This is the canonical input to the
   * human-approval review (and, later, the signature-keyed catalog); the other
   * terrain buckets ({@link Terrain.high_volume_off_schema},
   * {@link Terrain.intel_sources}) are consumer-facing views derived from it.
   */
  readonly classified_indices?: OffSchemaIndex[];
  /**
   * Off-schema streams that carry huntable material, ranked by breadth of
   * discovered observable categories then volume — the direct "hunt here too"
   * list a worker should read when the ECS streams are empty.
   */
  readonly huntable_off_schema_indices: string[];
  /**
   * Intelligence / enrichment sources (IOC feeds, reputation, external scan
   * results) discovered among the off-schema indices. These are match-list /
   * enrichment inputs — a worker matches telemetry *against* them rather than
   * hunting *on* them — so they are deliberately excluded from the huntable list.
   */
  readonly intel_sources: string[];
  /**
   * Indices that support process parent/child analysis, tiered by capability and
   * ranked by volume within tier. The profiler-run version of the lineage
   * capability matrix — a worker reads this directly to pick a tree source.
   */
  readonly process_tree_indices: {
    readonly full: string[];
    readonly parent_only: string[];
  };
  /**
   * Hunt-primitive support matrix: for each {@link HuntPrimitive}, the hunt-target
   * indices that support it, ranked by volume (mirrors excluded so a primitive
   * isn't advertised twice). Spans the full, composable vocabulary — foundational
   * tactics (`ioc_match`, `frequency_analysis`, `enrichment_match`,
   * `known_good_diff`, `string_analysis`) as well as terrain-gated behavioral ones
   * (`process_lineage`, `temporal_sequence`, …). Every verdict is terrain-derived
   * from field shape / affordances / available sources — never bound to ATT&CK.
   * The worker-facing answer to "which tactics can I run here, and where?".
   */
  readonly primitive_matrix?: Partial<Record<HuntPrimitive, string[]>>;
  /**
   * Whether `ioc_match` is a self-serviced loop here: `true` when the cluster ships
   * an in-cluster intel/match source (see {@link Terrain.intel_sources}); `false`
   * means indices are fully matchable but the worker must bring its own indicator
   * list. Never gates the {@link Terrain.primitive_matrix} `ioc_match` list — only
   * annotates the mode (per-index detail lives on {@link PrimitiveSupport.source_mode}).
   */
  readonly ioc_match_self_serviced?: boolean;
  /**
   * Whether `enrichment_match` is self-serviced: `true` when an in-cluster enrichable
   * verdict source exists; `false` means matchable observables are present but the
   * worker calls an external enrichment service. Mode only — never gates capability.
   */
  readonly enrichment_self_serviced?: boolean;
  /**
   * Cross-index join fabric: for each join key (host / user / agent / …), the hunt
   * indices that carry it — the pivots a worker uses to sequence, deduplicate,
   * match findings across primitives, and cue follow-up hunts.
   */
  readonly joinability?: Joinability;
  /**
   * Class → supported-tactics gating table (mirror of
   * {@link PRIMITIVES_SUPPORTED_BY_CLASS}). Lets the generator resolve a hunt
   * index's {@link OffSchemaIndex.data_class} to the tactics it can run.
   */
  readonly primitives_supported_by_class?: Record<
    DataClass,
    readonly DataClassPrimitive[]
  >;
  /**
   * Cross-index field-presence map: canonical field → the hunt indices that carry
   * it (present + addressable). Two jobs: (1) a multi-index `FROM` list can avoid
   * erroring on a column absent from one member, and (2) it is the authoritative
   * input to the blind-spot rule — an observable is blind only if NO hunt index
   * whose {@link OffSchemaIndex.data_class} supports the needed primitive carries it.
   */
  readonly field_presence?: Record<string, string[]>;
  /** Human-readable gaps ("no network telemetry", "alerts only, no raw events"). */
  readonly blind_spots: string[];
}

/**
 * Advanced Security capabilities detected as *in use* (evidence-based), not just
 * available. Lets skills tailor recommendations (e.g. lean on Entity Analytics
 * only when it is actually populated).
 */
export interface Capabilities {
  readonly entity_analytics: boolean;
  readonly attack_discovery: boolean;
  readonly cases: boolean;
  readonly correlation_corpus: boolean;
  /**
   * True when the deployment carries the sample/demo data marker — a signal to
   * treat the profile as a "Showroom", not a real customer environment.
   */
  readonly is_sample_data: boolean;
}

/**
 * Raw degraders (Step 3, flag-only). The intent-vs-efficacy gap that defines a
 * messy environment. Collected and surfaced for a worker to interpret; this
 * iteration deliberately derives no covered/degraded/blind verdict.
 */
export interface CoverageSignals {
  readonly detection_rules?: {
    readonly enabled: number;
    readonly disabled: number;
    readonly with_exceptions: number;
    readonly total_exception_items: number;
  };
  readonly prevention_exceptions?: {
    readonly trusted_apps: number;
    readonly event_filters: number;
    readonly blocklist: number;
  };
  readonly ingest_hygiene?: {
    readonly pipelines_with_drop: string[];
    readonly pipelines_with_sampling: string[];
  };
  readonly retention?: { readonly family: string; readonly earliest_seen?: number }[];
  readonly enrichment?: {
    readonly entity_store_populated: boolean;
    readonly asset_criticality_present: boolean;
  };
}

export type ProtectionCoverage = "prevented" | "detected" | "uncovered";

export interface ApplicabilityVerdict {
  readonly item: string;
  readonly kind: "technique" | "ioc_type" | "tech";
  readonly observable: boolean;
  readonly deployed: boolean;
  readonly protection_coverage: ProtectionCoverage;
  readonly exposure_hint?: "high" | "medium" | "low";
  readonly reason: string;
}

/**
 * Per-consumer slices (Step 4). Binary this iteration; each references the raw
 * `coverage_signals` so a worker can self-limit. Derived confidence /
 * limiting-factors are deferred until after the single-cluster proof.
 */
export interface WorkerContracts {
  readonly hunt?: { readonly indices: string[]; readonly field_map: Record<string, string> };
  readonly emulation?: {
    readonly in_scope_techniques: string[];
    readonly prevent_mode_protections: string[];
  };
  readonly risk?: { readonly technique_weights: Record<string, number> };
  readonly correlation?: { readonly relevance_weights: Record<string, number> };
  readonly response?: { readonly available_actions: string[] };
}

export interface EnvironmentProfile {
  readonly scope: ProfileScope;
  readonly generated_at: string;
  readonly inventory: EnvironmentInventory;
  readonly endpoint_posture: EndpointPosture;
  readonly response_capabilities: ResponseCapabilities;
  readonly terrain: Terrain;
  readonly capabilities: Capabilities;
  // Later phases (undefined until their step runs):
  readonly coverage_signals?: CoverageSignals;
  readonly applicability?: ApplicabilityVerdict[];
  readonly worker_contracts?: WorkerContracts;
  /** Probes that failed so the profile is honest about its own blind spots. */
  readonly collection_errors: string[];
}
