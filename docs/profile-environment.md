# Profile Environment (IPB/IPOE)

The **Profile Environment** workflow inspects the connected Elastic/Kibana deployment and
produces a typed `EnvironmentProfile` plus an analyst-readable `environment-profile.md` and an
interactive Cursor Canvas (`environment-brief.canvas.tsx`), so other agent skills tailor their
queries and recommendations to what is *actually* deployed instead of assuming a well-instrumented
"Showroom" stack.

It is exposed as a single model-facing MCP tool, `profile-environment`, driven by the
[`profile-environment` skill](../skills/profile-environment/SKILL.md).

## Why

Agent skills (alert triage, threat hunt, query generation, correlation) often assume endpoint
telemetry, common ECS fields, entity analytics, and cloud/network data are all present. Real
customer environments vary widely — endpoint-only, cloud-heavy with sparse host data, custom
index names, missing fields. Without knowing what is in the stack, agents generate queries that
look correct in a demo but return empty or wrong results in production. This workflow gives every
other skill a shared, refreshable picture of the terrain.

## What is inspected

| Section | Signal | Source |
|---------|--------|--------|
| Inventory | Active data streams (volume, recency), installed integrations, cloud providers, OS mix, entity counts, detection-rule inventory | `_data_stream`, `_data_stream/_stats`, `_cat/indices`, Fleet `epm/packages/installed`, ES\|QL, `detection_engine/rules/_find` |
| Endpoint posture | Intended Elastic Defend protection modes (malware/ransomware/memory/behavior) + captured events; third-party EDR presence | Fleet `package_policies` (endpoint), installed packages |
| Response capabilities | Configured SOAR/connectors by domain (endpoint/network/cloud/identity/ticketing/notify) and their actions | Kibana `actions/connectors` |
| Field terrain | Which canonical ECS hunt fields are actually **populated** (not just mapped), population ratio, type conflicts, resolved hunt indices, off-schema indices | ES\|QL `STATS COUNT(field)`, `_field_caps` |
| Off-schema huntable material | For non-ECS / off-schema indices, huntable fields discovered by name/type semantics grouped by observable category (hash, process, ip, domain, intel, …) | `_field_caps` + deterministic classifier |
| Index affordances | Per-index multi-label capabilities — `huntable` / `matchable` / `enrichable` / `pivotable` — with `confidence`, `evidence`, `source`, and a sticky-catalog `signature`. Drives the hunt-target vs. intelligence-source split (`terrain.intel_sources`) and the process-tree tiers. See [Index affordances](#index-affordances-hybrid-classification) | Stage 0 `_meta` harvest + Stage 1 heuristic classifier (+ optional LLM/human confirmation) |
| Process lineage | Per-index process parent/child capability tier (`full` / `parent_only` / `none`) and the concrete join field(s), rolled up into ranked `process_tree_indices.{full,parent_only}` | `_field_caps` + deterministic lineage classifier |
| Hunt indices (ECS + off-schema) | Unified, first-class hunt-target catalog (`terrain.hunt_indices`): every probed hunt index — ECS happy-path `logs-*`/`.alerts*`/`.entities*` **and** off-schema — with huntable fields, lineage, primitives, and join keys, ranked by breadth then volume. ECS is the primary substrate; `high_volume_off_schema` is the off-schema subset | `_field_caps` on ECS + off-schema streams |
| Joinability | Cross-index join fabric (`terrain.joinability.by_key`): for each stable key (`host`/`host_ip`/`user`/`agent`/`process`/`session`/`network`/`cloud`/`container`/`event`) the hunt indices that carry it — the pivots for sequencing, deduplication, matching across primitives, and cueing follow-up hunts. See [Joinability](#joinability) | `_field_caps` + deterministic join-key classifier |
| Hunt-primitive matrix | Per-index supported hunt techniques beyond lineage — `temporal_sequence`, `auth_lateral`, `network_beaconing`, `dns_analytics`, `cloud_identity`, `geo_impossible_travel`, `egress_exfil`, `file_integrity`, `code_signature` — each with the concrete fields a worker builds on, rolled up into `terrain.primitive_matrix`. See [Hunt-primitive matrix](#hunt-primitive-matrix) | `_field_caps` + deterministic primitive classifier |
| Duplicate mirrors | Reindex copies (equal doc volume within a normalized dataset family, e.g. `export-<X>` == `<X>`) collapsed to one canonical; mirrors flagged (`mirror_of`) but kept out of the hunt list/roll-ups. Confirmed-empty streams (real `_count` == 0) dropped entirely | Family normalization + equal-volume mirror detection |
| Coverage gaps | Human-readable blind spots ("no network telemetry", "alerts only, no raw events") | Derived from terrain + inventory |
| Capabilities in use | Entity Analytics, Attack Discovery, Cases, correlation corpus, sample/demo-data marker | Entity counts, `attack_discovery/generations`, `cases/_find`, `ti-reports*` count, sample-data tag |
| Provenance | Cluster binding (`scope`), timestamp, sections that could not be inspected | Bound cluster + per-probe error capture |

## Index affordances (hybrid classification)

Off-schema classification is a **hybrid** pipeline — deterministic heuristics build a
skeleton, an LLM confirms the shape of the uncertain calls, and a human approves; approvals
are persisted so reruns are sticky and deterministic.

Each probed off-schema index gets an `affordances` verdict describing what a worker may do
with it:

| Affordance | Meaning |
|------------|---------|
| `huntable` | A place to hunt — behavioral/observation telemetry or detection alerts. |
| `matchable` | An indicator/IOC list to match telemetry *against* (not a hunt target). |
| `enrichable` | A reputation/enrichment lookup source. |
| `pivotable` | Supports process-tree reconstruction (lineage-capable). |

Alongside the flags each verdict carries `confidence` (`high`/`medium`/`low` — how decisively
structure settled it), `evidence` (the signals behind it), `source`
(`heuristic` → `llm` → `human`), and a stable `signature`.

**Stage 0 — structural harvest.** Index/data-stream `_meta` (`description`/`managed_by`/
`package`) is harvested as a deterministic purpose hint before any model is involved.

**Stage 1 — heuristic classifier.** From name + field structure + `_meta`, the classifier
emits the affordance skeleton with `source: "heuristic"`. It is deliberately conservative:
what it is unsure about is flagged low-confidence for the next stage rather than guessed.

**Stage 2 — LLM confirmation (skill-driven).** The `profile-environment` skill has the agent
confirm/correct the low-confidence verdicts from the index *shape only* (name, `_meta`,
huntable field names, lineage — **no raw document reads**), adding a one-line
`characterization`.

**Stage 3 — human approval.** The markdown **"Classification review"** table (low-confidence
first) and `summary.classification_review.needs_review` present the calls for sign-off.

**Stage 4 — sticky catalog.** Approved verdicts are written back by re-calling
`profile-environment` with `approvals: [...]`, keyed by `signature` (see below). On this and
every future run, any index whose shape matches adopts the approved verdict — with `source:
"human"` — and the hunt/intel/lineage buckets re-flow accordingly.

### Signatures and the catalog

A `signature` is a stable fingerprint of an index's **shape**: its name plus the sorted set of
its huntable field names (volatile facts like doc counts and timestamps are excluded). It is the
catalog key — a sticky verdict re-applies only while the shape is unchanged; adding materially
new fields invalidates the key and re-surfaces the index for review.

The catalog is a JSON file (default `environment-catalog.json`, overridable via
`ENVIRONMENT_CATALOG_FILE` — one per environment for MSSP/MDR). It is read at the start of every
run and written on approval. Reads fail open (a missing/corrupt file is treated as empty), so the
catalog never blocks a profile. **Add it to `.gitignore`** — it describes customer topology.

### Index-role derivation

`role` is a coarse bucket kept alongside affordances for readability. Not every index with
huntable fields is a place to hunt. The profiler classifies each off-schema index
deterministically:

1. **`alerts`** when detection-output fields are present (`kibana.alert.*` / `signal.*`).
2. **`intelligence`** when the name carries an intel token (`indicator`, `ioc`, `threatintel`,
   `reputation`, `cti`, `feed`, `stix`, …) **or** it has threat-intel schema
   (`threat.indicator.*` / `threat.feed` / STIX) with **no owned-asset anchor**
   (`agent.id` / `host.id` / `host.name`) — the tell that it describes external observables
   (IOC feeds, reputation, external scan results) rather than the customer's own hosts.
3. **`telemetry`** when there is an owned-asset anchor and/or event observations.
4. **`reference`** / **`unknown`** otherwise.

Only `telemetry` and `alerts` are hunt targets; `intelligence` is surfaced under
`terrain.intel_sources` as a match-list/enrichment input and excluded from the huntable list
and the process-tree tiers.

### Process-lineage derivation

The lineage tier is derived deterministically from each index's field map (all casings —
ECS `process.parent.*`, Elastic-Endpoint `Events.process.*` / `Target.process.*`, and vendor
variants such as CrowdStrike `ParentCommandLine`):

1. Detect the signals: child id (`process.entity_id`), parent join key
   (`process.parent.entity_id`), ancestry array (`process.Ext.ancestry`), Sessions-View leaders
   (`entry/session/group_leader.entity_id`), `ppid` / `unique_ppid`, parent attributes, parent
   command line.
2. Classify: **`full`** when a child id is present *and* a real join key exists (parent
   entity_id, ancestry array, or session leaders) → arbitrary-depth trees; **`parent_only`**
   when parent attributes/command line/ppid exist but no join key → single-hop pivots only;
   **`none`** otherwise.
3. Roll up into `terrain.process_tree_indices.{full,parent_only}`, ranked by volume within tier,
   and record the concrete `join_fields` a worker should join on.

### Hunt-primitive matrix

Process lineage is one hunt primitive; the profiler generalizes the same field-shape derivation
to the broader set of techniques Elastic ships behavioral/ML detections for (grounded in the
`detection-rules` integration packages — `beaconing`, `lmd`, `pad`, `ded`, `dga`, `okta`/`aws`/
`azure` identity, `fim` — and the tradecraft GenAI-hunter pivots). For each off-schema hunt
target the classifier records the **supported primitives** and the concrete fields a worker would
build on, then rolls them up (mirrors excluded) into `terrain.primitive_matrix`:

| Primitive | Supported when the field shape has… |
|---|---|
| `process_lineage` | lineage capability `full`/`parent_only` (see above) |
| `temporal_sequence` | a time anchor + a join entity (`process.entity_id`/`host.*`/`user.*`/`source.ip`) + event typing (`event.category`/`action`) — the substrate for EQL `sequence by` |
| `auth_lateral` | `source.ip` + a user identity + a host/target and/or an auth-outcome/logon signal (logon failure→success, RDP) |
| `network_beaconing` | a destination (`destination.ip`/`domain`) + bytes/flow, or the shipped `beacon_stats.*` model output |
| `dns_analytics` | `dns.question.name` (DGA / tunneling) |
| `cloud_identity` | `okta.*` / `aws.cloudtrail.user_identity.*` / `azure.signinlogs.*` / `o365.*` / `gcp.audit.*` (session replay, assume-role, MFA, password spray) |
| `geo_impossible_travel` | `source.geo.*`/`as.*` + a user (rare-geo / velocity) |
| `egress_exfil` | byte counters aggregated per user/host |
| `file_integrity` | `file.path`/`file.name` + create/modify/delete typing |
| `code_signature` | `file`/`process.code_signature.*` (unsigned / untrusted binary hunts) |

Each entry carries a `confidence` (high when the discriminating field is present, e.g.
`dns.question.name` or `beacon_stats.*`; medium when inferred from generic combinations) so a
worker can prefer the strongest evidence.

### ECS happy path as first-class

ECS-aligned streams (`logs-*`, `.alerts*`, `.entities*`) are probed with the **same** field-shape
classifier as off-schema indices, so a normal customer deployment gets full per-index huntable
fields, lineage, primitives, and join keys — not just aggregate ECS coverage. The unified
`terrain.hunt_indices` catalog spans both; `high_volume_off_schema` / `huntable_off_schema_indices`
remain as the off-schema subset for the "where is my data hiding" narrative. On a happy-path cluster
the primitive matrix and joinability fabric light up from `logs-endpoint.events.*`,
`logs-system.security`, `logs-okta.*`, `logs-aws.cloudtrail`, `.alerts-security.alerts-*`, etc.

### Joinability

Correlation across indices needs shared keys. For every hunt index the profiler records the stable
keys present (`classifyJoinKeys`), then rolls them up into `terrain.joinability.by_key` — for each
key, all indices that carry it (mutually joinable on that key), ranked by volume:

| Key | Field(s) | Primary use |
|---|---|---|
| `host` | `host.name` / `host.id` / `host.hostname` | match findings across primitives on the same host; cue follow-up hunts |
| `host_ip` | `host.ip` | host resolution / network↔host correlation |
| `user` | `user.name` / `user.id` | identity correlation; cue follow-up hunts |
| `agent` | `agent.id` | sensor-scoped joins / dedup across an agent's streams |
| `process` | `process.entity_id` | **sequencing** and lineage joins |
| `session` | `entry/session/group_leader.entity_id` | Sessions-View sequencing |
| `network` | `source.ip` / `destination.ip` | network pivots (beaconing → endpoint) |
| `cloud` | `cloud.instance.id` / `cloud.account.id` | cloud-resource correlation |
| `container` | `container.id` | container-scoped joins |
| `event` | `event.id` / `kibana.alert.uuid` | **deduplication** / exact-event match |

The four purposes map to keys: **sequencing** → `process`/`session` (+ a time anchor); **dedup** →
`event`; **matching across primitives** and **cueing follow-up hunts** → `host`/`user`/`agent`/
`network`. Presence is derived from `_field_caps` (cheap, deterministic); per-field population on the
ECS happy path is a future enhancement.

### Duplicate mirrors and empty streams

Custom pipelines frequently reindex the same dataset into `export-<X>` / `reindexed-v8-<X>` /
`restored-<X>` copies. Surfacing every copy pollutes the hunt list and double-counts. The profiler:

1. Normalizes each index name to a **family** key (strip transform prefixes and date/generation/
   version suffixes), so raw/cleaned/export variants group together.
2. Within a family, treats members with an **identical nonzero doc volume** as reindex mirrors of
   one canonical (preferring the un-prefixed / shortest name). Mirrors get `mirror_of` set and are
   excluded from `huntable_off_schema_indices`, the primitive matrix, and the lineage tiers — but
   stay in the review (`classified_indices`) for transparency. Different-volume members of a family
   (raw vs. cleaned stages, sampled exports) stay independent.
3. Drops **confirmed-empty** streams (a real `_count` returns 0) from the hunt list and the review —
   distinct from an unreportable frozen tier (count throws → left as-is and still surfaced).

## Scope and multi-cluster

Every profile carries an addressable `scope` (`level` + `ref` + stable `scope_id`) so a leaf
profile can later roll up into an overarching MSSP/MDR portfolio view. The current tool profiles
one connected cluster (the default `deployment` scope); pass `space` or `indexPattern` to narrow
it. Portfolio aggregation across workspaces is future work (see issue #22 for multi-cluster).

## How to refresh

Re-run the `profile-environment` tool and overwrite `environment-profile.md` (and the
`environment-brief.canvas.tsx` canvas). The canvas is a fully static, pre-rendered artifact — all
findings are baked into it by the profiler, so it is regenerated on each run rather than edited by
hand. Refresh:

- on demand, whenever the environment may have changed;
- when the saved profile's cluster (`scope.ref.deployment`) does not match the active MCP cluster;
- before a hunting/detection session if the profile is more than a few days old.

There is no continuous monitoring — the profile is a point-in-time snapshot.

## Resilience

Every probe is isolated. A permission error or timeout degrades only that section (recorded under
`collection_errors` / the "Not inspected" heading) rather than failing the whole profile. Treat
the profile as **evidence, not ground truth**: a field mapped but 3% populated, or a rule that is
enabled but heavily exception'd, will still mislead a worker that trusts intent over efficacy.

## Known limitations

- Field terrain probes a curated set of canonical hunt fields over a 30-day window, not every
  mapped field.
- Third-party EDR is reported as presence + telemetry only; per-protection modes are available for
  Elastic Defend only.
- Advanced-capability detection is evidence-based (in use), not a features-API capability listing.
- Doc counts per data stream are best-effort (summed from backing indices).

## Sensitive data

`environment-profile.md`, the generated canvas (`environment-brief.canvas.tsx`), and the
classification catalog (`environment-catalog.json`) describe customer topology (indices,
integrations, security tooling). Treat them as sensitive: **add all three to `.gitignore`** in
analyst workspaces and do not commit real-customer profiles, canvases, or catalogs to shared
repositories.

## Consuming the profile in other skills

Other skills should read `environment-profile.md` from the workspace root (or re-call the tool)
and prefer indices in `terrain.resolved_hunt_indices` and fields with a non-trivial
`population_ratio`, while avoiding anything under `terrain.blind_spots`. If no profile exists, run
the `profile-environment` skill first.
