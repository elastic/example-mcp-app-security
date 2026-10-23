---
name: profile-environment
description: >
  Inspect the connected Elastic/Kibana stack and produce an environment profile so other
  skills can tailor queries and recommendations to what is actually deployed. Use before
  hunting, writing detections, correlating, or emulating in an unfamiliar deployment, and
  whenever queries return empty or look wrong for the environment. Trigger for: "profile
  the environment", "profile this stack", "what data do we have", "what's in this cluster",
  "map the environment", "what telemetry exists", "coverage gaps", "is this the demo data",
  "prepare the environment", "environment profile", "IPB", "what integrations are installed".
---

# Profile Environment (IPB/IPOE)

Build a context profile of the connected deployment using the `elastic-security` MCP connector,
save it to the workspace, and let other skills read it instead of assuming a well-instrumented
"Showroom" stack. The heavy inspection is done server-side by the `profile-environment` tool;
this skill drives the review-and-save workflow around it.

## Workflow

The profiler is a **hybrid** pipeline: deterministic heuristics build the skeleton, you
(the LLM) confirm the shape of the uncertain calls, a human approves, and approvals are
persisted so reruns are sticky and deterministic.

| Step | Action |
|------|--------|
| 1 | Call `profile-environment`. Optionally pass `space` or `indexPattern` to scope it; default is the whole deployment. |
| 2 | Save the returned `markdown` field verbatim to `environment-profile.md` at the workspace root, and the `canvas` field verbatim to the workspace canvases directory as `environment-brief.canvas.tsx` (see below). |
| 3 | **Classification review** — confirm/correct the low-confidence index classifications (see below). |
| 4 | Show the analyst the summary (data sources, gaps, capabilities, sample-data flag) plus your proposed corrections, and ask them to approve/edit. |
| 5 | Persist the approved verdicts by re-calling `profile-environment` with `approvals: [...]`. This writes the catalog and returns a refreshed profile; **re-save it** to `environment-profile.md`. |
| 6 | Other skills read `environment-profile.md` (or re-call the tool) to ground their queries. |

### Step 1 — `profile-environment`

```
profile-environment
  level: "deployment"     # optional: fleet | deployment | space | datastream
  space: "<space-id>"     # optional: scope to one Kibana space / tenant
  indexPattern: "logs-*"  # optional: scope to one feed
```

The tool returns `{ summary, markdown, canvas, profile }`:
- `summary` — compact digest for quick reasoning.
- `markdown` — the analyst-readable report; **save this to `environment-profile.md`**.
- `canvas` — a self-contained Cursor Canvas (`.canvas.tsx`) rendering of the same findings; **save this to the workspace canvases directory**.
- `profile` — the full typed `EnvironmentProfile` (also embedded in the markdown as JSON).

### Step 2 — save to the workspace

Write the `markdown` field to `environment-profile.md` at the workspace root. This is the
documented, consistent location other skills look for. Re-running the tool refreshes it.

Also write the `canvas` field verbatim to the workspace canvases directory as
`environment-brief.canvas.tsx` — the exact path is
`/Users/<user>/.cursor/projects/<workspace>/canvases/environment-brief.canvas.tsx`
(the IDE only detects canvases written directly in that directory). It is a fully
static, pre-rendered artifact: the profiler bakes all findings into it, so **do not
edit it by hand** — regenerate by re-running the tool. Tell the analyst they can open
it beside the chat, linking the file path. If the canvases directory can't be
resolved for this workspace, fall back to saving it at the workspace root.

### Step 3 — classification review (heuristic → LLM confirmation)

Each off-schema index carries a heuristic **affordance** verdict — what a worker may do with
it: `huntable` (a place to hunt), `matchable` (an IOC/indicator list to match telemetry
*against*), `enrichable` (reputation/enrichment lookups), `pivotable` (process-tree capable) —
plus a `confidence`, `evidence`, `source`, and a stable `signature`.

Read `summary.classification_review`:
- `needs_review` lists every index the heuristic is **not** sure about (`confidence` ≠ `high`).
- The markdown **"Classification review"** table shows the same, low-confidence first.

For each `needs_review` entry, confirm or correct the verdict from the index's **shape only**
— its `name`, `meta_description`, `huntable_fields` categories/field names, and `lineage` in
`profile.terrain.classified_indices[]`. **Do not query or read raw documents**; names and
mappings are enough. Typical corrections:
- an IOC feed / reputation list mis-marked `huntable` → set `huntable: false, matchable: true`;
- an EDR/behavior corpus mis-marked as intel → set `huntable: true`;
- add a one-line `characterization` of what the index actually is.

Keep the heuristic verdict when the evidence agrees. Only change what the shape contradicts,
and record why in `evidence` (or `note`).

### Step 4 — analyst review

Surface the highlights and your proposed corrections; let the analyst approve or edit. Call out:
- the **cluster** the profile was built against (`scope.ref.deployment`),
- your **proposed classification corrections** (Step 3),
- any **coverage gaps** (`terrain.blind_spots`, e.g. "no network telemetry"),
- anything under **Not inspected** (`collection_errors`) — permissions/timeouts,
- whether this is **sample/demo data** (`capabilities.is_sample_data`).

### Step 5 — persist approvals (sticky catalog)

Once the analyst approves, re-call the tool with the confirmed verdicts:

```
profile-environment
  approvals:
    - name: "ia-loupe-indicators"
      signature: "<from classified_indices[].signature>"
      affordances:
        huntable: false
        matchable: true
        enrichable: false
        pivotable: false
        confidence: "high"
        evidence: ["analyst: curated IOC feed, match-only"]
        source: "human"
      note: "Threat-intel indicator list, not a hunt target."
```

Approvals are keyed by `signature` (index name + field shape). On this and every future run,
any index whose shape matches adopts the approved verdict — until its shape materially changes,
which re-surfaces it for review. Re-save the refreshed `markdown` to `environment-profile.md`.

## What the profile captures

- **Data sources** — active data streams with rough volume and recency.
- **Integrations & deployed tech** — installed integrations, cloud providers, OS mix, entity counts, rule inventory.
- **Endpoint posture** — intended Elastic Defend protection modes; third-party EDR presence.
- **Response capabilities** — configured SOAR/connectors by domain (endpoint/network/cloud/identity/ticketing/notify).
- **Field terrain** — which canonical ECS fields are actually **populated** (not just mapped), with type-conflict flags.
- **Off-schema classification** — per-index affordances (huntable/matchable/enrichable/pivotable) with confidence, evidence, and a sticky-catalog signature; hunt targets vs. intelligence/enrichment sources; process-lineage tiers.
- **Hunt indices (ECS + off-schema)** — `terrain.hunt_indices` is the unified, first-class hunt-target catalog. ECS happy-path streams (`logs-*`/`.alerts*`/`.entities*`) are probed the same way as off-schema, so a normal deployment gets full per-index primitives, lineage, and join keys. Prefer ECS indices; off-schema is the fallback.
- **Hunt-primitive matrix** — which hunt techniques the environment supports beyond lineage (temporal_sequence, auth_lateral, network_beaconing, dns_analytics, cloud_identity, geo_impossible_travel, egress_exfil, file_integrity, code_signature), each with the concrete fields to build on. Pick indices from `primitive_matrix[<primitive>]` for the technique a worker needs.
- **Joinability** — `terrain.joinability.by_key` maps each stable key (host/user/agent/process/session/network/cloud/container/event) to the indices carrying it. Use it to sequence (`process`/`session`), deduplicate (`event`), match findings across primitives, and cue follow-up hunts (`host`/`user`/`agent`/`network`).
- **Duplicate mirrors collapsed** — reindex copies (equal doc volume within a dataset family, e.g. `export-<X>` == `<X>`) are flagged `mirror_of` and excluded from the hunt list; confirmed-empty streams are dropped. Hunt the canonical, not the mirror.
- **Coverage gaps** — human-readable blind spots.
- **Advanced capabilities in use** — Entity Analytics, Attack Discovery, Cases, correlation corpus, sample-data marker.
- **Cluster binding + timestamp + not-inspected sections.**

## How other skills should use it

- Before hunting or writing detections, read `environment-profile.md`. Prefer indices in
  `terrain.resolved_hunt_indices` and fields with a non-trivial `population_ratio`; avoid fields
  listed in `terrain.blind_spots`.
- If no profile exists, run this skill first.
- If the profile's cluster (`scope.ref.deployment`) does not match the active MCP cluster,
  re-run `profile-environment` — the saved profile is stale for this connection.

## Sensitive data

The profile describes customer topology (indices, integrations, tooling). Treat
`environment-profile.md` and the generated `environment-brief.canvas.tsx` as sensitive
and **add them to `.gitignore`** in analyst workspaces. Do not commit real-customer
profiles to shared repos.

## Tools (via elastic-security MCP connector)

| Tool | Purpose |
|------|---------|
| `profile-environment` | Inspect the stack and return `{ summary, markdown, canvas, profile }`. Params: `level`, `space`, `indexPattern`, `approvals` (all optional). Pass `approvals` to persist confirmed classifications to the sticky catalog. |
| `list-indices` / `get-mapping` | Lower-level index/field inspection for follow-up drill-down. |
| `check-existing-sample-data` | Confirm whether demo data is present. |
