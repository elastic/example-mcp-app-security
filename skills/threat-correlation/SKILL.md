---
name: threat-correlation
description: >
  Correlate a case or incident against the threat-report corpus using the Diamond Model
  of Intrusion Analysis. ALWAYS use this skill when the user asks to correlate an alert,
  case, incident, or report, or when they ask whether an actor, campaign, or intrusion set
  is related to anything seen before. Trigger for: "correlate this", "is this actor/campaign
  related to anything we've seen", "find related threat reports", "diamond correlation",
  "correlate this case", "correlate this incident", "correlate this report", "any matching
  threat intel", "diamond model search", "related actor", "related campaign",
  "is this a known intrusion set", "have we seen this before", "is this attributed",
  "known campaign", "known actor", "match this case to threat intel", "who is behind this",
  "is this attributed to", "have we seen this actor before", "is this a known campaign".
---

# Threat Correlation

Correlate SOC cases and incidents against the threat-report corpus using the `elastic-security`
MCP connector. The authoritative correlation is done by the server-side **`ti-correlation`
Kibana Workflow** (retrieval → Sonnet triage → Opus synthesis, all consistent tradecraft). The
host does NOT synthesize findings itself — it triggers the workflow and renders the result.

## ALWAYS call the tools

When the user asks to correlate a case or find related threat intel — including phrasings
like "is this a known intrusion set", "have we seen this before", "is this attributed",
"known campaign/actor", "match this case to threat intel", "who is behind this" — ALWAYS drive
the correlation through the tools below. Do not answer from memory or describe correlation
results without running the workflow.

## Authoritative path — `correlate` → poll → `render_correlation`

This is the ONE correlation workflow. Use it for every correlation request.

| Step | Situation | Tool call |
|------|-----------|-----------|
| 1 | You have a stored corpus report to correlate, or pasted case text | `correlate` with `report_id` (a report's content_fingerprint) OR `raw_text`. Optionally set `depth` (default `full`), `triage_pool`, `triage_floor`. Returns a `run_id`. |
| 2 | The workflow runs asynchronously in Kibana (full depth can take a few minutes) | `get_correlation_run` with the `run_id`. Poll until `status` is `completed` (while running you get `{ found: false, status: "pending" }` — wait and retry). |
| 3 | The run completed and returned render-ready `findings` | `render_correlation` with the `findings` from step 2. Pure renderer — no reasoning. |

### Step 1 — `correlate`

```
correlate with:
  report_id: "<content_fingerprint>"     # OR raw_text: "<pasted case text>"
  depth: "full"                          # free | cheap | med | full (default full)
```

- Provide EITHER `report_id` OR `raw_text`, never both.
- Only `depth: full` produces a renderable report (Opus synthesis). `free`/`cheap`/`med`
  are cheaper diagnostic tiers that stop before synthesis.
- The tool returns immediately with `{ run_id }`; the workflow does the heavy lifting
  server-side (no host token cost, no 120s host timeout).

### Step 2 — `get_correlation_run`

Poll with the `run_id` until `status` is `completed`:
- `pending` — still executing (or record not yet written). Wait a few seconds and poll again.
- `completed` — `findings` is a render-ready `CorrelationFindings` object (candidate titles
  already resolved to report ids via the run's `picks`). Go to step 3.
- `budget_exceeded` — the case + candidates exceeded the synthesis input budget; no findings.
- `failed` — inspect `error`, `counts`, and `picks`.

For non-`full` depths, `findings` is `null` — report the `counts`/`picks` instead of rendering.

### Step 3 — `render_correlation`

Call with the `findings` returned by `get_correlation_run`. This hands the structured result
to the analyst view. It performs no reasoning and no queries.

## Exploration aids (NOT the correlation path)

`correlation_input_check`, `diamond_search`, `diamond_search_analyst`, and `get_report` let an
analyst browse the corpus by Diamond-vertex similarity or read a report's text. They are
exploration aids — useful for scoping a case or sanity-checking what the corpus holds — but they
do NOT produce authoritative findings. **Host-driven synthesis from these tools is deprecated;
always run `correlate` to correlate a case.**

- `correlation_input_check` — per-vertex signal stoplight (`{ query, signal }` per vertex).
- `diamond_search` — blind corpus search (matched_vertices evidence, no scores).
- `diamond_search_analyst` — scored corpus search (per-vertex scores + coverage) for the triage UI.
- `get_report` — fetch full report text by id (`report_ids`, 1–10).

## Tools

| Tool | When to use | Purpose |
|------|-------------|---------|
| `correlate` | Correlate a case (authoritative) | Trigger the ti-correlation workflow. Params: `report_id` OR `raw_text`, `depth`, `triage_pool`, `triage_floor`. Returns `run_id`. |
| `get_correlation_run` | Poll after `correlate` | Fetch a run by `run_id`; returns status + render-ready `findings`. Param: `run_id`. |
| `render_correlation` | Final step | Render the workflow's findings. Param: `findings` (from `get_correlation_run`). |
| `correlation_input_check` | Exploration | Per-vertex signal stoplight gate. |
| `diamond_search` | Exploration | Blind corpus search — matched_vertices evidence, no scores. |
| `diamond_search_analyst` | Exploration | Scored corpus search — vertex_scores for analyst browse. |
| `get_report` | Exploration | Fetch full report text by id. |
