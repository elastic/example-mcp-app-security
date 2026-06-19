---
name: threat-correlation
description: >
  Correlate a case or incident against the threat-report corpus using the Diamond Model
  of Intrusion Analysis. ALWAYS use this skill when the user asks to correlate an alert,
  case, incident, or report, or when they ask whether an actor or campaign is related to
  anything seen before. Trigger for: "correlate this", "is this actor/campaign related to
  anything we've seen", "find related threat reports", "diamond correlation", "correlate
  this case", "correlate this incident", "correlate this report", "any matching threat intel",
  "diamond model search", "related actor", "related campaign".
---

# Threat Correlation

Correlate SOC cases and incidents against the threat-report corpus using the `elastic-security`
MCP connector and the Diamond Model of Intrusion Analysis (adversary, capability, infrastructure,
victim).

## ALWAYS call the tool

When the user asks to correlate a case or find related threat intel, ALWAYS start with
`correlation_input_check` to surface the per-vertex signal stoplight. Do not attempt to
answer from memory or describe correlation results without calling the tools.

## Gate: choose a run mode after `correlation_input_check`

After `correlation_input_check` surfaces the per-vertex stoplight, PAUSE and offer the analyst
two run modes. Branch on their reply.

### Mode A — Full run (autonomous, disciplined)

1. Call `diamond_search_analyst` with the confirmed vertex queries.
2. Review the scored candidates yourself using the `triage_rubric` in the response. Pull
   `get_report` for the **top ~10 candidates** ranked by (overlap desc, max_score desc) — cap
   at ~10 to bound token cost.
3. Apply the full `synthesis_guidance` and `triage_rubric` tradecraft from the tool's payload.
4. Call `render_correlation` with the completed `CorrelationFindings`.

Frame honestly: more thorough, full tradecraft and bias-reduction discipline, but **slower
and higher token cost** (synthesis across many reports); results are model-dependent.

### Mode B — Analyst-led (interactive, short-circuitable)

1. Call `diamond_search_analyst` with the confirmed vertex queries.
2. **Present the ranked candidates to the analyst** — show titles, scores, and per-vertex
   match detail from the response.
3. Wait for the analyst to pick which candidates to deep-dive.
4. Call `get_report` for only the analyst-selected `report_ids`.
5. Synthesize findings and call `render_correlation`.

Frame honestly: **faster, cheaper, more interactive** — analyst steers depth and can
short-circuit at any point — but less programmatically disciplined (relies on analyst judgment
rather than a full autonomous triage pass).

### Both modes use the same 5 tools

The only difference is who performs triage: the model (Mode A) or the analyst (Mode B).

---

## Primary path — analyst-led (transparent)

Use this path for interactive human-in-the-loop correlation. It gives the analyst full
visibility into what signal you have before the search runs.

| Step | User says / situation | Tool call |
|------|-----------------------|-----------|
| 1 | Summarise the case into Diamond Model vertices, then show the analyst the signal quality | `correlation_input_check` with `adversary`, `capability`, `infrastructure`, `victim` — each with a `query` paragraph and a `signal` self-rating (HIGH / PARTIAL / NONE) |
| 2 | Analyst confirms signal is ready (or chooses Mode A/B at the gate) | `diamond_search_analyst` with the same vertex queries — presents scored candidates with per-vertex match detail |
| 3 | Analyst selects top candidates from the scored list | `get_report` with the chosen `report_ids` (1–10) |
| 4 | You (the host) synthesize CorrelationFindings from the report text | `render_correlation` with your completed `findings` object |

### Input signal self-rating scale

| Rating | Meaning |
|--------|---------|
| HIGH | Specific, well-attested behavioural detail — strong search anchor |
| PARTIAL | Present but weak or inferred — query sent but may add noise |
| NONE | Genuinely absent — omit this vertex from the search |

### Step 1 — `correlation_input_check`

```
correlation_input_check with:
  adversary:      { query: "APT28 / Fancy Bear; attributed to Russian GRU Unit 26165", signal: "HIGH" }
  capability:     { query: "Zebrocy downloader, Sofacy implant, spear-phishing lures", signal: "HIGH" }
  infrastructure: { query: "dynamic DNS, .ru TLD hosting", signal: "PARTIAL" }
  victim:         { query: "NATO defence contractors, Eastern European governments", signal: "PARTIAL" }
```

The analyst reviews the stoplight and decides whether to proceed or refine the input.

### Step 2 — `diamond_search_analyst`

Pass the same vertex queries (omit NONE-rated vertices). The response includes:
- `candidates`: ScoredStub[] ranked by (overlap desc, max_score desc) with per-vertex match scores
- `coverage`: signal quality summary — `thin: true` signals weak multi-vertex retrieval
- `tradecraft`: triage_rubric and synthesis_guidance for steps 3–4

### Step 3 — `get_report`

Call with the `report_ids` the analyst selected. Returns full `body_text`, `title`, `vendor`, `url`
per report — source material for your synthesis.

### Step 4 — `render_correlation`

After completing your synthesis, call `render_correlation` with your full `CorrelationFindings`
object (`leads`, `no_match`, `synthesis`). This is a pure pass-through to the analyst view —
the tool performs no reasoning.

## Alternate path — blind autonomous (no analyst triage)

Use `diamond_search` + `get_report` when operating autonomously without analyst oversight.
`diamond_search` returns candidate stubs WITHOUT scores (scores are stripped server-side
to preserve independent judgment). Triage candidates yourself using the `triage_rubric`
in the response, then call `get_report` for the top picks and synthesise findings inline
in the conversation (no `render_correlation` required unless you want the rendered UI).

## Tools

| Tool | Purpose |
|------|---------|
| `correlation_input_check` | Per-vertex signal stoplight gate. Params: `adversary`, `capability`, `infrastructure`, `victim` (each: `{ query, signal }`) |
| `diamond_search_analyst` | Scored transparent search. Params: `adversary`, `capability`, `infrastructure`, `victim` (strings), `iocs`, `size` |
| `get_report` | Fetch full report text by ID. Params: `report_ids` (array, 1–10) |
| `render_correlation` | Render host-synthesized findings. Params: `findings` (CorrelationFindings) |
| `diamond_search` | Blind autonomous search — stubs only, no scores. Same vertex + IOC params as `diamond_search_analyst` |
