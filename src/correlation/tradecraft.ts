/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

// VENDORED SNAPSHOT from kibana-threat-intel-poc — canonical source is the Kibana plugin
// (x-pack/.../server/threat_intelligence/services/synthesis_guidance.ts).
// Re-vendor on change. Do not edit here.

// ---------------------------------------------------------------------------
// Diamond Model schema — vertex names + summarisation guidance for the host
// ---------------------------------------------------------------------------

export const DIAMOND_VERTICES = ['adversary', 'capability', 'infrastructure', 'victim'] as const;
export type DiamondVertex = (typeof DIAMOND_VERTICES)[number];

/**
 * Instructions for the host model on how to summarise a case into the four
 * Diamond Model vertices before calling `diamond_search`.
 *
 * Each vertex should be a single free-text paragraph that captures the
 * behavioural signal for that corner.  Omit a vertex (pass undefined or empty
 * string) when there is genuinely no observable signal — never invent content.
 */
export const DIAMOND_SUMMARISATION_GUIDANCE = `\
To drive a Diamond Model correlation search, summarise the case into up to four
vertex paragraphs.  Write each as a self-contained behavioural description that
could stand alone as a search query; do NOT include IOC values (hashes, IPs,
domains) in the paragraphs — those are handled separately via the iocs parameter.

adversary  — Who is operating: threat-actor names, aliases, tracked clusters,
             attributed nation-state or criminal group, operational objectives.
             Omit if unknown.

capability — What tools and techniques are used: malware families, exploited
             CVEs, LOLBIN abuse, C2 frameworks, TTP patterns (MITRE ATT&CK
             technique names are fine).  Focus on WHAT and HOW.

infrastructure — How the operation is staged: hosting patterns, bulletproof
             providers, TLD preferences, certificate quirks, relay/proxy chains,
             legitimate-service abuse.  Focus on the operational-security profile.

victim     — Who is targeted: industry verticals, geographies, organisation
             types, job titles, technology stack (OS, exposed services).

Guidelines:
- One paragraph per vertex, 2–5 sentences.
- Use behavioural language, not atomic artifact lists.
- Omit or leave empty any vertex with no observable signal.
- Do NOT embed IOC values inline — pass them separately as iocs[].`;

// ---------------------------------------------------------------------------
// Triage rubric — the host model uses this to rank candidates returned by
// diamond_search before deciding which to fetch in full via get_report.
// ---------------------------------------------------------------------------

export const TRIAGE_RUBRIC = `\
TRIAGE GUIDANCE

After receiving diamond_search results, triage the candidate stubs in this order:

1. OVERLAP first — prefer candidates that matched on more Diamond Model vertices
   (overlap count, if provided).  Multi-vertex overlap is stronger evidence than
   any single-vertex hit.

2. VERTEX ALIGNMENT — weight matches on the vertices where your case has the
   strongest signal.  A capability match when your case is capability-rich is
   more significant than a victim match when capability is the only evidence.

3. EXCLUDE OBVIOUS MISSES — discard candidates whose titles clearly describe
   unrelated threat clusters (different malware family, different target sector,
   different era) before spending tokens on full-text reads.

4. SELECT FOR DEPTH — call get_report for the top candidates that survive triage
   (typically 3–7).  Prioritise candidates with the highest multi-vertex overlap;
   include at least one lower-overlap candidate as a falsification check.

5. ANCHOR CHECK — if the search also returned anchor (exact IOC / actor) matches,
   treat those as higher-confidence leads regardless of semantic score.

Do NOT anchor on numeric scores if they are not provided — the search is
deliberately score-blind (blind-pack pattern) to avoid over-indexing on any
single similarity metric.`;

// ---------------------------------------------------------------------------
// Synthesis guidance — verbatim from kibana-threat-intel-poc synthesis_guidance.ts
// ---------------------------------------------------------------------------

export const SYNTHESIS_GUIDANCE_TEXT = `\
RELATIONSHIP TAXONOMY

Assess each candidate at one of three levels:

same_campaign — The new case and the candidate describe the same operational activity. They may be observed by different vendors, at different times, or from different vantage points, but the underlying intrusion, tooling deployment, and operational intent are the same.

same_actor — The new case and the candidate are different campaigns operated by the same threat actor or group. The operational activity is distinct, but persistent behavioral patterns tie them to a common operator.

shared_tradecraft — The new case and the candidate share techniques, tooling, or infrastructure patterns, but the overlap may reflect shared toolkits, commodity malware ecosystems, or common operational playbooks rather than a single actor.

CONFIDENCE CALIBRATION

high — Multiple independent behavioral indicators corroborate across at least two Diamond Model vertices. The shared patterns are specific enough that coincidence is unlikely.

moderate — Meaningful overlap exists on at least one vertex with supporting indicators on a second. You must state what additional evidence would elevate this to high confidence.

low — Surface-level similarity exists but the behavioral specificity is insufficient to distinguish this from other actors operating in the same space. You must explain why the similarity is weak.

EVIDENCE WEIGHTS

Each evidence item in \`evidence[]\` receives exactly one weight:

smoking_gun — Decisive, highly discriminating; coincidence implausible. The item alone would materially determine the relationship.
supporting — Corroborating; materially supports but is not alone decisive. Combines with other items to build confidence.
non_discriminatory — Present in both the new case and the candidate but generic; does NOT narrow the candidate set (e.g. "both target Windows", commodity malware, broadly used techniques).
counter — Argues against the proposed relationship; introduces doubt. Requires POSITIVE contradictory evidence (e.g. the same infrastructure role attributed to a different, confirmed actor; conflicting malware families in the same functional role). The absence of overlap, a missing indicator, or "X was not found in the candidate" is a GAP — never a counter or decisive_counter.
decisive_counter — Decisively refutes or rules out the relationship. Same positive-evidence requirement as counter, at a higher threshold.

Each item also names the Diamond Model vertex it belongs to.

JUDGE REASONING GUIDANCE

Weight a coherent multi-vertex attack SHAPE over isolated atomic artifacts — the strongest correlation is usually the cross-vertex pattern, not any single item.

Weight an indicator by its EXCLUSIVITY in real-world malicious use, not merely "tool vs. technique." A generic, independently-reimplemented technique is weak (→ non_discriminatory or counter). A rare, gated, or boutique tool CONFIRMED in-case is strong. An atomic code artifact is a tool-mark: distinctive and corroborating, but narrower than a behavioral-shape match.

VALUE OF INFORMATION: where an UNCONFIRMED indicator would materially change the assessment if confirmed, say so in that lead's \`gaps\` AND add a HIGH-priority next step to verify it.

BEHAVIORAL RULES

1. Evidence-first reasoning. Lead with specific behavioral evidence before stating confidence.
2. Cross-vertex corroboration must be explicit. Populate vertex_signal for all four vertices; use "high" only when specific evidence applies, "partial" for weak or inferred signal, "none" when absent.
3. Articulate the gap. For moderate and low confidence leads, state what evidence is missing.
4. No hallucinated linkage. Work only with the provided source material and candidate reports.
5. Unidirectional output. Produce affirmative matches or no-match statements only.
6. Probability language, not certainty language.
7. Graceful degradation on thin evidence. Never stretch a weak match.
7a. Do not treat absent capabilities as divergent evidence. A capability not mentioned in the candidate does not contradict the new case.
7b. Describe what the case evidence shows, not what happened to it.
8. Distinguish what the new case shows from what candidate reports claim.
8a. Extract and weight author-assessed confidence from candidate reports before reasoning about the relationship.
9. Resolve vendor tracking labels before reasoning. Elastic REF#### = intrusion sets. Mandiant UNC#### = uncategorized clusters. Microsoft weather names = actor groups. CrowdStrike animals = actor designations.
10. Format technical indicators. Wrap IOCs, file paths, commands, domains, package versions, and hashes in backtick code spans in all text fields — including both the lead \`bluf\` and the case-level \`synthesis.bluf\`.
11. Evidence per rated vertex. Every vertex you rate \`partial\` or \`high\` in vertex_signal MUST have at least one evidence item whose \`vertex\` matches it. If you cannot cite evidence for a vertex, rate it \`none\`. (e.g. if you rate infrastructure: partial, there must be an evidence[] item with vertex: infrastructure.)`;

// ---------------------------------------------------------------------------
// Input-signal self-rating guidance — used with correlation_input_check
// ---------------------------------------------------------------------------

/**
 * Instructions for the host model on how to self-rate each vertex's signal
 * quality when calling `correlation_input_check`.
 *
 * Self-ratings mirror the corpus-side `extracted.diamond.*.signal` scale:
 *   HIGH    — specific, well-attested; multiple concrete behavioural details
 *   PARTIAL — present but weak or inferred; one vague indicator or indirect evidence
 *   NONE    — genuinely absent from the case; no observable signal for this vertex
 *
 * The rating is a SELF-ASSESSMENT to help the analyst decide whether the input
 * is ready to search or needs more information. It is NOT a search weight and
 * does NOT affect retrieval — it is advisory context for the analyst gate.
 */
export const INPUT_SIGNAL_GUIDANCE = `\
SELF-RATING YOUR DIAMOND VERTEX SIGNAL

Before running a correlation search, rate each vertex's signal quality using
the same scale as the corpus index:

HIGH    — You have specific, well-attested behavioural details: named malware
          families, attributed threat-actor aliases, confirmed infrastructure
          patterns, concrete target industry/geography.  Multiple corroborating
          observations.  High-confidence search anchor.

PARTIAL — You have some signal but it is weak or inferred: one vague indicator,
          a single technique without context, a suspected (not confirmed) actor.
          The query will be sent but may produce noisier results.

NONE    — Genuinely absent from the case.  Do NOT write a placeholder paragraph.
          Omit this vertex from the query entirely (pass empty string or omit).

RULES:
- Rate only the signal you actually have — do NOT inflate a PARTIAL to HIGH.
- NONE is not a failure; many real cases have strong signal on only 2–3 vertices.
- A PARTIAL vertex is still worth querying; a NONE vertex adds noise, omit it.
- The gate view shows the analyst your self-ratings before the search runs;
  they may ask you to refine weak vertices before proceeding.`;

/**
 * Composite tradecraft bundle returned in every corpus-search response.
 *
 * The summarisation/input/triage guidance help an analyst interpret the
 * EXPLORATION-AID search tools (diamond_search*, get_report).
 *
 * `synthesis_guidance` is DEPRECATED: host-driven synthesis has been replaced by
 * the server-side `ti-correlation` Kibana Workflow (see the `correlate` tool),
 * which owns retrieval → Sonnet triage → Opus synthesis with consistent
 * tradecraft and no 120s host timeout. The block is retained only so any legacy
 * host loop still has the output shape; new flows should NOT synthesize here —
 * call `correlate`, poll `get_correlation_run`, then `render_correlation`.
 */
export const TRADECRAFT = {
  diamond_summarisation_guidance: DIAMOND_SUMMARISATION_GUIDANCE,
  input_signal_guidance: INPUT_SIGNAL_GUIDANCE,
  triage_rubric: TRIAGE_RUBRIC,
  /** @deprecated Use the `correlate` workflow tool instead of host synthesis. */
  synthesis_guidance: {
    deprecated: true,
    deprecation_note:
      "Host-driven synthesis is deprecated. Use the `correlate` tool (ti-correlation workflow) → `get_correlation_run` → `render_correlation`. This block remains only for legacy compatibility.",
    instructions: SYNTHESIS_GUIDANCE_TEXT,
    recommended_output: {
      leads: [
        {
          candidate_ids: ['<report_id>'],
          title: '<report title or cluster label>',
          relationship: 'same_campaign | same_actor | shared_tradecraft',
          confidence: 'high | moderate | low',
          vertex_signal: {
            adversary: 'high | partial | none',
            capability: 'high | partial | none',
            infrastructure: 'high | partial | none',
            victim: 'high | partial | none',
          },
          bluf: '<evidence-first one-sentence narrative — name the specific behavioral evidence first, state relationship second>',
          evidence: [
            {
              vertex: 'capability | infrastructure | adversary | victim',
              weight: 'smoking_gun | supporting | non_discriminatory | counter | decisive_counter',
              text: '<discrete observation — one per entry>',
            },
          ],
          gaps: '<what evidence is missing — required for moderate and low confidence; "none found" valid for high>',
        },
      ],
      no_match: [
        {
          id: '<report_id>',
          title: '<report title>',
        },
      ],
      synthesis: {
        bluf: '<case-level one-liner stating the basis of correlation>',
        correlation_signal: 'high | moderate | low | none',
        reasoning:
          '<overall correlation picture — state signal, name matched vertices, assess indicator overlap>',
        gaps: '<what the primary source material did or did not claim about the relationship>',
        next_steps: [{ priority: 'high | moderate', text: '<actionable investigative step>' }],
      },
    },
  },
} as const;
