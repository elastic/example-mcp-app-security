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

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import type { CorrelationService } from "../elastic/service/correlationService.js";
import { TRADECRAFT } from "../correlation/tradecraft.js";
import { registerTrackedAppTool } from "./tracked-app-tool.js";
import { resolveViewPath } from "./view-path.js";
import { emitCorrelationCanvas, canvasDirFromEnv } from "../canvas/correlation-canvas.js";

const CORRELATION_RESOURCE_URI = "ui://correlation/mcp-app.html";
const CORRELATION_INPUT_RESOURCE_URI = "ui://correlation-input/mcp-app.html";

export interface CorrelationToolDeps {
  readonly correlationService: CorrelationService;
  readonly analytics: AnalyticsClient;
}

// Map the ti-correlation workflow's CorrelationFindings (leads keyed by exact
// candidate TITLE) into the shape render_correlation expects (leads keyed by
// candidate_ids). The run record's picks[] carry the title→fingerprint bridge.
//
// A title that does not resolve to a pick fingerprint is a LOUD miss: it is
// collected in `unresolved` (so get_correlation_run can warn + surface it) and
// its candidate_id falls back to the raw title string so the report still
// renders. Returns findings=null when there is nothing to render (non-full
// depth, or synthesis absent/failed). Exported for the smoke test + unit tests.
export interface RenderShapeResult {
  findings: Record<string, unknown> | null;
  /** Titles the synthesis referenced that no pick fingerprint matched. */
  unresolved: Array<{ where: "lead" | "no_match"; index: number; title: string }>;
}

/** Run-level context folded into the render-shape findings (the App view only
 *  receives `findings`, so counts/trace/run metadata ride along inside it). */
export interface RenderShapeMeta {
  trace?: Record<string, unknown>;
  counts?: Record<string, number>;
  run?: { run_id?: string; depth?: string; status?: string };
  /** Case anchors the workflow searched (case.anchors on the run record). */
  caseAnchors?: {
    hashes?: string[];
    network?: string[];
    artifacts?: string[];
    techniques?: string[];
    /** Distinctive code/execution tokens searched as exact phrase anchors. */
    code_tokens?: string[];
  };
  /** Per-vertex signal of the case under analysis (case.vertex_signal on the
   *  run record; NONE/PARTIAL/HIGH). Drives the "Case signal" diamond. */
  caseVertexSignal?: Record<string, string>;
  /** Fused-pool candidates (run.candidates) — used to build the anchor trail. */
  pool?: Array<{
    id: string;
    has_anchor?: boolean;
    anchor_score?: number;
    has_phrase_anchor?: boolean;
    phrase_score?: number;
    overlap?: number;
  }>;
}

/** One row of the anchor trail: an anchor-matched corpus report and its fate
 *  through triage → synthesis. */
export interface AnchorTrailEntry {
  fp: string;
  anchor_score: number;
  overlap: number;
  /** Present when triage picked this candidate (title/vendor/url come from picks). */
  title?: string;
  vendor?: string;
  url?: string;
  triage_confidence?: number;
  justification?: string;
  /** Terminal fate. */
  outcome: "lead" | "picked_no_lead" | "dropped_at_triage";
  lead_title?: string;
  relationship?: string;
  lead_confidence?: string;
}

export function workflowFindingsToRenderShape(
  findings: Record<string, unknown> | undefined,
  picks: Array<{ fp: string; title?: string; vendor?: string; url?: string }> | undefined,
  meta?: RenderShapeMeta
): RenderShapeResult {
  if (!findings || typeof findings !== "object") return { findings: null, unresolved: [] };
  const synthesis = (findings as { synthesis?: unknown }).synthesis;
  if (!synthesis || typeof synthesis !== "object") return { findings: null, unresolved: [] };

  // Normalize titles before the join: the synthesis LLM commonly re-emits a
  // candidate title with straight ASCII quotes where the stored pick title has
  // typographic ones (’ “ ” …), which breaks a raw string match. Fold quotes,
  // collapse whitespace, and lowercase so those match; genuine rewordings still
  // fall back to the title string (and are reported as unresolved).
  const normalizeTitle = (t: string): string =>
    t
      .normalize("NFKC")
      .replace(/[\u2018\u2019\u02BC\u2032]/g, "'")
      .replace(/[\u201C\u201D\u2033]/g, '"')
      .replace(/[\u2010-\u2015]/g, "-")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();

  const titleToFp = new Map<string, string>();
  const candidateMeta: Record<string, { title?: string; vendor?: string; url?: string }> = {};
  for (const p of picks ?? []) {
    if (p.title && p.fp) {
      titleToFp.set(normalizeTitle(p.title), p.fp);
      // vendor/url come from the workflow pick (source.name / source.url); omit
      // empties so the view's source chips only light up when we actually have a
      // link. This is what populates candidate_meta[id].{vendor,url} in App.tsx.
      candidateMeta[p.fp] = {
        title: p.title,
        ...(p.vendor ? { vendor: p.vendor } : {}),
        ...(p.url ? { url: p.url } : {}),
      };
    }
  }
  const unresolved: RenderShapeResult["unresolved"] = [];
  // Resolve a title to a pick fp; record a loud miss when it does not join.
  const resolve = (title: string, where: "lead" | "no_match", index: number): string => {
    const fp = titleToFp.get(normalizeTitle(title));
    if (fp) return fp;
    unresolved.push({ where, index, title });
    return title;
  };

  const rawLeads = Array.isArray((findings as { leads?: unknown }).leads)
    ? ((findings as { leads: Array<Record<string, unknown>> }).leads)
    : [];
  const leads = rawLeads.map((lead, i) => {
    const titles = Array.isArray(lead.candidate_titles)
      ? (lead.candidate_titles as string[])
      : [];
    const { candidate_titles: _drop, ...rest } = lead;
    return {
      ...rest,
      candidate_ids: titles.map((t) => resolve(t, "lead", i)),
      consolidated_candidates: Array.isArray(lead.consolidated_candidates)
        ? lead.consolidated_candidates
        : [],
    };
  });

  const rawNoMatch = Array.isArray((findings as { no_match?: unknown }).no_match)
    ? ((findings as { no_match: Array<Record<string, unknown>> }).no_match)
    : [];
  const no_match = rawNoMatch.map((nm, i) => {
    const title = typeof nm.title === "string" ? nm.title : "";
    return { id: resolve(title, "no_match", i), title };
  });

  // --- Anchor trail: searched → matched → triage → synthesis --------------
  // Traces each exact-anchor-matched corpus report from retrieval through its
  // terminal fate. leads[].candidate_ids are already resolved to fps above, so
  // we can map fp → its lead; picks give the triage confidence/justification.
  const fpToLead = new Map<string, { lead_title?: string; relationship?: string; lead_confidence?: string }>();
  for (const lead of leads) {
    const ids = Array.isArray((lead as { candidate_ids?: unknown }).candidate_ids)
      ? ((lead as { candidate_ids: string[] }).candidate_ids)
      : [];
    for (const fp of ids) {
      if (!fpToLead.has(fp)) {
        fpToLead.set(fp, {
          lead_title: (lead as { title?: string }).title,
          relationship: (lead as { relationship?: string }).relationship,
          lead_confidence: (lead as { confidence?: string }).confidence,
        });
      }
    }
  }
  const pickByFp = new Map<string, { title?: string; vendor?: string; url?: string; confidence?: number; justification?: string }>();
  for (const p of picks ?? []) {
    const pp = p as { fp: string; title?: string; vendor?: string; url?: string; confidence?: number; justification?: string };
    if (pp.fp) pickByFp.set(pp.fp, pp);
  }
  const anchorHits = (meta?.pool ?? []).filter((c) => c.has_anchor);
  const anchor_trail: AnchorTrailEntry[] = anchorHits
    .map((c) => {
      const pick = pickByFp.get(c.id);
      const lead = fpToLead.get(c.id);
      const outcome: AnchorTrailEntry["outcome"] = lead
        ? "lead"
        : pick
          ? "picked_no_lead"
          : "dropped_at_triage";
      return {
        fp: c.id,
        anchor_score: c.anchor_score ?? 0,
        overlap: c.overlap ?? 0,
        ...(pick?.title ? { title: pick.title } : {}),
        ...(pick?.vendor ? { vendor: pick.vendor } : {}),
        ...(pick?.url ? { url: pick.url } : {}),
        ...(pick?.confidence != null ? { triage_confidence: pick.confidence } : {}),
        ...(pick?.justification ? { justification: pick.justification } : {}),
        outcome,
        ...(lead?.lead_title ? { lead_title: lead.lead_title } : {}),
        ...(lead?.relationship ? { relationship: lead.relationship } : {}),
        ...(lead?.lead_confidence ? { lead_confidence: lead.lead_confidence } : {}),
      };
    })
    // lead first, then picked-no-lead, then dropped; higher anchor_score first.
    .sort((a, b) => {
      const rank = { lead: 0, picked_no_lead: 1, dropped_at_triage: 2 } as const;
      return rank[a.outcome] - rank[b.outcome] || b.anchor_score - a.anchor_score;
    });

  // Phrase-anchor trail: same join, but for candidates that shared a distinctive
  // code/execution token (extracted.code_tokens) with the case. Tracked as its own
  // group so the debug accordion can surface code-token "smoking guns" separately
  // from IOC/artifact anchors. anchor_score carries the phrase-match score.
  const phraseHits = (meta?.pool ?? []).filter((c) => c.has_phrase_anchor);
  const phrase_anchor_trail: AnchorTrailEntry[] = phraseHits
    .map((c) => {
      const pick = pickByFp.get(c.id);
      const lead = fpToLead.get(c.id);
      const outcome: AnchorTrailEntry["outcome"] = lead
        ? "lead"
        : pick
          ? "picked_no_lead"
          : "dropped_at_triage";
      return {
        fp: c.id,
        anchor_score: c.phrase_score ?? 0,
        overlap: c.overlap ?? 0,
        ...(pick?.title ? { title: pick.title } : {}),
        ...(pick?.vendor ? { vendor: pick.vendor } : {}),
        ...(pick?.url ? { url: pick.url } : {}),
        ...(pick?.confidence != null ? { triage_confidence: pick.confidence } : {}),
        ...(pick?.justification ? { justification: pick.justification } : {}),
        outcome,
        ...(lead?.lead_title ? { lead_title: lead.lead_title } : {}),
        ...(lead?.relationship ? { relationship: lead.relationship } : {}),
        ...(lead?.lead_confidence ? { lead_confidence: lead.lead_confidence } : {}),
      };
    })
    .sort((a, b) => {
      const rank = { lead: 0, picked_no_lead: 1, dropped_at_triage: 2 } as const;
      return rank[a.outcome] - rank[b.outcome] || b.anchor_score - a.anchor_score;
    });

  const ca = meta?.caseAnchors;
  const anchors_searched = ca
    ? {
        hashes: ca.hashes ?? [],
        network: ca.network ?? [],
        artifacts: ca.artifacts ?? [],
        techniques: ca.techniques ?? [],
        code_tokens: ca.code_tokens ?? [],
      }
    : undefined;

  // Case-signal diamond: the workflow persists the case's own per-vertex signal
  // (case.vertex_signal, NONE/PARTIAL/HIGH) but does not put it inside findings.
  // Fold it in (lowercased to match lead vertex_signal) unless synthesis already
  // supplied one; skip when every vertex is NONE so the view can hide an empty
  // diamond instead of drawing an all-grey one.
  const existingCaseSignal = (findings as { case_vertex_signal?: Record<string, string> })
    .case_vertex_signal;
  const cvsIn = meta?.caseVertexSignal;
  const derivedCaseSignal =
    !existingCaseSignal && cvsIn
      ? (() => {
          const lowered: Record<string, string> = {};
          let anySignal = false;
          for (const [k, v] of Object.entries(cvsIn)) {
            const lv = String(v ?? "").toLowerCase();
            lowered[k] = lv;
            if (lv && lv !== "none") anySignal = true;
          }
          return anySignal ? lowered : undefined;
        })()
      : undefined;

  return {
    findings: {
      ...findings,
      leads,
      no_match,
      candidate_meta: {
        ...candidateMeta,
        ...((findings as { candidate_meta?: Record<string, unknown> }).candidate_meta ?? {}),
      },
      // Fold run-level context into findings so the view (which only receives
      // `findings`) can render counts + the Pipeline & cost panel. Omitted when
      // not provided so existing callers/tests are unaffected.
      ...(meta?.counts ? { counts: meta.counts } : {}),
      ...(meta?.trace ? { trace: meta.trace } : {}),
      ...(meta?.run ? { run_meta: meta.run } : {}),
      ...(derivedCaseSignal ? { case_vertex_signal: derivedCaseSignal } : {}),
      ...(anchors_searched ? { anchors_searched } : {}),
      ...(anchor_trail.length > 0 ? { anchor_trail } : {}),
      ...(phrase_anchor_trail.length > 0 ? { phrase_anchor_trail } : {}),
    },
    unresolved,
  };
}

/**
 * Register the threat-report correlation tools.
 *
 * AUTHORITATIVE PATH (workflow-driven — use this to correlate a case):
 *   1. `correlate` → trigger the `ti-correlation` Kibana Workflow (retrieval →
 *      Sonnet triage → Opus synthesis, all server-side). Returns a run_id.
 *   2. `get_correlation_run` → poll by run_id until status is "completed";
 *      returns render-ready CorrelationFindings (candidate titles resolved to
 *      report ids via the run's picks[]).
 *   3. `render_correlation` → hand those findings to the analyst view.
 *
 * EXPLORATION AIDS (analyst-driven, NOT the correlation path):
 *   `diamond_search` / `diamond_search_analyst` / `get_report` let an analyst
 *   browse the corpus by Diamond-vertex similarity or pull a report's text.
 *   They do NOT synthesize — host-driven synthesis is deprecated in favour of
 *   the workflow above (consistent tradecraft + no 120s host timeout).
 */
export function registerCorrelationTools(
  server: McpServer,
  deps: CorrelationToolDeps
): void {
  const { correlationService, analytics } = deps;

  // -------------------------------------------------------------------------
  // correlate — AUTHORITATIVE path: trigger the ti-correlation Kibana Workflow
  // -------------------------------------------------------------------------

  registerTrackedAppTool(
    analytics,
    server,
    "correlate",
    {
      title: "Correlate Threat Report (Workflow)",
      description: `Correlate a case against the report corpus using the server-side ti-correlation Kibana Workflow. This is the AUTHORITATIVE correlation path — the workflow runs retrieval (anchor + diamond kNN + BM25), Sonnet triage, and Opus synthesis with consistent tradecraft. Do NOT hand-synthesize findings from diamond_search/get_report; those are analyst exploration aids only.

Provide EITHER report_id (a stored corpus report's content_fingerprint) OR raw_text (pasted case text) — not both.

This tool triggers the run ASYNCHRONOUSLY and returns a run_id immediately. The workflow executes in Kibana Task Manager; full-depth synthesis can take a few minutes. Poll get_correlation_run with the returned run_id until status is "completed" (or "budget_exceeded"/"failed"), then call render_correlation with the returned findings.

DEPTH TIERS (each adds cost on top of the previous):
  free  — exact anchor match + behavioral/BM25 retrieval only (no LLM)
  cheap — + per-vertex diamond kNN (no LLM)
  med   — + Sonnet triage over the fused candidate pool
  full  — + Opus synthesis into CorrelationFindings (default; the only depth that yields a renderable report)`,
      _meta: { ui: {} },
      inputSchema: {
        report_id: z
          .string()
          .optional()
          .describe(
            "Stored corpus report _id (content_fingerprint) to correlate. Mutually exclusive with raw_text."
          ),
        raw_text: z
          .string()
          .optional()
          .describe(
            "Pasted case text to correlate. Mutually exclusive with report_id."
          ),
        depth: z
          .enum(["free", "cheap", "med", "full"])
          .optional()
          .describe(
            "How far to run: free/cheap (retrieval only), med (+triage), full (+synthesis; default). Only full yields a renderable report."
          ),
        triage_pool: z
          .number()
          .int()
          .min(1)
          .max(500)
          .optional()
          .describe("Max fused candidates presented to triage (default 120)."),
        triage_floor: z
          .number()
          .min(0)
          .max(1)
          .optional()
          .describe("Triage confidence floor 0..1 — picks below this are dropped (default 0.65)."),
      },
    },
    async ({ report_id, raw_text, depth, triage_pool, triage_floor }) => {
      const result = await correlationService.runCorrelation({
        report_id,
        raw_text,
        depth,
        triage_pool,
        triage_floor,
      });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              kind: "correlation_run_started",
              run_id: result.run_id,
              workflow_id: result.workflow_id,
              depth: result.depth,
              summary: `Correlation run ${result.run_id} started (depth: ${result.depth}). Poll get_correlation_run until status is "completed".`,
            }),
          },
        ],
      };
    }
  );

  // -------------------------------------------------------------------------
  // get_correlation_run — poll a run by run_id; return render-ready findings
  // -------------------------------------------------------------------------

  registerTrackedAppTool(
    analytics,
    server,
    "get_correlation_run",
    {
      title: "Get Correlation Run",
      description: `Fetch a correlation run record by run_id (returned by correlate) from the correlations index.

Poll this until status is "completed". While the workflow is still running the record does not exist yet — you'll get { found: false, status: "pending" }; wait and retry.

On completion the response includes render-ready \`findings\` (a CorrelationFindings object with candidate titles already resolved to report ids via the run's picks). When findings is present, pass it straight to render_correlation. For non-full depths (free/cheap/med) there is no synthesized report, so findings is null — inspect counts/picks instead.

Statuses: "pending" (still running / not yet persisted), "completed" (synthesis done), "budget_exceeded" (input too large — no synthesis), "failed".`,
      _meta: { ui: {} },
      inputSchema: {
        run_id: z
          .string()
          .describe("The run_id (workflow execution id) returned by correlate."),
      },
    },
    async ({ run_id }) => {
      const record = await correlationService.getCorrelationRun(run_id);
      if (!record.found) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                kind: "correlation_run",
                run_id,
                found: false,
                status: "pending",
                summary: `Run ${run_id} not persisted yet — still executing. Wait and poll again.`,
              }),
            },
          ],
        };
      }

      const status = record.status ?? "completed";
      const rid = record.run_id ?? run_id;
      const { findings, unresolved } = workflowFindingsToRenderShape(
        record.findings,
        record.picks,
        {
          trace: record.trace,
          counts: record.counts,
          run: { run_id: rid, depth: record.depth, status },
          caseAnchors: record.case?.anchors,
          caseVertexSignal: record.case?.vertex_signal as Record<string, string> | undefined,
          pool: record.candidates,
        }
      );
      const leadsCount = Array.isArray((findings as { leads?: unknown[] } | null)?.leads)
        ? (findings as { leads: unknown[] }).leads.length
        : 0;

      // LOUD miss: a synthesis title that no pick fingerprint matched. The report
      // still renders (candidate_id falls back to the title), but the id won't
      // join to a report — so warn on the server and surface it in the response
      // rather than letting it pass silently.
      if (unresolved.length > 0) {
        const detail = unresolved
          .map((u) => `${u.where}[${u.index}] "${u.title}"`)
          .join("; ");
        console.warn(
          `[correlation] run ${rid}: ${unresolved.length} candidate title(s) did not resolve to a report id (fell back to the title string): ${detail}`
        );
      }

      // Opt-in Cursor canvas: when CORRELATION_CANVAS_DIR is set, stamp these
      // render-shape findings into the paint-by-numbers template so Cursor gets
      // a native side-panel report (its MCP app views only render inline). This
      // is best-effort — a canvas write failure must not fail the poll.
      let canvasPath: string | undefined;
      if (findings && canvasDirFromEnv()) {
        try {
          const emitted = emitCorrelationCanvas({
            findings,
            runId: rid,
            caseTitle: record.case?.title,
          });
          if (emitted) {
            canvasPath = emitted.file;
            console.error(`[correlation] run ${rid}: wrote Cursor canvas ${emitted.file}`);
          }
        } catch (err) {
          console.warn(
            `[correlation] run ${rid}: canvas emit failed: ${String(
              (err as Error)?.message ?? err
            )}`
          );
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              kind: "correlation_run",
              run_id: rid,
              found: true,
              status,
              depth: record.depth,
              counts: record.counts,
              picks: record.picks,
              trace: record.trace,
              error: record.error,
              findings,
              unresolved_candidate_titles: unresolved,
              ...(canvasPath ? { canvas_path: canvasPath } : {}),
              summary: findings
                ? `Run ${rid} ${status} — ${leadsCount} lead(s)${
                    unresolved.length > 0
                      ? `; WARNING: ${unresolved.length} candidate title(s) did not resolve to a report id (see unresolved_candidate_titles)`
                      : ""
                  }.${canvasPath ? ` Cursor canvas written to ${canvasPath} — open it for the side-panel report.` : ""} Pass findings to render_correlation.`
                : `Run ${rid} ${status} — no synthesized report (depth ${record.depth ?? "?"}); inspect counts/picks.`,
            }),
          },
        ],
      };
    }
  );

  // -------------------------------------------------------------------------
  // diamond_search — EXPLORATION AID (analyst browse; not the correlation path)
  // -------------------------------------------------------------------------

  registerTrackedAppTool(
    analytics,
    server,
    "diamond_search",
    {
      title: "Diamond Model Corpus Search (Exploration Aid)",
      description: `EXPLORATION AID — browse the report corpus by Diamond-vertex similarity. This is NOT the correlation path: to correlate a case, use \`correlate\` (the ti-correlation workflow), which does retrieval + triage + synthesis server-side. Host-driven synthesis from these stubs is deprecated.

Returns candidates with per-vertex matched_vertices evidence summaries and NO numeric scores, so an analyst can eyeball what the corpus holds for a given case sketch. Use diamond_search_analyst if you want visible scores.

USAGE:
1. Summarise the case into up to four Diamond Model vertex paragraphs (adversary, capability, infrastructure, victim) following diamond_summarisation_guidance. Omit vertices with no signal.
2. Call this tool with your vertex summaries and any file-hash IOCs.
3. Inspect the returned candidate stubs. To produce authoritative findings, feed the case to \`correlate\` rather than synthesizing here.`,
      _meta: { ui: {} },
      inputSchema: {
        adversary: z
          .string()
          .optional()
          .describe(
            "Adversary vertex: threat-actor names, aliases, attributed group, operational objectives."
          ),
        capability: z
          .string()
          .optional()
          .describe(
            "Capability vertex: malware families, exploited CVEs, TTP patterns, C2 frameworks."
          ),
        infrastructure: z
          .string()
          .optional()
          .describe(
            "Infrastructure vertex: hosting patterns, TLD preferences, relay chains, opsec profile."
          ),
        victim: z
          .string()
          .optional()
          .describe(
            "Victim vertex: targeted industry verticals, geographies, org types, technology stack."
          ),
        iocs: z
          .array(
            z.object({
              type: z
                .enum(["hash", "ip", "domain", "url"])
                .describe("IOC type"),
              value: z.string().describe("IOC value (lowercase)"),
            })
          )
          .optional()
          .describe(
            "File-hash and network IOCs from the case. Hash IOCs are used as discriminating anchors; network IOCs boost scoring."
          ),
        size: z
          .number()
          .int()
          .min(1)
          .max(50)
          .optional()
          .describe("Maximum candidate stubs to return (default 20, max 50)."),
      },
    },
    async ({ adversary, capability, infrastructure, victim, iocs, size }) => {
      const result = await correlationService.diamondSearch({
        vertex_queries: { adversary, capability, infrastructure, victim },
        iocs,
        size,
      });

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              candidates: result.candidates,
              meta: {
                total: result.total,
                degraded: result.degraded,
                vertices_queried: result.vertices_queried,
              },
              tradecraft: TRADECRAFT,
            }),
          },
        ],
      };
    }
  );

  // -------------------------------------------------------------------------
  // get_report
  // -------------------------------------------------------------------------

  registerTrackedAppTool(
    analytics,
    server,
    "get_report",
    {
      title: "Get Threat Report (Exploration Aid)",
      description: `Retrieve the full text of one or more threat reports by ID — an analyst exploration aid for reading source material.

Note: authoritative correlation is done by \`correlate\` (the ti-correlation workflow), which reads report bodies itself during synthesis. Use this to let an analyst read a report the workflow surfaced, or to inspect a diamond_search candidate — not to hand-synthesize a correlation report.`,
      _meta: { ui: {} },
      inputSchema: {
        report_ids: z
          .array(z.string())
          .min(1)
          .max(10)
          .describe(
            "Array of report IDs from diamond_search candidates. Maximum 10 per call."
          ),
      },
    },
    async ({ report_ids }) => {
      const reports = await correlationService.getReports(report_ids);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ reports }),
          },
        ],
      };
    }
  );

  // -------------------------------------------------------------------------
  // diamond_search_analyst — analyst-led transparent path
  // -------------------------------------------------------------------------

  registerTrackedAppTool(
    analytics,
    server,
    "diamond_search_analyst",
    {
      title: "Diamond Model Corpus Search — Scored (Exploration Aid)",
      description: `EXPLORATION AID — analyst-led browse of the corpus with visible per-vertex scores. This is NOT the correlation path: to correlate a case, use \`correlate\` (the ti-correlation workflow). Host-driven synthesis from these candidates is deprecated.

Returns ranked candidates with per-vertex match scores (vertex_scores) so an analyst can see how the corpus ranks against a case sketch and drive the triage UI.

The response includes:
- candidates: ScoredStub[] ranked by (overlap desc, max_score desc) — each with vertex_scores showing which Diamond Model vertices matched and their semantic similarity scores
- coverage: { queried, avg_overlap, thin } — thin=true signals weak retrieval (degraded or low multi-vertex overlap); the UI renders a backfill nudge
- tradecraft: triage_rubric for interpreting candidates

USAGE:
1. Summarise the case into Diamond Model vertex paragraphs following diamond_summarisation_guidance.
2. Call this tool; present the scored candidates and coverage signal to the analyst for exploration.
3. To produce authoritative findings, run \`correlate\` on the case and render the resulting run — do not hand-synthesize here.`,
      _meta: { ui: { resourceUri: CORRELATION_RESOURCE_URI } },
      inputSchema: {
        adversary: z
          .string()
          .optional()
          .describe(
            "Adversary vertex: threat-actor names, aliases, attributed group, operational objectives."
          ),
        capability: z
          .string()
          .optional()
          .describe(
            "Capability vertex: malware families, exploited CVEs, TTP patterns, C2 frameworks."
          ),
        infrastructure: z
          .string()
          .optional()
          .describe(
            "Infrastructure vertex: hosting patterns, TLD preferences, relay chains, opsec profile."
          ),
        victim: z
          .string()
          .optional()
          .describe(
            "Victim vertex: targeted industry verticals, geographies, org types, technology stack."
          ),
        iocs: z
          .array(
            z.object({
              type: z
                .enum(["hash", "ip", "domain", "url"])
                .describe("IOC type"),
              value: z.string().describe("IOC value (lowercase)"),
            })
          )
          .optional()
          .describe(
            "File-hash and network IOCs from the case. Hash IOCs are used as discriminating anchors; network IOCs boost scoring."
          ),
        size: z
          .number()
          .int()
          .min(1)
          .max(50)
          .optional()
          .describe("Maximum candidate stubs to return (default 20, max 50)."),
      },
    },
    async ({ adversary, capability, infrastructure, victim, iocs, size }) => {
      const result = await correlationService.diamondSearchScored({
        vertex_queries: { adversary, capability, infrastructure, victim },
        iocs,
        size,
      });

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              candidates: result.candidates,
              meta: {
                total: result.total,
                degraded: result.degraded,
                vertices_queried: result.vertices_queried,
              },
              coverage: result.coverage,
              tradecraft: TRADECRAFT,
            }),
          },
        ],
      };
    }
  );

  const correlationViewPath = resolveViewPath("correlation");
  registerAppResource(
    server,
    CORRELATION_RESOURCE_URI,
    CORRELATION_RESOURCE_URI,
    { mimeType: RESOURCE_MIME_TYPE },
    async () => {
      const html = fs.readFileSync(correlationViewPath, "utf-8");
      return {
        contents: [{ uri: CORRELATION_RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }],
      };
    }
  );

  // -------------------------------------------------------------------------
  // correlation_input_check — gate: show vertex signal before search runs
  // -------------------------------------------------------------------------

  const SIGNAL_SCHEMA = z.object({
    query: z.string().describe("The vertex summary paragraph (may be empty if signal is NONE)."),
    signal: z.enum(["HIGH", "PARTIAL", "NONE"]).describe(
      "Self-rated signal quality for this vertex."
    ),
  });

  registerTrackedAppTool(
    analytics,
    server,
    "correlation_input_check",
    {
      title: "Correlation Input Gate",
      description: `Review the diamond-query signal BEFORE running a correlation search.

Call this first with your per-vertex case summaries and signal self-ratings. The analyst reviews the stoplight (🟢 HIGH / 🟡 PARTIAL / 🔴 NONE) and query text for each vertex, then decides whether the input is ready to search.

On "Search this case", call diamond_search_analyst with the same vertex queries to explore the corpus (an exploration aid). For an authoritative correlation, run \`correlate\` on the case instead.
On "I'll revise first", the analyst provides additional case context in chat and you re-summarise before calling this tool again.

This tool performs NO Elasticsearch call and does NO search — it is a display-only gate.

INPUT SIGNAL SELF-RATING SCALE:
  HIGH    — specific, well-attested behavioural details; strong search anchor
  PARTIAL — present but weak or inferred; query sent but may produce noise
  NONE    — genuinely absent; omit this vertex from the search query`,
      _meta: { ui: { resourceUri: CORRELATION_INPUT_RESOURCE_URI } },
      inputSchema: {
        adversary: SIGNAL_SCHEMA.optional().describe(
          "Adversary vertex summary and self-rated signal."
        ),
        capability: SIGNAL_SCHEMA.optional().describe(
          "Capability vertex summary and self-rated signal."
        ),
        infrastructure: SIGNAL_SCHEMA.optional().describe(
          "Infrastructure vertex summary and self-rated signal."
        ),
        victim: SIGNAL_SCHEMA.optional().describe(
          "Victim vertex summary and self-rated signal."
        ),
      },
    },
    async ({ adversary, capability, infrastructure, victim }) => {
      const vertices = { adversary, capability, infrastructure, victim };

      // Build a compact summary line for the host's context.
      const ABBREV = { adversary: "ADV", capability: "CAP", infrastructure: "INF", victim: "VIC" } as const;
      const parts = (["adversary", "capability", "infrastructure", "victim"] as const)
        .filter((v) => vertices[v] !== undefined)
        .map((v) => `${ABBREV[v]} ${vertices[v]!.signal}`);

      const summaryLine = parts.length > 0
        ? `Input signal: ${parts.join(", ")} — review before searching.`
        : "No vertex signal provided. Describe the case first.";

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              kind: "correlation_input_check",
              vertices,
              summary: summaryLine,
            }),
          },
        ],
      };
    }
  );

  const correlationInputViewPath = resolveViewPath("correlation-input");
  registerAppResource(
    server,
    CORRELATION_INPUT_RESOURCE_URI,
    CORRELATION_INPUT_RESOURCE_URI,
    { mimeType: RESOURCE_MIME_TYPE },
    async () => {
      const html = fs.readFileSync(correlationInputViewPath, "utf-8");
      return {
        contents: [{ uri: CORRELATION_INPUT_RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }],
      };
    }
  );

  // -------------------------------------------------------------------------
  // render_correlation — pure pass-through; the host synthesized, we render
  // -------------------------------------------------------------------------

  const CORRELATION_REPORT_RESOURCE_URI = "ui://correlation-report/mcp-app.html";

  const VERTEX_SIGNAL_SCHEMA = z.enum(["high", "partial", "none"]);

  const EVIDENCE_ITEM_SCHEMA = z.object({
    vertex: z.enum(["adversary", "capability", "infrastructure", "victim"]),
    weight: z.enum([
      "smoking_gun",
      "supporting",
      "non_discriminatory",
      "counter",
      "decisive_counter",
    ]),
    text: z.string(),
  });

  const CONSOLIDATED_CANDIDATE_SCHEMA = z.object({
    id: z.string(),
    title: z.string(),
    reason: z.string(),
  });

  const LEAD_SCHEMA = z.object({
    candidate_ids: z.array(z.string()).min(1),
    title: z.string(),
    relationship: z.enum(["same_campaign", "same_actor", "shared_tradecraft"]),
    confidence: z.enum(["high", "moderate", "low"]),
    vertex_signal: z.object({
      adversary: VERTEX_SIGNAL_SCHEMA,
      capability: VERTEX_SIGNAL_SCHEMA,
      infrastructure: VERTEX_SIGNAL_SCHEMA,
      victim: VERTEX_SIGNAL_SCHEMA,
    }),
    bluf: z.string(),
    evidence: z.array(EVIDENCE_ITEM_SCHEMA),
    gaps: z.string(),
    consolidated_candidates: z.array(CONSOLIDATED_CANDIDATE_SCHEMA).default([]),
  });

  const NO_MATCH_SCHEMA = z.object({
    id: z.string(),
    title: z.string(),
    vendor: z.string().optional(),
  });

  const SYNTHESIS_SCHEMA = z.object({
    bluf: z.string(),
    correlation_signal: z.enum(["high", "moderate", "low", "none"]),
    reasoning: z.string(),
    gaps: z.string(),
    next_steps: z.array(
      z.object({
        priority: z.enum(["high", "moderate"]),
        text: z.string(),
      })
    ),
    inferential_hops: z.number().int().optional(),
    atomic_ioc_overlap: z
      .object({ assessed: z.boolean(), note: z.string().optional() })
      .optional(),
    case_title: z.string().optional(),
  });

  const CANDIDATE_META_ENTRY_SCHEMA = z.object({
    title: z.string().optional(),
    vendor: z.string().optional(),
    url: z.string().optional(),
  });

  // Shared shape for both the exact-anchor and code-token (phrase) anchor trails.
  const ANCHOR_TRAIL_ENTRY_SCHEMA = z.object({
    fp: z.string(),
    anchor_score: z.number(),
    overlap: z.number(),
    title: z.string().optional(),
    vendor: z.string().optional(),
    url: z.string().optional(),
    triage_confidence: z.number().optional(),
    justification: z.string().optional(),
    outcome: z.enum(["lead", "picked_no_lead", "dropped_at_triage"]),
    lead_title: z.string().optional(),
    relationship: z.string().optional(),
    lead_confidence: z.string().optional(),
  });

  registerTrackedAppTool(
    analytics,
    server,
    "render_correlation",
    {
      title: "Render Correlation Report",
      description: `Render a structured correlation report in the analyst view.

Call this with the \`findings\` returned by get_correlation_run once a correlate run has completed (findings are already resolved to the render shape — candidate ids populated). The analyst sees the rendered deep-dive report.

This tool performs NO synthesis and NO Elasticsearch queries — it is a pure renderer. The authoritative reasoning is done by the ti-correlation workflow (see \`correlate\`); this tool only hands the structured result to the UI.`,
      _meta: { ui: { resourceUri: CORRELATION_REPORT_RESOURCE_URI } },
      inputSchema: {
        findings: z
          .object({
            leads: z.array(LEAD_SCHEMA),
            no_match: z.array(NO_MATCH_SCHEMA),
            synthesis: SYNTHESIS_SCHEMA,
            case_vertex_signal: z
              .object({
                adversary: VERTEX_SIGNAL_SCHEMA,
                capability: VERTEX_SIGNAL_SCHEMA,
                infrastructure: VERTEX_SIGNAL_SCHEMA,
                victim: VERTEX_SIGNAL_SCHEMA,
              })
              .optional(),
            candidate_labels: z.record(z.string(), z.string()).optional(),
            candidate_meta: z.record(z.string(), CANDIDATE_META_ENTRY_SCHEMA).optional(),
            // Run-level context folded in by get_correlation_run so the view can
            // render the counts strip + Pipeline & cost panel from findings alone.
            counts: z.record(z.string(), z.number()).optional(),
            trace: z.record(z.string(), z.unknown()).optional(),
            run_meta: z
              .object({
                run_id: z.string().optional(),
                depth: z.string().optional(),
                status: z.string().optional(),
              })
              .optional(),
            // Anchor trail: the case anchors the workflow searched + how each
            // exact-anchor-matched report fared through triage into synthesis.
            anchors_searched: z
              .object({
                hashes: z.array(z.string()).default([]),
                network: z.array(z.string()).default([]),
                artifacts: z.array(z.string()).default([]),
                techniques: z.array(z.string()).default([]),
                code_tokens: z.array(z.string()).default([]),
              })
              .optional(),
            anchor_trail: z.array(ANCHOR_TRAIL_ENTRY_SCHEMA).optional(),
            // Code-token (phrase) anchor trail: candidates that shared a
            // distinctive code/execution token with the case.
            phrase_anchor_trail: z.array(ANCHOR_TRAIL_ENTRY_SCHEMA).optional(),
          })
          .describe("CorrelationFindings from get_correlation_run (render-ready)."),
      },
    },
    async ({ findings }) => {
      const leadsCount = findings.leads.length;
      const signal = findings.synthesis.correlation_signal;
      const caseTitle = findings.synthesis.case_title ?? "Correlation deep-dive";

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              kind: "correlation_report",
              findings,
              summary: `${caseTitle} — ${leadsCount} lead${leadsCount !== 1 ? "s" : ""}, signal: ${signal}`,
            }),
          },
        ],
      };
    }
  );

  const correlationReportViewPath = resolveViewPath("correlation-report");
  registerAppResource(
    server,
    CORRELATION_REPORT_RESOURCE_URI,
    CORRELATION_REPORT_RESOURCE_URI,
    { mimeType: RESOURCE_MIME_TYPE },
    async () => {
      const html = fs.readFileSync(correlationReportViewPath, "utf-8");
      return {
        contents: [{ uri: CORRELATION_REPORT_RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }],
      };
    }
  );
}
