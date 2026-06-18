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

const CORRELATION_RESOURCE_URI = "ui://correlation/mcp-app.html";
const CORRELATION_INPUT_RESOURCE_URI = "ui://correlation-input/mcp-app.html";

export interface CorrelationToolDeps {
  readonly correlationService: CorrelationService;
  readonly analytics: AnalyticsClient;
}

/**
 * Register the two threat-report correlation tools.
 *
 * HOST LOOP (described in each tool's description):
 *   1. Summarise the case into Diamond Model vertices (use TRADECRAFT guidance).
 *   2. Call `diamond_search` → receive candidate stubs + triage/synthesis rubric.
 *   3. Triage candidates yourself using the returned rubric.
 *   4. Call `get_report` for the top candidates.
 *   5. Synthesise correlation findings using the returned synthesis guidance.
 */
export function registerCorrelationTools(
  server: McpServer,
  deps: CorrelationToolDeps
): void {
  const { correlationService, analytics } = deps;

  // -------------------------------------------------------------------------
  // diamond_search
  // -------------------------------------------------------------------------

  registerTrackedAppTool(
    analytics,
    server,
    "diamond_search",
    {
      title: "Diamond Model Correlation Search",
      description: `Search the threat-report corpus for reports that correlate with a new case using the Diamond Model of Intrusion Analysis.

HOST WORKFLOW:
1. Summarise your case into up to four Diamond Model vertex paragraphs (adversary, capability, infrastructure, victim) following the diamond_summarisation_guidance included in every response. Omit vertices with no signal.
2. Call this tool with your vertex summaries and any file-hash IOCs from the case.
3. You will receive ranked candidate stubs (report_id, title, vendor, url) plus the triage_rubric and synthesis_guidance you need for later steps.
4. Triage candidates using the returned triage_rubric — do NOT anchor on numeric scores (none are returned).
5. Call get_report with the IDs of your top candidates.
6. Synthesise correlation findings using the returned synthesis_guidance.`,
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
      title: "Get Threat Report",
      description: `Retrieve the full text of one or more threat reports by ID.

Call this after triaging the candidates returned by diamond_search. Pass the report_ids of the candidates you selected for in-depth synthesis. The returned body_text + title + url are the source material for your synthesis step.`,
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
      title: "Diamond Model Correlation Search (Analyst-Led)",
      description: `Analyst-led transparent correlation: returns ranked candidates WITH per-vertex match scores and retrieval coverage, for an analyst (or analyst-supervised LLM) to triage with full visibility. Use this for interactive human-in-the-loop correlation. For blinded independent judgment instead, use \`diamond_search\`.

The response includes:
- candidates: ScoredStub[] ranked by (overlap desc, max_score desc) — each with vertex_scores showing which Diamond Model vertices matched and their semantic similarity scores
- coverage: { queried, avg_overlap, thin } — thin=true signals weak retrieval (degraded or low multi-vertex overlap); the UI renders a backfill nudge
- tradecraft: the same triage_rubric and synthesis_guidance as diamond_search

HOST WORKFLOW (analyst-supervised):
1. Summarise the case into Diamond Model vertex paragraphs following diamond_summarisation_guidance.
2. Call this tool; present the scored candidates and coverage signal to the analyst.
3. The analyst triages using vertex_scores as cues alongside the triage_rubric.
4. Call get_report for analyst-selected candidates.
5. Synthesise using synthesis_guidance.`,
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

On "Search this case", call diamond_search_analyst with the same vertex queries.
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

  registerTrackedAppTool(
    analytics,
    server,
    "render_correlation",
    {
      title: "Render Correlation Report",
      description: `Render a structured correlation report you (the host) synthesized.

Call this AFTER calling get_report and completing your synthesis. Pass your CorrelationFindings; the analyst sees the rendered deep-dive report.

This tool performs NO synthesis and NO Elasticsearch queries — it is a pure pass-through to the analyst view. The host is responsible for all reasoning; this tool only hands the structured result to the UI.`,
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
          })
          .describe("CorrelationFindings you synthesized from get_report output."),
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
