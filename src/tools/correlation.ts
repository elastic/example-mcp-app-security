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
import { z } from "zod";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import type { CorrelationService } from "../elastic/service/correlationService.js";
import { TRADECRAFT } from "../correlation/tradecraft.js";
import { registerTrackedAppTool } from "./tracked-app-tool.js";

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
}
