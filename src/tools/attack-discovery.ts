/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import type { AttackDiscovery } from "../elastic/client/index.js";
import type {
  AttackDiscoveryService,
  CasesService,
} from "../elastic/service/index.js";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import { registerTrackedAppTool } from "./tracked-app-tool.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://triage-attack-discoveries/mcp-app.html";

/**
 * Split a discovery's `detailsMarkdown` into the bullets that belong on the
 * case description ("Immediate actions") and the rest of the narrative
 * ("Attack chain"), so cases created from Attack Discoveries follow a
 * predictable structure regardless of what the LLM produced.
 *
 * If the markdown does not contain a recognizable Immediate Actions section,
 * we fall back to a small, generic checklist so the description always has
 * actionable content.
 */
function splitDiscoveryDetails(detailsMarkdown: string | undefined): {
  immediateActions: string;
  attackChain: string;
} {
  const FALLBACK = [
    "- Validate the affected user account(s) and recent authentication events.",
    "- Investigate the affected host(s) for further indicators of compromise.",
    "- Acknowledge or escalate the linked alerts based on triage outcome.",
  ].join("\n");

  if (!detailsMarkdown?.trim()) {
    return { immediateActions: FALLBACK, attackChain: "" };
  }

  // Walk the markdown line-by-line and look for a heading (`## …` / `### …`)
  // whose text mentions "immediate". When found, capture everything until
  // the next heading at the same-or-higher level (or end of document).
  const lines = detailsMarkdown.split(/\r?\n/);
  let startIdx = -1;
  let endIdx = lines.length;

  for (let i = 0; i < lines.length; i++) {
    const headingMatch = /^(#{2,3})\s+(.+)$/.exec(lines[i]);
    if (!headingMatch) continue;
    if (startIdx === -1) {
      if (/immediate/i.test(headingMatch[2])) startIdx = i;
    } else {
      endIdx = i;
      break;
    }
  }

  if (startIdx === -1) {
    return { immediateActions: FALLBACK, attackChain: detailsMarkdown.trim() };
  }

  const sectionBody = lines.slice(startIdx + 1, endIdx).join("\n").trim();
  const beforeBlock = lines.slice(0, startIdx).join("\n").trim();
  const afterBlock = lines.slice(endIdx).join("\n").trim();
  const attackChain = [beforeBlock, afterBlock].filter(Boolean).join("\n\n").trim();
  return {
    immediateActions: sectionBody || FALLBACK,
    attackChain,
  };
}

/** Services the attack-discovery tools depend on (default cluster only, for now). */
export interface AttackDiscoveryToolDeps {
  readonly attackDiscoveryService: AttackDiscoveryService;
  readonly casesService: CasesService;
  readonly analytics: AnalyticsClient;
}

export function registerAttackDiscoveryTools(
  server: McpServer,
  deps: AttackDiscoveryToolDeps
) {
  const { attackDiscoveryService, casesService, analytics } = deps;
  registerTrackedAppTool(
    analytics,
    server,
    "triage-attack-discoveries",
    {
      title: "Triage Attack Discoveries",
      description:
        "Fetch and triage Elastic Security Attack Discovery findings. Opens an interactive triage dashboard showing correlated attack narratives with confidence scoring, entity risk context, and approve/reject workflows. Use this for correlated attack-level triage (EASE), not individual alert triage.",
      inputSchema: {
        days: z.number().optional().describe("Number of days to look back (default: 1)"),
        limit: z.number().optional().describe("Max discoveries to return (default: 50)"),
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ days, limit }) => {
      const summary = await attackDiscoveryService.getDiscoveries({ days, limit });

      let triaged = null;
      if (summary.discoveries.length > 0) {
        try {
          triaged = await attackDiscoveryService.assessConfidence(summary.discoveries);
        } catch {
          triaged = null;
        }
      }

      const compact = {
        total: summary.total,
        params: { days: days || 1, limit: limit || 50 },
        discoveries: (triaged || summary.discoveries).slice(0, 20).map((d) => {
          const base: Record<string, unknown> = {
            id: d.id,
            title: d.title,
            summaryMarkdown: d.summaryMarkdown,
            detailsMarkdown: d.detailsMarkdown,
            mitreTactics: d.mitreTactics,
            alertIds: d.alertIds,
            alertCount: d.alertIds.length,
            alertsContextCount: d.alertsContextCount,
            riskScore: d.riskScore,
            timestamp: d.timestamp,
          };
          const td = d as unknown as Record<string, unknown>;
          if (td.confidence !== undefined) {
            base.confidence = td.confidence;
            base.hosts = td.hosts;
            base.users = td.users;
            base.ruleNames = td.ruleNames;
            base.signals = td.signals;
          }
          return base;
        }),
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(compact) }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "poll-discoveries",
    {
      title: "Poll Attack Discoveries",
      description: "Poll for updated attack discovery data",
      inputSchema: {
        days: z.number().optional(),
        limit: z.number().optional(),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ days, limit }) => {
      const summary = await attackDiscoveryService.getDiscoveries({ days, limit });
      return {
        content: [{ type: "text" as const, text: JSON.stringify(summary) }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "assess-discovery-confidence",
    {
      title: "Assess Discovery Confidence",
      description: "Run bulk confidence scoring across all discoveries",
      inputSchema: {
        discoveries: z.string().describe("JSON-encoded array of AttackDiscovery objects"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ discoveries: discoveriesJson }) => {
      const discoveries: AttackDiscovery[] = JSON.parse(discoveriesJson);
      const triaged = await attackDiscoveryService.assessConfidence(discoveries);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(triaged) }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "enrich-discovery",
    {
      title: "Enrich Discovery",
      description: "Fetch detailed context for a single attack discovery finding",
      inputSchema: {
        discovery: z.string().describe("JSON-encoded AttackDiscovery object"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ discovery: discoveryJson }) => {
      const discovery: AttackDiscovery = JSON.parse(discoveryJson);
      const detail = await attackDiscoveryService.getDiscoveryDetail(discovery);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(detail) }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "approve-discoveries",
    {
      title: "Approve Discoveries",
      description: "Create cases for approved attack discovery findings. Call this to bulk-create cases from triaged attack discoveries.",
      inputSchema: {
        findings: z.array(
          z.object({
            id: z.string(),
            title: z.string(),
            summaryMarkdown: z.string(),
            detailsMarkdown: z.string().optional().describe("Full attack narrative with IOCs, attack chain, and investigation details"),
            mitreTactics: z.array(z.string()),
            alertIds: z.array(z.string()),
            riskScore: z.number(),
            confidence: z.string().optional(),
          })
        ).describe("Array of approved findings to create cases for"),
      },
      _meta: { ui: { resourceUri: "ui://manage-cases/mcp-app.html" } },
    },
    async ({ findings }) => {
      const results: { findingId: string; caseId: string; caseTitle: string; alertsAttached: number }[] = [];

      for (const finding of findings) {
        const { immediateActions, attackChain } = splitDiscoveryDetails(finding.detailsMarkdown);

        // Description: short, predictable structure — summary + risk metadata + Immediate actions.
        const descriptionLines: string[] = [
          `## Attack Discovery Finding`,
          ``,
          `**Risk Score**: ${finding.riskScore}`,
          `**Confidence**: ${finding.confidence || "N/A"}`,
          `**MITRE Tactics**: ${finding.mitreTactics.join(", ") || "None"}`,
          `**Alert Count**: ${finding.alertIds.length}`,
          ``,
          finding.summaryMarkdown,
          ``,
          `## Immediate actions`,
          ``,
          immediateActions,
        ];

        const caseData = await casesService.createCase({
          title: `[Attack Discovery] ${finding.title}`,
          description: descriptionLines.join("\n"),
          tags: ["attack-discovery", "ease", ...finding.mitreTactics.map((t) => `mitre:${t}`)],
          severity: finding.riskScore >= 80 ? "critical" : finding.riskScore >= 60 ? "high" : finding.riskScore >= 40 ? "medium" : "low",
        });

        // First comment: the full attack chain narrative (everything except
        // the Immediate Actions section, which is already in the description).
        if (attackChain) {
          try {
            await casesService.addComment(
              caseData.id,
              [`## Attack chain`, ``, attackChain].join("\n")
            );
          } catch {
            // comment failed — case still created
          }
        }

        const alertsAttached = await casesService.attachAlertsByIds(
          caseData.id,
          finding.alertIds
        );

        results.push({ findingId: finding.id, caseId: caseData.id, caseTitle: caseData.title, alertsAttached });
      }

      return {
        content: [{ type: "text" as const, text: JSON.stringify({ created: results.length, cases: results }) }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "acknowledge-discoveries",
    {
      title: "Acknowledge Discoveries",
      description: "Mark attack discovery findings as acknowledged",
      inputSchema: {
        discoveryIds: z.array(z.string()).describe("Array of discovery document IDs"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ discoveryIds }) => {
      const result = await attackDiscoveryService.acknowledgeDiscoveries(discoveryIds);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result) }],
      };
    }
  );

  // ─── On-Demand Generation ───

  registerTrackedAppTool(
    analytics,
    server,
    "generate-attack-discovery",
    {
      title: "Generate Attack Discovery",
      description: "Trigger an on-demand attack discovery generation using a specified AI connector.",
      inputSchema: {
        connectorName: z.string().describe("AI connector name (e.g., 'Sonnet 4.5', 'GPT 5')"),
        size: z.number().optional().describe("Number of alerts to analyze (default: 50)"),
        start: z.string().optional().describe("Start time (default: now-7d)"),
        end: z.string().optional().describe("End time (default: now)"),
        filter: z.string().optional().describe("Optional ES DSL filter as JSON string"),
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ connectorName, size, start, end, filter }) => {
      try {
        const connectors = await attackDiscoveryService.listAIConnectors();
        let connector = connectors.find((c) => c.name.toLowerCase().includes(connectorName.toLowerCase()));
        if (!connector && connectors.length === 1) {
          connector = connectors[0];
        }
        if (!connector) {
          return { content: [{ type: "text" as const, text: JSON.stringify({ error: "No matching connector. Available: " + connectors.map((c) => c.name).join(", ") }) }] };
        }
        const filterObj = filter ? (JSON.parse(filter) as Record<string, unknown>) : undefined;
        const result = await attackDiscoveryService.generateAttackDiscovery({
          connectorId: connector.id,
          actionTypeId: connector.actionTypeId,
          connectorName: connector.name,
          size,
          start,
          end,
          filter: filterObj,
        });
        return { content: [{ type: "text" as const, text: JSON.stringify({ status: "generation_started", execution_uuid: result.execution_uuid, connector: connector.name, message: "Attack discovery generation has been started using " + connector.name + ". This typically takes 1-3 minutes. The interactive dashboard will show a progress banner and auto-refresh when results are ready. Do NOT call triage-attack-discoveries yet — wait for the user to tell you the results are in, or let them view results directly in the dashboard." }) }] };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }] };
      }
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "get-generation-status",
    {
      title: "Get Attack Discovery Generation Status",
      description: "Check the status of attack discovery generations",
      inputSchema: {
        size: z.number().optional(),
        start: z.string().optional(),
        end: z.string().optional(),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ size, start, end }) => {
      const result = await attackDiscoveryService.getGenerations({ size, start, end });
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "list-ai-connectors",
    {
      title: "List AI Connectors",
      description: "List available AI connectors. Call this first before generate-attack-discovery to find valid connector names.",
      inputSchema: {},
      _meta: { ui: {} },
    },
    async () => {
      const connectors = await attackDiscoveryService.listAIConnectors();
      return { content: [{ type: "text" as const, text: JSON.stringify(connectors) }] };
    }
  );

  const viewPath = resolveViewPath("attack-discovery");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
