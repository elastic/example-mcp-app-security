import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppTool,
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import {
  fetchDiscoveries,
  assessConfidence,
  acknowledgeDiscoveries,
  getDiscoveryDetail,
} from "../elastic/attack-discovery.js";
import type { AttackDiscovery } from "../elastic/attack-discovery.js";
import { createCase, attachAlert } from "../elastic/cases.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://triage-attack-discoveries/mcp-app.html";

export function registerAttackDiscoveryTools(server: McpServer) {
  registerAppTool(
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
      const summary = await fetchDiscoveries({ days, limit });

      let triaged = null;
      if (summary.discoveries.length > 0) {
        try {
          triaged = await assessConfidence(summary.discoveries);
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

  registerAppTool(
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
      const summary = await fetchDiscoveries({ days, limit });
      return {
        content: [{ type: "text" as const, text: JSON.stringify(summary) }],
      };
    }
  );

  registerAppTool(
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
      const triaged = await assessConfidence(discoveries);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(triaged) }],
      };
    }
  );

  registerAppTool(
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
      const detail = await getDiscoveryDetail(discovery);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(detail) }],
      };
    }
  );

  registerAppTool(
    server,
    "approve-discoveries",
    {
      title: "Approve Discoveries",
      description: "Create cases for approved attack discovery findings",
      inputSchema: {
        findings: z.array(
          z.object({
            id: z.string(),
            title: z.string(),
            summaryMarkdown: z.string(),
            mitreTactics: z.array(z.string()),
            alertIds: z.array(z.string()),
            riskScore: z.number(),
            confidence: z.string().optional(),
          })
        ).describe("Array of approved findings to create cases for"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ findings }) => {
      const results: { findingId: string; caseId: string; caseTitle: string }[] = [];

      for (const finding of findings) {
        const caseData = await createCase({
          title: `[Attack Discovery] ${finding.title}`,
          description: [
            `## Attack Discovery Finding`,
            ``,
            `**Risk Score**: ${finding.riskScore}`,
            `**Confidence**: ${finding.confidence || "N/A"}`,
            `**MITRE Tactics**: ${finding.mitreTactics.join(", ") || "None"}`,
            `**Alert Count**: ${finding.alertIds.length}`,
            ``,
            finding.summaryMarkdown,
          ].join("\n"),
          tags: ["attack-discovery", "ease", ...finding.mitreTactics.map((t) => `mitre:${t}`)],
          severity: finding.riskScore >= 80 ? "critical" : finding.riskScore >= 60 ? "high" : finding.riskScore >= 40 ? "medium" : "low",
        });

        results.push({ findingId: finding.id, caseId: caseData.id, caseTitle: caseData.title });
      }

      return {
        content: [{ type: "text" as const, text: JSON.stringify({ created: results.length, cases: results }) }],
      };
    }
  );

  registerAppTool(
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
      const result = await acknowledgeDiscoveries(discoveryIds);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result) }],
      };
    }
  );

  // ─── On-Demand Generation ───

  registerAppTool(
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
        const { generateAttackDiscovery, listAIConnectors } = await import("../elastic/attack-discovery.js");
        const connectors = await listAIConnectors();
        const connector = connectors.find((c) => c.name.toLowerCase().includes(connectorName.toLowerCase()));
        if (!connector) {
          return { content: [{ type: "text" as const, text: JSON.stringify({ error: "No matching connector. Available: " + connectors.map((c) => c.name).join(", ") }) }] };
        }
        const filterObj = filter ? JSON.parse(filter) : undefined;
        const result = await generateAttackDiscovery({ connectorId: connector.id, actionTypeId: connector.actionTypeId, connectorName: connector.name, size, start, end, filter: filterObj });
        return { content: [{ type: "text" as const, text: JSON.stringify({ status: "generation_started", execution_uuid: result.execution_uuid, connector: connector.name, message: "Attack discovery generation has been started using " + connector.name + ". This typically takes 1-3 minutes. The interactive dashboard will show a progress banner and auto-refresh when results are ready. Do NOT call triage-attack-discoveries yet — wait for the user to tell you the results are in, or let them view results directly in the dashboard." }) }] };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: msg }) }] };
      }
    }
  );

  registerAppTool(
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
      const { kibanaRequest } = await import("../elastic/client.js");
      const params: Record<string, string> = {};
      if (size) params.size = String(size);
      if (start) params.start = start;
      if (end) params.end = end;
      const result = await kibanaRequest("/api/attack_discovery/generations", { params, apiVersion: "2023-10-31" });
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "list-ai-connectors",
    {
      title: "List AI Connectors",
      description: "List available AI connectors",
      inputSchema: {},
      _meta: { ui: { visibility: ["app"] } },
    },
    async () => {
      const { listAIConnectors } = await import("../elastic/attack-discovery.js");
      const connectors = await listAIConnectors();
      return { content: [{ type: "text" as const, text: JSON.stringify(connectors) }] };
    }
  );

  const viewPath = resolveViewPath("attack-discovery");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
