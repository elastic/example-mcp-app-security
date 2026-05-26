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
import type { SecurityAlert } from "../shared/types.js";
import { createMcpAppBootstrap } from "../shared/mcp-app-bootstrap.js";
import type { AlertsService } from "../elastic/service/index.js";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import { registerTrackedAppTool } from "./tracked-app-tool.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://triage-alerts/mcp-app.html";

export interface AlertTriageToolDeps {
  readonly alertsService: AlertsService;
  readonly analytics: AnalyticsClient;
}

export function registerAlertTriageTools(
  server: McpServer,
  deps: AlertTriageToolDeps
) {
  const { alertsService, analytics } = deps;
  registerTrackedAppTool(
    analytics,
    server,
    "triage-alerts",
    {
      title: "Triage Security Alerts",
      description:
        "Fetch and triage unacknowledged Elastic Security alerts. Opens an interactive triage dashboard where you can investigate alerts, view process trees, classify threats, and create cases.",
      inputSchema: {
        days: z.number().optional().describe("Number of days to look back (default: 7)"),
        severity: z
          .enum(["low", "medium", "high", "critical"])
          .optional()
          .describe("Filter by severity"),
        limit: z.number().optional().describe("Max alerts to return (default: 50)"),
        query: z.string().optional().describe("Search query to filter alerts by rule name, hostname, username, process, MITRE technique, IP address, or file path. Derived from the user's request — e.g. 'ransomware', 'mimikatz', 'SRVWIN04', 'lateral movement'."),
        verdicts: z.array(z.object({
          rule: z.string().describe("The detection rule name this verdict applies to"),
          classification: z.enum(["benign", "suspicious", "malicious"]).describe("Your triage verdict"),
          confidence: z.enum(["low", "medium", "high"]).describe("Confidence level"),
          summary: z.string().describe("1-2 sentence explanation"),
          action: z.string().describe("Recommended next action"),
          hosts: z.array(z.string()).optional().describe("Affected hostnames"),
        })).optional().describe("Your triage verdicts — one per detection rule or alert group. Provide these based on your analysis of the alert data."),
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ days, severity, limit, query, verdicts }) => {
      const summary = await alertsService.getAlerts({ days, severity, limit, query });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              createMcpAppBootstrap("alert-triage", {
                summary: {
                  total: summary.total,
                  bySeverity: summary.bySeverity,
                  byRule: summary.byRule.slice(0, 10),
                  byHost: summary.byHost.slice(0, 10),
                  alerts: summary.alerts.slice(0, 30).map((a) => {
                    const s = a._source;
                    return {
                      id: a._id,
                      rule: s["kibana.alert.rule.name"],
                      severity: s["kibana.alert.severity"],
                      risk_score: s["kibana.alert.risk_score"],
                      reason: s["kibana.alert.reason"],
                      host: s.host?.name,
                      user: s.user?.name,
                      process: s.process?.name,
                      executable: s.process?.executable,
                      parent_process: s.process?.parent?.name,
                      file: s.file?.path,
                      source_ip: s.source?.ip,
                      dest_ip: s.destination?.ip,
                      timestamp: s["@timestamp"],
                      mitre: s["kibana.alert.rule.threat"]?.map((t) => ({
                        tactic: t.tactic.name,
                        techniques: t.technique?.map((tech) => `${tech.id} ${tech.name}`) || [],
                      })),
                    };
                  }),
                },
                params: { days: days || 7, severity, limit: limit || 50, query },
                verdicts: verdicts || [],
              }),
            ),
          },
        ],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "poll-alerts",
    {
      title: "Poll Alerts",
      description: "Poll for updated alert data",
      inputSchema: {
        days: z.number().optional(),
        severity: z.string().optional(),
        limit: z.number().optional(),
        status: z.string().optional(),
        query: z.string().optional(),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ days, severity, limit, status, query }) => {
      const summary = await alertsService.getAlerts({ days, severity, limit, status, query });
      return {
        content: [{ type: "text" as const, text: JSON.stringify(summary) }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "get-alert-context",
    {
      title: "Get Alert Context",
      description: "Fetch process tree, network events, and related alerts for investigation",
      inputSchema: {
        alertId: z.string().describe("The alert document ID"),
        alert: z.string().describe("JSON-encoded alert document"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ alertId, alert: alertJson }) => {
      const alert = JSON.parse(alertJson) as SecurityAlert;
      const context = await alertsService.getAlertContext(alertId, alert);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(context) }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "acknowledge-alert",
    {
      title: "Acknowledge Alert",
      description: "Mark an alert as acknowledged",
      inputSchema: {
        alertId: z.string().describe("The alert document ID"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ alertId }) => {
      await alertsService.acknowledgeAlert(alertId);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ success: true, alertId }) }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "unacknowledge-alert",
    {
      title: "Unacknowledge Alert",
      description: "Move an alert back to the open queue (used by the Triage UI Undo affordance after acknowledging)",
      inputSchema: {
        alertId: z.string().describe("The alert document ID"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ alertId }) => {
      const result = await alertsService.setAlertWorkflowStatus([alertId], "open");
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ success: true, alertId, ...result }) }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "acknowledge-alerts-bulk",
    {
      title: "Bulk Acknowledge Alerts",
      description: "Mark multiple alerts as acknowledged. Call this after triaging alerts to clear them from the queue.",
      inputSchema: {
        alertIds: z.array(z.string()).describe("Array of alert document IDs"),
      },
      _meta: { ui: {} },
    },
    async ({ alertIds }) => {
      const result = await alertsService.acknowledgeAlerts(alertIds);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result) }],
      };
    }
  );

  const viewPath = resolveViewPath("alert-triage");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
