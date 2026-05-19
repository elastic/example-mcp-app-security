/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { registerAlertTriageTools } from "./alert-triage.js";
import {
  createMockMcpServer,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import { createMockAlertsService } from "../test/helpers/mockServices.js";
import type { AlertSummary, SecurityAlert } from "../shared/types.js";
import type { AlertsService } from "../elastic/service/index.js";

const TRIAGE_RESOURCE_URI = "ui://triage-alerts/mcp-app.html";

function makeAlert(overrides: Partial<SecurityAlert["_source"]> = {}): SecurityAlert {
  return {
    _id: "alert-1",
    _index: ".alerts-security.alerts-default",
    _source: {
      "@timestamp": "2026-05-01T00:00:00Z",
      "kibana.alert.rule.name": "Suspicious PowerShell",
      "kibana.alert.rule.uuid": "rule-1",
      "kibana.alert.severity": "high",
      "kibana.alert.risk_score": 73,
      "kibana.alert.workflow_status": "open",
      "kibana.alert.reason": "powershell encoded command on host-1",
      ...overrides,
    },
  } as SecurityAlert;
}

function emptySummary(overrides: Partial<AlertSummary> = {}): AlertSummary {
  return {
    total: 0,
    bySeverity: {},
    byRule: [],
    byHost: [],
    alerts: [],
    ...overrides,
  };
}

describe("registerAlertTriageTools", () => {
  let server: MockMcpServer;
  let alertsService: AlertsService;

  beforeEach(() => {
    server = createMockMcpServer();
    alertsService = createMockAlertsService();
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>triage</html>");
    registerAlertTriageTools(server as unknown as McpServer, { alertsService });
  });

  it("registers every alert-triage tool plus its UI resource", () => {
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "triage-alerts",
        "poll-alerts",
        "get-alert-context",
        "acknowledge-alert",
        "unacknowledge-alert",
        "acknowledge-alerts-bulk",
      ].sort()
    );
    expect([...server.resources.keys()]).toEqual([TRIAGE_RESOURCE_URI]);
  });

  it("attaches the resource URI on the primary triage-alerts tool", () => {
    const tool = server.tool("triage-alerts");
    expect(tool.config._meta).toMatchObject({
      ui: { resourceUri: TRIAGE_RESOURCE_URI },
    });
  });

  describe("triage-alerts", () => {
    it("forwards days/severity/limit/query to AlertsService and shapes a compact response", async () => {
      vi.mocked(alertsService.getAlerts).mockResolvedValueOnce(
        emptySummary({
          total: 12,
          bySeverity: { high: 12 },
          byRule: Array.from({ length: 15 }, (_, i) => ({
            name: `rule-${i}`,
            count: 15 - i,
          })),
          byHost: Array.from({ length: 15 }, (_, i) => ({
            name: `host-${i}`,
            count: 15 - i,
          })),
          alerts: Array.from({ length: 35 }, (_, i) =>
            makeAlert({
              "kibana.alert.rule.name": `rule-${i}`,
            })
          ).map((a, i) => ({ ...a, _id: `alert-${i}` })),
        })
      );

      const out = await server
        .tool("triage-alerts")
        .callback({ days: 3, severity: "high", limit: 25, query: "powershell" });

      expect(alertsService.getAlerts).toHaveBeenCalledWith({
        days: 3,
        severity: "high",
        limit: 25,
        query: "powershell",
        namespace: undefined,
      });

      const body = parseToolText<{
        total: number;
        byRule: unknown[];
        byHost: unknown[];
        alerts: { id: string }[];
        params: Record<string, unknown>;
        verdicts: unknown[];
      }>(out);

      expect(body.total).toBe(12);
      expect(body.byRule).toHaveLength(10);
      expect(body.byHost).toHaveLength(10);
      expect(body.alerts).toHaveLength(30);
      expect(body.params).toEqual({
        days: 3,
        severity: "high",
        limit: 25,
        query: "powershell",
        namespace: undefined,
      });
      expect(body.verdicts).toEqual([]);
    });

    it("forwards and echoes namespace when supplied", async () => {
      vi.mocked(alertsService.getAlerts).mockResolvedValueOnce(emptySummary());
      const out = await server
        .tool("triage-alerts")
        .callback({ namespace: "soc" });
      expect(alertsService.getAlerts).toHaveBeenCalledWith(
        expect.objectContaining({ namespace: "soc" })
      );
      const body = parseToolText<{ params: Record<string, unknown> }>(out);
      expect(body.params.namespace).toBe("soc");
    });

    it("falls back to default params (days=7, limit=50) and surfaces the supplied verdicts", async () => {
      vi.mocked(alertsService.getAlerts).mockResolvedValueOnce(emptySummary());

      const verdicts = [
        {
          rule: "Suspicious PowerShell",
          classification: "malicious",
          confidence: "high",
          summary: "Confirmed encoded payload",
          action: "Isolate host",
          hosts: ["host-1"],
        },
      ];
      const out = await server.tool("triage-alerts").callback({ verdicts });

      const body = parseToolText<{
        params: Record<string, unknown>;
        verdicts: unknown[];
      }>(out);
      expect(body.params).toEqual({
        days: 7,
        severity: undefined,
        limit: 50,
        query: undefined,
        namespace: undefined,
      });
      expect(body.verdicts).toEqual(verdicts);
    });

    it("flattens the alert source into the wire shape consumed by the UI", async () => {
      vi.mocked(alertsService.getAlerts).mockResolvedValueOnce(
        emptySummary({
          alerts: [
            makeAlert({
              host: { name: "host-1" },
              user: { name: "alice" },
              process: {
                name: "powershell.exe",
                executable: "C:\\powershell.exe",
                parent: { name: "explorer.exe" },
              },
              file: { path: "C:\\malware.exe" },
              source: { ip: "10.0.0.1" },
              destination: { ip: "10.0.0.2" },
              "kibana.alert.rule.threat": [
                {
                  tactic: { id: "TA0001", name: "Initial Access", reference: "" },
                  framework: "MITRE ATT&CK",
                  technique: [
                    { id: "T1059", name: "Command Scripting", reference: "" },
                  ],
                },
              ],
            }),
          ],
        })
      );

      const out = await server.tool("triage-alerts").callback({});

      const body = parseToolText<{
        alerts: {
          id: string;
          rule: string;
          host: string;
          process: string;
          mitre: { tactic: string; techniques: string[] }[];
        }[];
      }>(out);

      expect(body.alerts).toEqual([
        expect.objectContaining({
          id: "alert-1",
          rule: "Suspicious PowerShell",
          severity: "high",
          host: "host-1",
          user: "alice",
          process: "powershell.exe",
          executable: "C:\\powershell.exe",
          parent_process: "explorer.exe",
          file: "C:\\malware.exe",
          source_ip: "10.0.0.1",
          dest_ip: "10.0.0.2",
          mitre: [
            { tactic: "Initial Access", techniques: ["T1059 Command Scripting"] },
          ],
        }),
      ]);
    });

    it("emits an empty mitre techniques array when the alert lists a tactic without techniques", async () => {
      vi.mocked(alertsService.getAlerts).mockResolvedValueOnce(
        emptySummary({
          alerts: [
            makeAlert({
              "kibana.alert.rule.threat": [
                {
                  tactic: { id: "TA0001", name: "Initial Access", reference: "" },
                  framework: "MITRE ATT&CK",
                },
              ],
            }),
          ],
        })
      );

      const out = await server.tool("triage-alerts").callback({});
      const body = parseToolText<{ alerts: { mitre?: unknown[] }[] }>(out);
      expect(body.alerts[0].mitre).toEqual([
        { tactic: "Initial Access", techniques: [] },
      ]);
    });
  });

  describe("poll-alerts", () => {
    it("delegates straight through to AlertsService.getAlerts and returns the raw summary", async () => {
      const summary = emptySummary({ total: 3 });
      vi.mocked(alertsService.getAlerts).mockResolvedValueOnce(summary);

      const out = await server.tool("poll-alerts").callback({
        days: 1,
        severity: "critical",
        limit: 5,
        status: "acknowledged",
        query: "ransomware",
      });

      expect(alertsService.getAlerts).toHaveBeenCalledWith({
        days: 1,
        severity: "critical",
        limit: 5,
        status: "acknowledged",
        query: "ransomware",
        namespace: undefined,
      });
      expect(parseToolText(out)).toEqual(summary);
    });

    it("forwards namespace to the service when supplied", async () => {
      vi.mocked(alertsService.getAlerts).mockResolvedValueOnce(emptySummary());
      await server.tool("poll-alerts").callback({ namespace: "soc" });
      expect(alertsService.getAlerts).toHaveBeenCalledWith(
        expect.objectContaining({ namespace: "soc" })
      );
    });
  });

  describe("get-alert-context", () => {
    it("parses the JSON-encoded alert and forwards it alongside the alert id", async () => {
      const alert = makeAlert();
      const context = {
        processEvents: [],
        networkEvents: [],
        relatedAlerts: [],
      };
      vi.mocked(alertsService.getAlertContext).mockResolvedValueOnce(context);

      const out = await server.tool("get-alert-context").callback({
        alertId: "alert-1",
        alert: JSON.stringify(alert),
      });

      expect(alertsService.getAlertContext).toHaveBeenCalledWith(
        "alert-1",
        alert,
        undefined
      );
      expect(parseToolText(out)).toEqual(context);
    });

    it("forwards namespace to the service when supplied", async () => {
      const alert = makeAlert();
      vi.mocked(alertsService.getAlertContext).mockResolvedValueOnce({
        processEvents: [],
        networkEvents: [],
        relatedAlerts: [],
      });
      await server.tool("get-alert-context").callback({
        alertId: "alert-1",
        alert: JSON.stringify(alert),
        namespace: "soc",
      });
      expect(alertsService.getAlertContext).toHaveBeenCalledWith(
        "alert-1",
        alert,
        "soc"
      );
    });
  });

  describe("acknowledge-alert", () => {
    it("acknowledges a single alert and returns success metadata", async () => {
      vi.mocked(alertsService.acknowledgeAlert).mockResolvedValueOnce(undefined);

      const out = await server
        .tool("acknowledge-alert")
        .callback({ alertId: "alert-42" });

      expect(alertsService.acknowledgeAlert).toHaveBeenCalledWith(
        "alert-42",
        undefined
      );
      expect(parseToolText(out)).toEqual({ success: true, alertId: "alert-42" });
    });

    it("forwards namespace to the service when supplied", async () => {
      vi.mocked(alertsService.acknowledgeAlert).mockResolvedValueOnce(undefined);
      await server
        .tool("acknowledge-alert")
        .callback({ alertId: "alert-42", namespace: "soc" });
      expect(alertsService.acknowledgeAlert).toHaveBeenCalledWith(
        "alert-42",
        "soc"
      );
    });
  });

  describe("acknowledge-alerts-bulk", () => {
    it("forwards the alert ids and surfaces the updated count from AlertsService", async () => {
      vi.mocked(alertsService.acknowledgeAlerts).mockResolvedValueOnce({
        updated: 2,
      });

      const out = await server.tool("acknowledge-alerts-bulk").callback({
        alertIds: ["a", "b"],
      });

      expect(alertsService.acknowledgeAlerts).toHaveBeenCalledWith(
        ["a", "b"],
        undefined
      );
      expect(parseToolText(out)).toEqual({ updated: 2 });
    });

    it("forwards namespace to the service when supplied", async () => {
      vi.mocked(alertsService.acknowledgeAlerts).mockResolvedValueOnce({
        updated: 1,
      });
      await server
        .tool("acknowledge-alerts-bulk")
        .callback({ alertIds: ["a"], namespace: "soc" });
      expect(alertsService.acknowledgeAlerts).toHaveBeenCalledWith(["a"], "soc");
    });
  });

  describe("triage-alerts UI resource", () => {
    it("reads the resolved view file and returns it as the resource body", async () => {
      const out = await server.resource(TRIAGE_RESOURCE_URI).readCallback();
      expect(fs.readFileSync).toHaveBeenCalledTimes(1);
      expect(out).toEqual({
        contents: [
          {
            uri: TRIAGE_RESOURCE_URI,
            mimeType: "text/html;profile=mcp-app",
            text: "<html>triage</html>",
          },
        ],
      });
    });
  });
});
