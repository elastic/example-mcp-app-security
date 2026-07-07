/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { registerAttackDiscoveryTools } from "./attack-discovery.js";
import {
  createMockMcpServer,
  parseBootstrapToolText,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import {
  createMockAttackDiscoveryService,
  createMockCasesService,
} from "../test/helpers/mockServices.js";
import { createMockAnalyticsClient } from "../test/helpers/mockAnalytics.js";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import type {
  AttackDiscovery,
  TriagedDiscovery,
} from "../elastic/client/index.js";
import type {
  AttackDiscoveryService,
  CasesService,
} from "../elastic/service/index.js";
import type { KibanaCase } from "../shared/types.js";

const RESOURCE_URI = "ui://triage-attack-discoveries/mcp-app.html";

function caseStub(overrides: Partial<KibanaCase>): KibanaCase {
  return overrides as unknown as KibanaCase;
}

function makeDiscovery(overrides: Partial<AttackDiscovery> = {}): AttackDiscovery {
  return {
    id: "d-1",
    timestamp: "2026-05-01T00:00:00Z",
    executionUuid: "exec-1",
    title: "Suspicious activity",
    summaryMarkdown: "summary",
    detailsMarkdown: "details",
    mitreTactics: ["TA0001"],
    alertIds: ["a1", "a2"],
    alertsContextCount: 2,
    riskScore: 50,
    ...overrides,
  };
}

describe("registerAttackDiscoveryTools", () => {
  let server: MockMcpServer;
  let attackDiscoveryService: AttackDiscoveryService;
  let casesService: CasesService;
  let analytics: AnalyticsClient;

  beforeEach(() => {
    server = createMockMcpServer();
    attackDiscoveryService = createMockAttackDiscoveryService();
    casesService = createMockCasesService();
    analytics = createMockAnalyticsClient();
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>ad</html>");
    registerAttackDiscoveryTools(server as unknown as McpServer, {
      attackDiscoveryService,
      casesService,
      analytics,
    });
  });

  it("registers every attack-discovery tool plus the UI resource", () => {
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "triage-attack-discoveries",
        "poll-discoveries",
        "assess-discovery-confidence",
        "enrich-discovery",
        "approve-discoveries",
        "acknowledge-discoveries",
        "generate-attack-discovery",
        "get-generation-status",
        "list-ai-connectors",
      ].sort()
    );
    expect([...server.resources.keys()]).toEqual([RESOURCE_URI]);
  });

  describe("triage-attack-discoveries", () => {
    it("emits successful telemetry for the registered tool callback", async () => {
      vi.mocked(attackDiscoveryService.getDiscoveries).mockResolvedValueOnce({
        total: 0,
        discoveries: [],
      });

      await server.tool("triage-attack-discoveries").callback({ days: 2, limit: 10 });

      expect(analytics.trackToolCalled).toHaveBeenCalledExactlyOnceWith({
        tool_id: "triage-attack-discoveries",
        duration_ms: expect.any(Number),
        success: true,
      });
    });

    it("calls assessConfidence and returns triaged discoveries with confidence fields", async () => {
      const discoveries = [makeDiscovery()];
      vi.mocked(attackDiscoveryService.getDiscoveries).mockResolvedValueOnce({
        total: 1,
        discoveries,
      });
      const triaged: TriagedDiscovery[] = [
        {
          ...discoveries[0],
          confidence: "high",
          signals: {
            alertDiversity: { alertCount: 2, ruleCount: 1, severities: ["high"] },
            ruleFrequency: [],
            entityRisk: [],
          },
          hosts: ["host-1"],
          users: ["alice"],
          ruleNames: ["rule-1"],
        },
      ];
      vi.mocked(attackDiscoveryService.assessConfidence).mockResolvedValueOnce(
        triaged
      );

      const out = await server
        .tool("triage-attack-discoveries")
        .callback({ days: 2, limit: 10 });

      expect(attackDiscoveryService.getDiscoveries).toHaveBeenCalledWith({
        days: 2,
        limit: 10,
      });
      expect(attackDiscoveryService.assessConfidence).toHaveBeenCalledWith(
        discoveries
      );

      const body = parseBootstrapToolText(out, "attack-discovery");
      expect(body.total).toBe(1);
      expect(body.params).toEqual({ days: 2, limit: 10 });
      expect(body.discoveries[0]).toMatchObject({
        id: "d-1",
        confidence: "high",
        hosts: ["host-1"],
        users: ["alice"],
        ruleNames: ["rule-1"],
      });
    });

    it("falls back to the raw discoveries (without confidence) when assessment throws", async () => {
      const discoveries = [makeDiscovery()];
      vi.mocked(attackDiscoveryService.getDiscoveries).mockResolvedValueOnce({
        total: 1,
        discoveries,
      });
      vi.mocked(attackDiscoveryService.assessConfidence).mockRejectedValueOnce(
        new Error("LLM down")
      );

      const out = await server
        .tool("triage-attack-discoveries")
        .callback({});

      const body = parseBootstrapToolText(out, "attack-discovery");
      expect(body.params).toEqual({ days: 1, limit: 50 });
      expect(body.discoveries[0].confidence).toBeUndefined();
    });

    it("skips assessment entirely when there are no discoveries", async () => {
      vi.mocked(attackDiscoveryService.getDiscoveries).mockResolvedValueOnce({
        total: 0,
        discoveries: [],
      });

      const out = await server.tool("triage-attack-discoveries").callback({});

      expect(attackDiscoveryService.assessConfidence).not.toHaveBeenCalled();
      const body = parseBootstrapToolText(out, "attack-discovery");
      expect(body.discoveries).toEqual([]);
    });

    it("caps the response at 20 discoveries", async () => {
      const big = Array.from({ length: 35 }, (_, i) =>
        makeDiscovery({ id: `d-${i}` })
      );
      vi.mocked(attackDiscoveryService.getDiscoveries).mockResolvedValueOnce({
        total: 35,
        discoveries: big,
      });
      vi.mocked(attackDiscoveryService.assessConfidence).mockResolvedValueOnce(
        big.map((d) => ({
          ...d,
          confidence: "high" as const,
          signals: {
            alertDiversity: { alertCount: 0, ruleCount: 0, severities: [] },
            ruleFrequency: [],
            entityRisk: [],
          },
          hosts: [],
          users: [],
          ruleNames: [],
        }))
      );

      const out = await server.tool("triage-attack-discoveries").callback({});
      const body = parseBootstrapToolText(out, "attack-discovery");
      expect(body.discoveries).toHaveLength(20);
    });
  });

  describe("poll-discoveries", () => {
    it("emits failed telemetry when the tool callback rejects", async () => {
      const boom = new Error("service unavailable");
      vi.mocked(attackDiscoveryService.getDiscoveries).mockRejectedValueOnce(boom);

      await expect(server.tool("poll-discoveries").callback({})).rejects.toBe(boom);

      expect(analytics.trackToolCalled).toHaveBeenCalledExactlyOnceWith({
        tool_id: "poll-discoveries",
        duration_ms: expect.any(Number),
        success: false,
      });
    });

    it("returns the raw discovery summary as JSON", async () => {
      const summary = { total: 1, discoveries: [makeDiscovery()] };
      vi.mocked(attackDiscoveryService.getDiscoveries).mockResolvedValueOnce(
        summary
      );

      const out = await server.tool("poll-discoveries").callback({ days: 7 });
      expect(attackDiscoveryService.getDiscoveries).toHaveBeenCalledWith({
        days: 7,
        limit: undefined,
      });
      expect(parseToolText(out)).toEqual(summary);
    });
  });

  describe("assess-discovery-confidence", () => {
    it("parses the JSON-encoded discoveries argument and surfaces the triage result", async () => {
      const discoveries = [makeDiscovery()];
      const triaged: TriagedDiscovery[] = [
        {
          ...discoveries[0],
          confidence: "moderate",
          signals: {
            alertDiversity: { alertCount: 2, ruleCount: 1, severities: ["high"] },
            ruleFrequency: [],
            entityRisk: [],
          },
          hosts: [],
          users: [],
          ruleNames: [],
        },
      ];
      vi.mocked(attackDiscoveryService.assessConfidence).mockResolvedValueOnce(
        triaged
      );

      const out = await server.tool("assess-discovery-confidence").callback({
        discoveries: JSON.stringify(discoveries),
      });

      expect(attackDiscoveryService.assessConfidence).toHaveBeenCalledWith(
        discoveries
      );
      expect(parseToolText(out)).toEqual(triaged);
    });
  });

  describe("enrich-discovery", () => {
    it("parses the JSON-encoded discovery and returns the detail envelope", async () => {
      const discovery = makeDiscovery();
      const detail = {
        titleWithReplacements: "title",
        summaryWithReplacements: "summary",
        detailsWithReplacements: "details",
        alerts: [],
        entityRisk: [],
      };
      vi.mocked(attackDiscoveryService.getDiscoveryDetail).mockResolvedValueOnce(
        detail
      );

      const out = await server.tool("enrich-discovery").callback({
        discovery: JSON.stringify(discovery),
      });

      expect(attackDiscoveryService.getDiscoveryDetail).toHaveBeenCalledWith(
        discovery
      );
      expect(parseToolText(out)).toEqual(detail);
    });
  });

  describe("approve-discoveries", () => {
    it("creates a case per finding, attaches alerts, and reports the result", async () => {
      vi.mocked(casesService.createCase).mockImplementation(async (input) =>
        caseStub({
          id: `case-${input.title}`,
          title: input.title,
          severity: (input.severity || "low") as KibanaCase["severity"],
          description: input.description,
          tags: input.tags || [],
        })
      );
      vi.mocked(casesService.attachAlertsByIds).mockResolvedValueOnce(2);
      vi.mocked(casesService.addComment).mockResolvedValueOnce(undefined);

      const findings = [
        {
          id: "f-1",
          title: "Hot finding",
          summaryMarkdown: "summary",
          detailsMarkdown: "long details",
          mitreTactics: ["TA0001"],
          alertIds: ["a1", "a2"],
          riskScore: 85,
          confidence: "high",
        },
      ];

      const out = await server
        .tool("approve-discoveries")
        .callback({ findings });

      expect(casesService.createCase).toHaveBeenCalledTimes(1);
      const createCall = vi.mocked(casesService.createCase).mock.calls[0][0];
      expect(createCall.title).toBe("[Attack Discovery] Hot finding");
      expect(createCall.severity).toBe("critical");
      expect(createCall.tags).toEqual([
        "attack-discovery",
        "ease",
        "mitre:TA0001",
      ]);
      expect(createCall.description).toContain("**Risk Score**: 85");
      expect(createCall.description).toContain("## Immediate actions");

      expect(casesService.addComment).toHaveBeenCalledWith(
        "case-[Attack Discovery] Hot finding",
        expect.stringContaining("## Attack chain")
      );
      expect(casesService.addComment).toHaveBeenCalledWith(
        "case-[Attack Discovery] Hot finding",
        expect.stringContaining("long details")
      );
      expect(casesService.attachAlertsByIds).toHaveBeenCalledWith(
        "case-[Attack Discovery] Hot finding",
        ["a1", "a2"]
      );

      const body = parseToolText<{
        created: number;
        cases: { findingId: string; alertsAttached: number }[];
      }>(out);
      expect(body.created).toBe(1);
      expect(body.cases[0]).toMatchObject({
        findingId: "f-1",
        alertsAttached: 2,
      });
    });

    it.each([
      [85, "critical"],
      [65, "high"],
      [45, "medium"],
      [10, "low"],
    ])(
      "maps risk score %i to case severity %s",
      async (riskScore, expectedSeverity) => {
        vi.mocked(casesService.createCase).mockImplementation(async (input) =>
          caseStub({
            id: "case-x",
            title: input.title,
            severity: input.severity as KibanaCase["severity"],
          })
        );
        vi.mocked(casesService.attachAlertsByIds).mockResolvedValueOnce(0);

        await server.tool("approve-discoveries").callback({
          findings: [
            {
              id: "f-1",
              title: "x",
              summaryMarkdown: "s",
              mitreTactics: [],
              alertIds: [],
              riskScore,
            },
          ],
        });

        expect(
          vi.mocked(casesService.createCase).mock.calls[0][0].severity
        ).toBe(expectedSeverity);
      }
    );

    it("does not call addComment when the finding has no detailsMarkdown", async () => {
      vi.mocked(casesService.createCase).mockResolvedValueOnce(
        caseStub({ id: "case-1", title: "x" })
      );
      vi.mocked(casesService.attachAlertsByIds).mockResolvedValueOnce(0);

      await server.tool("approve-discoveries").callback({
        findings: [
          {
            id: "f-1",
            title: "x",
            summaryMarkdown: "s",
            mitreTactics: [],
            alertIds: [],
            riskScore: 10,
          },
        ],
      });

      expect(casesService.addComment).not.toHaveBeenCalled();
    });

    it("still returns success when addComment throws", async () => {
      vi.mocked(casesService.createCase).mockResolvedValueOnce(
        caseStub({ id: "case-1", title: "x" })
      );
      vi.mocked(casesService.addComment).mockRejectedValueOnce(
        new Error("permission denied")
      );
      vi.mocked(casesService.attachAlertsByIds).mockResolvedValueOnce(1);

      const out = await server.tool("approve-discoveries").callback({
        findings: [
          {
            id: "f-1",
            title: "x",
            summaryMarkdown: "s",
            detailsMarkdown: "details",
            mitreTactics: [],
            alertIds: ["a1"],
            riskScore: 10,
          },
        ],
      });

      const body = parseToolText<{ created: number }>(out);
      expect(body.created).toBe(1);
    });

    it("reports zero MITRE tactics when the finding lists none", async () => {
      vi.mocked(casesService.createCase).mockResolvedValueOnce(
        caseStub({ id: "case-1", title: "x" })
      );
      vi.mocked(casesService.attachAlertsByIds).mockResolvedValueOnce(0);

      await server.tool("approve-discoveries").callback({
        findings: [
          {
            id: "f-1",
            title: "x",
            summaryMarkdown: "s",
            mitreTactics: [],
            alertIds: [],
            riskScore: 10,
          },
        ],
      });

      const description = vi.mocked(casesService.createCase).mock.calls[0][0]
        .description;
      expect(description).toContain("**MITRE Tactics**: None");
      expect(description).toContain("**Confidence**: N/A");
    });
  });

  describe("acknowledge-discoveries", () => {
    it("forwards the ids to AttackDiscoveryService and surfaces the result", async () => {
      vi.mocked(
        attackDiscoveryService.acknowledgeDiscoveries
      ).mockResolvedValueOnce({ updated: 3 });

      const out = await server
        .tool("acknowledge-discoveries")
        .callback({ discoveryIds: ["d-1", "d-2", "d-3"] });

      expect(
        attackDiscoveryService.acknowledgeDiscoveries
      ).toHaveBeenCalledWith(["d-1", "d-2", "d-3"]);
      expect(parseToolText(out)).toEqual({ updated: 3 });
    });
  });

  describe("generate-attack-discovery", () => {
    it("matches the connector by case-insensitive substring and forwards the parsed filter", async () => {
      vi.mocked(attackDiscoveryService.listAIConnectors).mockResolvedValueOnce([
        { id: "c-1", name: "Sonnet 4.5", actionTypeId: ".bedrock" },
        { id: "c-2", name: "GPT 5", actionTypeId: ".gen-ai" },
      ]);
      vi.mocked(
        attackDiscoveryService.generateAttackDiscovery
      ).mockResolvedValueOnce({ execution_uuid: "exec-99" });

      const out = await server.tool("generate-attack-discovery").callback({
        connectorName: "sonnet",
        size: 25,
        start: "now-1d",
        end: "now",
        filter: '{"match_all":{}}',
      });

      expect(
        attackDiscoveryService.generateAttackDiscovery
      ).toHaveBeenCalledWith({
        connectorId: "c-1",
        actionTypeId: ".bedrock",
        connectorName: "Sonnet 4.5",
        size: 25,
        start: "now-1d",
        end: "now",
        filter: { match_all: {} },
      });

      const body = parseToolText<{
        status: string;
        execution_uuid: string;
        connector: string;
      }>(out);
      expect(body).toMatchObject({
        status: "generation_started",
        execution_uuid: "exec-99",
        connector: "Sonnet 4.5",
      });
    });

    it("falls back to the only available connector when no name matches", async () => {
      vi.mocked(attackDiscoveryService.listAIConnectors).mockResolvedValueOnce([
        { id: "c-1", name: "Sonnet 4.5", actionTypeId: ".bedrock" },
      ]);
      vi.mocked(
        attackDiscoveryService.generateAttackDiscovery
      ).mockResolvedValueOnce({ execution_uuid: "exec-1" });

      await server.tool("generate-attack-discovery").callback({
        connectorName: "definitely-not-found",
      });

      expect(
        attackDiscoveryService.generateAttackDiscovery
      ).toHaveBeenCalledWith(
        expect.objectContaining({ connectorId: "c-1" })
      );
    });

    it("returns a helpful error payload when no connector matches and several are available", async () => {
      vi.mocked(attackDiscoveryService.listAIConnectors).mockResolvedValueOnce([
        { id: "c-1", name: "Sonnet", actionTypeId: ".bedrock" },
        { id: "c-2", name: "GPT", actionTypeId: ".gen-ai" },
      ]);

      const out = await server
        .tool("generate-attack-discovery")
        .callback({ connectorName: "claude" });

      expect(
        attackDiscoveryService.generateAttackDiscovery
      ).not.toHaveBeenCalled();
      const body = parseToolText<{ error: string }>(out);
      expect(body.error).toContain("No matching connector");
      expect(body.error).toContain("Sonnet");
      expect(body.error).toContain("GPT");
    });

    it("turns thrown errors into a wrapped {error} JSON envelope", async () => {
      vi.mocked(attackDiscoveryService.listAIConnectors).mockRejectedValueOnce(
        new Error("boom")
      );

      const out = await server
        .tool("generate-attack-discovery")
        .callback({ connectorName: "sonnet" });

      expect(parseToolText(out)).toEqual({ error: "boom" });
    });

    it("surfaces non-Error values via String() in the error envelope", async () => {
      vi.mocked(attackDiscoveryService.listAIConnectors).mockRejectedValueOnce(
        "weird-string-error"
      );

      const out = await server
        .tool("generate-attack-discovery")
        .callback({ connectorName: "sonnet" });

      expect(parseToolText(out)).toEqual({ error: "weird-string-error" });
    });
  });

  describe("get-generation-status", () => {
    it("forwards options and returns the raw envelope", async () => {
      vi.mocked(attackDiscoveryService.getGenerations).mockResolvedValueOnce({
        data: [],
      });
      const out = await server.tool("get-generation-status").callback({
        size: 5,
        start: "now-1d",
        end: "now",
      });
      expect(attackDiscoveryService.getGenerations).toHaveBeenCalledWith({
        size: 5,
        start: "now-1d",
        end: "now",
      });
      expect(parseToolText(out)).toEqual({ data: [] });
    });
  });

  describe("list-ai-connectors", () => {
    it("returns the connectors as JSON", async () => {
      const connectors = [
        { id: "c-1", name: "GPT", actionTypeId: ".gen-ai" },
      ];
      vi.mocked(attackDiscoveryService.listAIConnectors).mockResolvedValueOnce(
        connectors
      );

      const out = await server.tool("list-ai-connectors").callback({});
      expect(parseToolText(out)).toEqual(connectors);
    });
  });

  describe("UI resource", () => {
    it("reads and returns the bundled HTML view", async () => {
      const out = await server.resource(RESOURCE_URI).readCallback();
      expect(fs.readFileSync).toHaveBeenCalledTimes(1);
      expect(out).toEqual({
        contents: [
          {
            uri: RESOURCE_URI,
            mimeType: "text/html;profile=mcp-app",
            text: "<html>ad</html>",
          },
        ],
      });
    });
  });
});
