/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import {
  createMockMcpServer,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import { createMockSampleDataService } from "../test/helpers/mockServices.js";
import type { SampleDataService } from "../elastic/service/index.js";

const RESOURCE_URI = "ui://generate-sample-data/mcp-app.html";

/**
 * `sample-data.ts` carries module-scoped state (`_pendingRuleIdMap`) that
 * `create-rules-for-scenario` mutates and `generate-scenario` reads. We
 * dynamically re-import the module per test to keep that state isolated.
 */
async function setup(): Promise<{
  server: MockMcpServer;
  sampleDataService: SampleDataService;
}> {
  vi.resetModules();
  const { registerSampleDataTools } = await import("./sample-data.js");
  const server = createMockMcpServer();
  const sampleDataService = createMockSampleDataService();
  registerSampleDataTools(server as unknown as McpServer, { sampleDataService });
  return { server, sampleDataService };
}

describe("registerSampleDataTools", () => {
  beforeEach(() => {
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>sample</html>");
  });

  it("registers every sample-data tool plus the UI resource", async () => {
    const { server } = await setup();
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "generate-sample-data",
        "generate-scenario",
        "cleanup-sample-data",
        "create-rules-for-scenario",
        "check-existing-sample-data",
      ].sort()
    );
    expect([...server.resources.keys()]).toEqual([RESOURCE_URI]);
  });

  describe("generate-sample-data", () => {
    it("returns the static `ready` envelope listing every supported scenario", async () => {
      const { server } = await setup();
      const out = await server.tool("generate-sample-data").callback({});
      const body = parseToolText<{ status: string; scenarios: string[] }>(out);
      expect(body.status).toBe("ready");
      expect(body.scenarios).toContain("ransomware-kill-chain");
      expect(body.scenarios.length).toBeGreaterThan(5);
    });

    it("documents the supported scenarios in the tool description", async () => {
      const { server } = await setup();
      const description = server.tool("generate-sample-data").config.description;
      expect(description).toContain("ransomware-kill-chain");
    });
  });

  describe("generate-scenario", () => {
    it("forwards scenario + count without a rule id map by default", async () => {
      const { server, sampleDataService } = await setup();
      vi.mocked(sampleDataService.generateSampleData).mockResolvedValueOnce({
        indexed: 50,
        scenario: "ransomware-kill-chain",
        indices: ["logs-endpoint.events.process-default"],
      });

      const out = await server.tool("generate-scenario").callback({
        scenario: "ransomware-kill-chain",
        count: 50,
      });

      expect(sampleDataService.generateSampleData).toHaveBeenCalledWith({
        scenario: "ransomware-kill-chain",
        count: 50,
      });
      const body = parseToolText<{ indexed: number; scenario: string }>(out);
      expect(body.indexed).toBe(50);
    });

    it("includes the pending rule id map after create-rules-for-scenario populates it", async () => {
      const { server, sampleDataService } = await setup();
      vi.mocked(sampleDataService.createRulesForScenario).mockResolvedValueOnce(
        {
          created: 2,
          existing: 0,
          ruleIds: ["rid-1", "rid-2"],
          ruleIdMap: { "Rule A": "rid-1", "Rule B": "rid-2" },
        }
      );
      vi.mocked(sampleDataService.generateSampleData).mockResolvedValueOnce({
        indexed: 1,
        scenario: "ransomware-kill-chain",
        indices: [],
      });

      await server.tool("create-rules-for-scenario").callback({
        scenario: "ransomware-kill-chain",
      });
      await server.tool("generate-scenario").callback({
        scenario: "ransomware-kill-chain",
      });

      expect(sampleDataService.generateSampleData).toHaveBeenCalledWith({
        scenario: "ransomware-kill-chain",
        count: undefined,
        ruleIdMap: { "Rule A": "rid-1", "Rule B": "rid-2" },
      });
    });
  });

  describe("cleanup-sample-data", () => {
    it("delegates to SampleDataService.cleanupSampleData", async () => {
      const { server, sampleDataService } = await setup();
      vi.mocked(sampleDataService.cleanupSampleData).mockResolvedValueOnce({
        deleted: 123,
      });

      const out = await server.tool("cleanup-sample-data").callback({});
      expect(sampleDataService.cleanupSampleData).toHaveBeenCalled();
      expect(parseToolText(out)).toEqual({ deleted: 123 });
    });
  });

  describe("create-rules-for-scenario", () => {
    it("returns a no-op envelope without calling the service when no rule definitions exist for the scenario", async () => {
      const { server, sampleDataService } = await setup();

      const out = await server
        .tool("create-rules-for-scenario")
        .callback({ scenario: "scenario-without-rules" });

      expect(sampleDataService.createRulesForScenario).not.toHaveBeenCalled();
      expect(parseToolText(out)).toEqual({
        created: 0,
        ruleIds: [],
        message: "No rule definitions for this scenario",
      });
    });

    it("forwards the scenario name to SampleDataService and returns its result", async () => {
      const { server, sampleDataService } = await setup();
      vi.mocked(sampleDataService.createRulesForScenario).mockResolvedValueOnce(
        {
          created: 1,
          existing: 0,
          ruleIds: ["rid-1"],
          ruleIdMap: { "Rule A": "rid-1" },
        }
      );

      const out = await server
        .tool("create-rules-for-scenario")
        .callback({ scenario: "ransomware-kill-chain" });

      expect(sampleDataService.createRulesForScenario).toHaveBeenCalledWith(
        "ransomware-kill-chain"
      );
      const body = parseToolText<{
        created: number;
        ruleIds: string[];
      }>(out);
      expect(body.created).toBe(1);
      expect(body.ruleIds).toEqual(["rid-1"]);
    });
  });

  describe("check-existing-sample-data", () => {
    it("returns the existing-data report on success", async () => {
      const { server, sampleDataService } = await setup();
      vi.mocked(sampleDataService.checkExistingData).mockResolvedValueOnce({
        totalDocs: 100,
        totalAlerts: 5,
        existingRules: 2,
        byScenario: { "ransomware-kill-chain": { events: 100, alerts: 5 } },
      });

      const out = await server.tool("check-existing-sample-data").callback({});
      const body = parseToolText<{ totalDocs: number; totalAlerts: number }>(
        out
      );
      expect(body.totalDocs).toBe(100);
      expect(body.totalAlerts).toBe(5);
    });

    it("returns sane fallbacks when the lookup throws", async () => {
      const { server, sampleDataService } = await setup();
      vi.mocked(sampleDataService.checkExistingData).mockRejectedValueOnce(
        new Error("ES down")
      );

      const out = await server.tool("check-existing-sample-data").callback({});
      expect(parseToolText(out)).toEqual({
        totalDocs: 0,
        totalAlerts: 0,
        byScenario: {},
      });
    });
  });

  describe("UI resource", () => {
    it("reads and serves the bundled view", async () => {
      const { server } = await setup();
      const out = await server.resource(RESOURCE_URI).readCallback();
      expect(fs.readFileSync).toHaveBeenCalled();
      expect(out.contents[0].text).toBe("<html>sample</html>");
    });
  });
});
