/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { registerDetectionRuleTools } from "./detection-rules.js";
import {
  createMockMcpServer,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import { createMockRulesService } from "../test/helpers/mockServices.js";
import type { RulesService } from "../elastic/service/index.js";
import type { DetectionRule } from "../shared/types.js";

const RESOURCE_URI = "ui://manage-rules/mcp-app.html";

function makeRule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return {
    id: "r-1",
    rule_id: "rid-1",
    name: "Suspicious PowerShell",
    description: "x".repeat(500),
    severity: "high",
    risk_score: 73,
    type: "query",
    enabled: true,
    query: "*".repeat(400),
    language: "kuery",
    tags: Array.from({ length: 15 }, (_, i) => `tag-${i}`),
    created_at: "2026-05-01T00:00:00Z",
    updated_at: "2026-05-01T00:00:00Z",
    created_by: "alice",
    threat: [
      {
        framework: "MITRE ATT&CK",
        tactic: { id: "TA0001", name: "Initial Access", reference: "" },
        technique: [
          { id: "T1059", name: "Command and Scripting", reference: "" },
        ],
      },
    ],
    ...overrides,
  };
}

describe("registerDetectionRuleTools", () => {
  let server: MockMcpServer;
  let rulesService: RulesService;

  beforeEach(() => {
    server = createMockMcpServer();
    rulesService = createMockRulesService();
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>rules</html>");
    registerDetectionRuleTools(server as unknown as McpServer, { rulesService });
  });

  it("registers every detection-rules tool plus the UI resource", () => {
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "manage-rules",
        "find-rules",
        "get-rule",
        "create-rule",
        "patch-rule",
        "toggle-rule",
        "validate-query",
        "noisy-rules",
        "manage-exceptions",
      ].sort()
    );
    expect([...server.resources.keys()]).toEqual([RESOURCE_URI]);
  });

  describe("manage-rules", () => {
    it("forwards filter/page/perPage and shapes a compact response", async () => {
      const rules = Array.from({ length: 25 }, (_, i) =>
        makeRule({ id: `r-${i}` })
      );
      vi.mocked(rulesService.findRules).mockResolvedValueOnce({
        total: 25,
        data: rules,
        page: 1,
        perPage: 20,
      });

      const out = await server.tool("manage-rules").callback({
        filter: "type:query",
        page: 1,
        perPage: 20,
      });

      expect(rulesService.findRules).toHaveBeenCalledWith({
        filter: "type:query",
        page: 1,
        perPage: 20,
      });

      const body = parseToolText<{
        total: number;
        rules: {
          id: string;
          description: string;
          query: string;
          tags: string[];
          threat: { tactic: string; techniques: string[] }[];
        }[];
        params: Record<string, unknown>;
      }>(out);
      expect(body.total).toBe(25);
      expect(body.rules).toHaveLength(20);
      expect(body.rules[0].description.length).toBe(200);
      expect(body.rules[0].query.length).toBe(300);
      expect(body.rules[0].tags).toHaveLength(10);
      expect(body.rules[0].threat).toEqual([
        {
          tactic: "Initial Access",
          techniques: ["T1059 Command and Scripting"],
        },
      ]);
      expect(body.params).toEqual({
        filter: "type:query",
        page: 1,
        perPage: 20,
      });
    });

    it("falls back to an empty techniques array for tactics with no techniques", async () => {
      vi.mocked(rulesService.findRules).mockResolvedValueOnce({
        total: 1,
        data: [
          makeRule({
            threat: [
              {
                framework: "MITRE ATT&CK",
                tactic: { id: "TA0001", name: "Initial Access", reference: "" },
              },
            ],
          }),
        ],
        page: 1,
        perPage: 20,
      });

      const out = await server.tool("manage-rules").callback({});
      const body = parseToolText<{
        rules: { threat: { tactic: string; techniques: string[] }[] }[];
      }>(out);
      expect(body.rules[0].threat).toEqual([
        { tactic: "Initial Access", techniques: [] },
      ]);
    });

    it("tolerates missing optional fields on a rule", async () => {
      vi.mocked(rulesService.findRules).mockResolvedValueOnce({
        total: 1,
        data: [
          makeRule({
            description: undefined as unknown as string,
            query: undefined,
            tags: undefined,
            threat: undefined,
          }),
        ],
        page: 1,
        perPage: 20,
      });

      const out = await server.tool("manage-rules").callback({});
      const body = parseToolText<{
        rules: {
          description?: string;
          query?: string;
          tags?: string[];
          threat?: unknown;
        }[];
      }>(out);
      expect(body.rules[0].description).toBeUndefined();
      expect(body.rules[0].query).toBeUndefined();
      expect(body.rules[0].tags).toBeUndefined();
      expect(body.rules[0].threat).toBeUndefined();
    });
  });

  describe("find-rules", () => {
    it("forwards every search option to RulesService.findRules verbatim", async () => {
      vi.mocked(rulesService.findRules).mockResolvedValueOnce({
        total: 0,
        data: [],
        page: 1,
        perPage: 20,
      });

      await server.tool("find-rules").callback({
        filter: "tags:important",
        page: 3,
        perPage: 50,
        sortField: "name",
        sortOrder: "asc",
      });

      expect(rulesService.findRules).toHaveBeenCalledWith({
        filter: "tags:important",
        page: 3,
        perPage: 50,
        sortField: "name",
        sortOrder: "asc",
      });
    });
  });

  describe("get-rule", () => {
    it("delegates straight to RulesService.getRule", async () => {
      const rule = makeRule();
      vi.mocked(rulesService.getRule).mockResolvedValueOnce(rule);
      const out = await server.tool("get-rule").callback({ id: "r-1" });
      expect(rulesService.getRule).toHaveBeenCalledWith("r-1");
      expect(parseToolText(out)).toEqual(rule);
    });
  });

  describe("create-rule", () => {
    it("parses the JSON-encoded rule body and forwards it to RulesService.createRule", async () => {
      const rule = makeRule({ id: "new" });
      vi.mocked(rulesService.createRule).mockResolvedValueOnce(rule);

      const out = await server.tool("create-rule").callback({
        rule: JSON.stringify({ name: "x", type: "query" }),
      });

      expect(rulesService.createRule).toHaveBeenCalledWith({
        name: "x",
        type: "query",
      });
      expect(parseToolText(out)).toEqual(rule);
    });
  });

  describe("patch-rule", () => {
    it("parses updates JSON and forwards the patch to RulesService", async () => {
      vi.mocked(rulesService.patchRule).mockResolvedValueOnce(makeRule());

      await server.tool("patch-rule").callback({
        id: "r-1",
        updates: JSON.stringify({ name: "renamed", risk_score: 99 }),
      });

      expect(rulesService.patchRule).toHaveBeenCalledWith("r-1", {
        name: "renamed",
        risk_score: 99,
      });
    });
  });

  describe("toggle-rule", () => {
    it("forwards id + boolean to RulesService.toggleRule", async () => {
      vi.mocked(rulesService.toggleRule).mockResolvedValueOnce(
        makeRule({ enabled: false })
      );

      await server
        .tool("toggle-rule")
        .callback({ id: "r-1", enabled: false });

      expect(rulesService.toggleRule).toHaveBeenCalledWith("r-1", false);
    });
  });

  describe("validate-query", () => {
    it.each(["kuery", "eql", "esql"] as const)(
      "delegates validation for the %s language",
      async (language) => {
        vi.mocked(rulesService.validateQuery).mockResolvedValueOnce({
          valid: true,
        });

        const out = await server
          .tool("validate-query")
          .callback({ query: "host:foo", language });

        expect(rulesService.validateQuery).toHaveBeenCalledWith(
          "host:foo",
          language
        );
        expect(parseToolText(out)).toEqual({ valid: true });
      }
    );
  });

  describe("noisy-rules", () => {
    it("forwards days/limit and returns the aggregated rules", async () => {
      const noisy = [{ ruleName: "r1", ruleId: "rid-1", alertCount: 12 }];
      vi.mocked(rulesService.noisyRules).mockResolvedValueOnce(noisy);

      const out = await server
        .tool("noisy-rules")
        .callback({ days: 14, limit: 5 });

      expect(rulesService.noisyRules).toHaveBeenCalledWith({
        days: 14,
        limit: 5,
      });
      expect(parseToolText(out)).toEqual(noisy);
    });
  });

  describe("manage-exceptions", () => {
    it("lists exceptions when action is `list`", async () => {
      vi.mocked(rulesService.listExceptions).mockResolvedValueOnce({
        data: [],
        total: 0,
      });

      const out = await server.tool("manage-exceptions").callback({
        action: "list",
        listId: "exception-list-1",
      });

      expect(rulesService.listExceptions).toHaveBeenCalledWith(
        "exception-list-1"
      );
      expect(rulesService.addException).not.toHaveBeenCalled();
      expect(parseToolText(out)).toEqual({ data: [], total: 0 });
    });

    it("returns an error envelope when add is requested without ruleId or exception", async () => {
      const out = await server.tool("manage-exceptions").callback({
        action: "add",
        listId: "list-1",
      });

      expect(rulesService.addException).not.toHaveBeenCalled();
      expect(parseToolText(out)).toEqual({
        error: "ruleId and exception required for add",
      });
    });

    it("adds an exception when ruleId + exception JSON are provided", async () => {
      vi.mocked(rulesService.addException).mockResolvedValueOnce({ id: "ex-1" });

      const exception = {
        name: "test",
        entries: [
          { field: "host.name", operator: "included", type: "match", value: "x" },
        ],
      };
      const out = await server.tool("manage-exceptions").callback({
        action: "add",
        ruleId: "r-1",
        listId: "list-1",
        exception: JSON.stringify(exception),
      });

      expect(rulesService.addException).toHaveBeenCalledWith(
        "r-1",
        "list-1",
        exception
      );
      expect(parseToolText(out)).toEqual({ id: "ex-1" });
    });
  });

  describe("UI resource", () => {
    it("reads and serves the bundled view", async () => {
      const out = await server.resource(RESOURCE_URI).readCallback();
      expect(fs.readFileSync).toHaveBeenCalledTimes(1);
      expect(out.contents[0].text).toBe("<html>rules</html>");
    });
  });
});
