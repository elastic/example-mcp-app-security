/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { registerCaseManagementTools } from "./case-management.js";
import {
  createMockMcpServer,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import { createMockCasesService } from "../test/helpers/mockServices.js";
import type { CasesService } from "../elastic/service/index.js";
import type { KibanaCase } from "../shared/types.js";

const RESOURCE_URI = "ui://manage-cases/mcp-app.html";

function makeCase(overrides: Partial<KibanaCase> = {}): KibanaCase {
  return {
    id: "case-1",
    version: "v1",
    title: "Investigation",
    description: "long ".repeat(100),
    status: "open",
    severity: "low",
    tags: Array.from({ length: 15 }, (_, i) => `tag-${i}`),
    totalAlerts: 0,
    totalComment: 0,
    created_at: "2026-05-01T00:00:00Z",
    created_by: { username: "alice" },
    updated_at: "2026-05-01T00:00:00Z",
    connector: { id: "none", name: "none", type: ".none", fields: null },
    settings: { syncAlerts: true },
    ...overrides,
  };
}

describe("registerCaseManagementTools", () => {
  let server: MockMcpServer;
  let casesService: CasesService;

  beforeEach(() => {
    server = createMockMcpServer();
    casesService = createMockCasesService();
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>cases</html>");
    registerCaseManagementTools(server as unknown as McpServer, {
      casesService,
    });
  });

  it("registers every case-management tool plus the UI resource", () => {
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "manage-cases",
        "list-cases",
        "get-case",
        "create-case",
        "update-case",
        "add-case-comment",
        "attach-alert-to-case",
        "get-case-alerts",
        "get-case-comments",
        "get-user-profile",
      ].sort()
    );
    expect([...server.resources.keys()]).toEqual([RESOURCE_URI]);
  });

  describe("manage-cases", () => {
    it("forwards filter params and emits a compact response (truncated description, sliced tags, max 20 cases)", async () => {
      const cases = Array.from({ length: 25 }, (_, i) =>
        makeCase({ id: `case-${i}` })
      );
      vi.mocked(casesService.listCases).mockResolvedValueOnce({
        total: 25,
        cases,
        page: 1,
        perPage: 20,
      });

      const out = await server.tool("manage-cases").callback({
        status: "open",
        severity: "high",
        search: "ransomware",
      });

      expect(casesService.listCases).toHaveBeenCalledWith({
        status: "open",
        severity: "high",
        search: "ransomware",
      });

      const body = parseToolText<{
        total: number;
        cases: { id: string; description: string; tags: string[] }[];
        params: Record<string, unknown>;
      }>(out);
      expect(body.total).toBe(25);
      expect(body.cases).toHaveLength(20);
      expect(body.cases[0].description.length).toBe(300);
      expect(body.cases[0].tags).toHaveLength(10);
      expect(body.params).toEqual({
        status: "open",
        severity: "high",
        search: "ransomware",
      });
    });

    it("defaults missing description and tags gracefully", async () => {
      vi.mocked(casesService.listCases).mockResolvedValueOnce({
        total: 1,
        cases: [
          makeCase({
            description: undefined as unknown as KibanaCase["description"],
            tags: undefined as unknown as KibanaCase["tags"],
            created_by: { username: "alice" },
          }),
        ],
        page: 1,
        perPage: 20,
      });

      const out = await server.tool("manage-cases").callback({});
      const body = parseToolText<{
        cases: { description?: string; tags?: string[]; created_by?: string }[];
      }>(out);
      expect(body.cases[0].description).toBeUndefined();
      expect(body.cases[0].tags).toBeUndefined();
      expect(body.cases[0].created_by).toBe("alice");
    });
  });

  describe("list-cases", () => {
    it("splits comma-separated tags before forwarding to the service", async () => {
      vi.mocked(casesService.listCases).mockResolvedValueOnce({
        total: 0,
        cases: [],
        page: 1,
        perPage: 20,
      });

      await server.tool("list-cases").callback({
        tags: "alpha,beta,gamma",
        page: 2,
        perPage: 50,
      });

      expect(casesService.listCases).toHaveBeenCalledWith({
        status: undefined,
        severity: undefined,
        search: undefined,
        tags: ["alpha", "beta", "gamma"],
        page: 2,
        perPage: 50,
      });
    });

    it("passes undefined tags when none are provided", async () => {
      vi.mocked(casesService.listCases).mockResolvedValueOnce({
        total: 0,
        cases: [],
        page: 1,
        perPage: 20,
      });

      await server.tool("list-cases").callback({});

      expect(casesService.listCases).toHaveBeenCalledWith(
        expect.objectContaining({ tags: undefined })
      );
    });
  });

  describe("get-case", () => {
    it("fetches a single case by id", async () => {
      const c = makeCase();
      vi.mocked(casesService.getCase).mockResolvedValueOnce(c);
      const out = await server.tool("get-case").callback({ caseId: "case-1" });
      expect(casesService.getCase).toHaveBeenCalledWith("case-1");
      expect(parseToolText(out)).toEqual(c);
    });
  });

  describe("create-case", () => {
    it("splits comma-separated tags, creates the case, then attaches alerts", async () => {
      const created = makeCase({ id: "new-case" });
      vi.mocked(casesService.createCase).mockResolvedValueOnce(created);
      vi.mocked(casesService.attachAlertsByIds).mockResolvedValueOnce(2);

      const out = await server.tool("create-case").callback({
        title: "Suspicious activity",
        description: "details",
        tags: "ransomware,investigation",
        severity: "high",
        alertIds: ["a1", "a2"],
      });

      expect(casesService.createCase).toHaveBeenCalledWith({
        title: "Suspicious activity",
        description: "details",
        tags: ["ransomware", "investigation"],
        severity: "high",
      });
      expect(casesService.attachAlertsByIds).toHaveBeenCalledWith("new-case", [
        "a1",
        "a2",
      ]);

      const body = parseToolText<{ id: string; alertsAttached: number }>(out);
      expect(body.id).toBe("new-case");
      expect(body.alertsAttached).toBe(2);
    });

    it("attaches an empty array of alerts when alertIds is omitted", async () => {
      vi.mocked(casesService.createCase).mockResolvedValueOnce(
        makeCase({ id: "c-x" })
      );
      vi.mocked(casesService.attachAlertsByIds).mockResolvedValueOnce(0);

      await server.tool("create-case").callback({
        title: "t",
        description: "d",
      });

      expect(casesService.createCase).toHaveBeenCalledWith({
        title: "t",
        description: "d",
        tags: undefined,
        severity: undefined,
      });
      expect(casesService.attachAlertsByIds).toHaveBeenCalledWith("c-x", []);
    });
  });

  describe("update-case", () => {
    it("forwards id + version + parsed tags to CasesService.updateCase", async () => {
      vi.mocked(casesService.updateCase).mockResolvedValueOnce([
        makeCase({ id: "c-1" }),
      ]);

      await server.tool("update-case").callback({
        caseId: "c-1",
        version: "v2",
        status: "in-progress",
        severity: "critical",
        tags: "a,b",
      });

      expect(casesService.updateCase).toHaveBeenCalledWith("c-1", "v2", {
        status: "in-progress",
        severity: "critical",
        tags: ["a", "b"],
      });
    });

    it("passes undefined tags through unchanged when omitted", async () => {
      vi.mocked(casesService.updateCase).mockResolvedValueOnce([
        makeCase({ id: "c-1" }),
      ]);

      await server.tool("update-case").callback({
        caseId: "c-1",
        version: "v1",
      });

      expect(casesService.updateCase).toHaveBeenCalledWith("c-1", "v1", {
        status: undefined,
        severity: undefined,
        tags: undefined,
      });
    });
  });

  describe("add-case-comment", () => {
    it("posts a comment to the case", async () => {
      vi.mocked(casesService.addComment).mockResolvedValueOnce({ id: "x" });
      const out = await server
        .tool("add-case-comment")
        .callback({ caseId: "c-1", comment: "investigated" });

      expect(casesService.addComment).toHaveBeenCalledWith("c-1", "investigated");
      expect(parseToolText(out)).toEqual({ id: "x" });
    });
  });

  describe("attach-alert-to-case", () => {
    it("forwards every required field to the alert-attach call", async () => {
      vi.mocked(casesService.attachAlert).mockResolvedValueOnce({ id: "a-x" });

      await server.tool("attach-alert-to-case").callback({
        caseId: "c-1",
        alertId: "a-1",
        alertIndex: ".alerts-security",
        ruleId: "r-1",
        ruleName: "Suspicious",
      });

      expect(casesService.attachAlert).toHaveBeenCalledWith(
        "c-1",
        "a-1",
        ".alerts-security",
        "r-1",
        "Suspicious"
      );
    });
  });

  describe("get-case-alerts", () => {
    it("returns the enriched attachments on success", async () => {
      const attachments = [
        {
          id: "a-1",
          index: ".alerts-security",
          attached_at: "2026-05-01T00:00:00Z",
        },
      ];
      vi.mocked(casesService.getCaseAlerts).mockResolvedValueOnce(attachments);

      const out = await server
        .tool("get-case-alerts")
        .callback({ caseId: "c-1" });

      expect(casesService.getCaseAlerts).toHaveBeenCalledWith("c-1");
      expect(parseToolText(out)).toEqual(attachments);
    });

    it("swallows failures and returns an empty array", async () => {
      vi.mocked(casesService.getCaseAlerts).mockRejectedValueOnce(
        new Error("boom")
      );

      const out = await server
        .tool("get-case-alerts")
        .callback({ caseId: "c-1" });

      expect(parseToolText(out)).toEqual([]);
    });
  });

  describe("get-case-comments", () => {
    it("delegates to CasesService.getComments", async () => {
      vi.mocked(casesService.getComments).mockResolvedValueOnce({
        comments: [],
        total: 0,
      });

      await server.tool("get-case-comments").callback({ caseId: "c-1" });
      expect(casesService.getComments).toHaveBeenCalledWith("c-1");
    });
  });

  describe("get-user-profile", () => {
    it("returns the user profile on success", async () => {
      vi.mocked(casesService.getUserProfile).mockResolvedValueOnce({
        username: "alice",
        avatar: { initials: "A" },
      });

      const out = await server.tool("get-user-profile").callback({});
      expect(parseToolText(out)).toEqual({
        username: "alice",
        avatar: { initials: "A" },
      });
    });

    it("returns sane fallbacks when the lookup throws", async () => {
      vi.mocked(casesService.getUserProfile).mockRejectedValueOnce(
        new Error("kibana down")
      );

      const out = await server.tool("get-user-profile").callback({});
      expect(parseToolText(out)).toEqual({ username: "", avatar: {} });
    });
  });

  describe("UI resource", () => {
    it("reads the bundled HTML", async () => {
      const out = await server.resource(RESOURCE_URI).readCallback();
      expect(fs.readFileSync).toHaveBeenCalledTimes(1);
      expect(out.contents[0].text).toBe("<html>cases</html>");
    });
  });
});
