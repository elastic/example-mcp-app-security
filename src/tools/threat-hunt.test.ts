/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { registerThreatHuntTools } from "./threat-hunt.js";
import {
  createMockMcpServer,
  parseBootstrapToolText,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import {
  createMockEntityDetailService,
  createMockEsqlService,
  createMockIndicesService,
  createMockInvestigateService,
} from "../test/helpers/mockServices.js";
import { noopAnalyticsClient } from "../test/helpers/mockAnalytics.js";
import type {
  EntityDetailService,
  EsqlService,
  IndicesService,
  InvestigateService,
} from "../elastic/service/index.js";

const RESOURCE_URI = "ui://threat-hunt/mcp-app.html";

describe("registerThreatHuntTools", () => {
  let server: MockMcpServer;
  let esqlService: EsqlService;
  let indicesService: IndicesService;
  let investigateService: InvestigateService;
  let entityDetailService: EntityDetailService;

  beforeEach(() => {
    server = createMockMcpServer();
    esqlService = createMockEsqlService();
    indicesService = createMockIndicesService();
    investigateService = createMockInvestigateService();
    entityDetailService = createMockEntityDetailService();
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>hunt</html>");
    registerThreatHuntTools(server as unknown as McpServer, {
      esqlService,
      indicesService,
      investigateService,
      entityDetailService,
      analytics: noopAnalyticsClient,
    });
  });

  it("registers every threat-hunt tool plus the UI resource", () => {
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "threat-hunt",
        "execute-esql",
        "list-indices",
        "get-mapping",
        "get-entity-detail",
        "investigate-entity",
      ].sort()
    );
    expect([...server.resources.keys()]).toEqual([RESOURCE_URI]);
  });

  describe("threat-hunt", () => {
    it("returns a bootstrap payload listing the first 20 indices", async () => {
      vi.mocked(indicesService.listIndices).mockResolvedValueOnce(
        Array.from({ length: 25 }, (_, i) => ({
          index: `idx-${i}`,
          health: "green",
          status: "open",
          docsCount: "100",
          storeSize: "1mb",
        }))
      );

      const out = await server.tool("threat-hunt").callback({});

      const body = parseBootstrapToolText(out, "threat-hunt");
      expect(body.indexCount).toBe(25);
      expect(body.indices).toHaveLength(20);
      expect(body.indices[0]).toBe("idx-0");
    });

    it("executes the supplied query and includes the ES|QL result in the bootstrap payload", async () => {
      vi.mocked(indicesService.listIndices).mockResolvedValueOnce([]);
      vi.mocked(esqlService.executeEsql).mockResolvedValueOnce({
        columns: [{ name: "host", type: "keyword" }],
        values: Array.from({ length: 30 }, (_, i) => [
          i === 0 ? "x".repeat(150) : i === 1 ? null : i === 2 ? { a: 1 } : `host-${i}`,
        ]),
      });

      const out = await server.tool("threat-hunt").callback({
        query: "FROM logs-* | LIMIT 30",
        description: "look for foo",
      });

      const body = parseBootstrapToolText(out, "threat-hunt");
      expect(body.params.query).toBe("FROM logs-* | LIMIT 30");
      expect(body.params.description).toBe("look for foo");
      expect(body.queryResult).toEqual({
        rowCount: 30,
        columns: ["host"],
        rows: Array.from({ length: 20 }, (_, i) => [
          i === 0
            ? `${"x".repeat(100)}...`
            : i === 1
              ? null
              : i === 2
                ? "{\"a\":1}"
                : `host-${i}`,
        ]),
      });
    });

    it("captures query errors in `queryError` rather than throwing", async () => {
      vi.mocked(indicesService.listIndices).mockResolvedValueOnce([]);
      vi.mocked(esqlService.executeEsql).mockRejectedValueOnce(
        new Error("syntax error at line 1")
      );

      const out = await server
        .tool("threat-hunt")
        .callback({ query: "FROM bogus" });

      const body = parseBootstrapToolText(out, "threat-hunt");
      expect(body.params.query).toBe("FROM bogus");
      expect(body.queryError).toBe("syntax error at line 1");
    });

    it("stringifies non-Error query failures via String()", async () => {
      vi.mocked(indicesService.listIndices).mockResolvedValueOnce([]);
      vi.mocked(esqlService.executeEsql).mockRejectedValueOnce("network blip");

      const out = await server
        .tool("threat-hunt")
        .callback({ query: "FROM bogus" });

      const body = parseBootstrapToolText(out, "threat-hunt");
      expect(body.queryError).toBe("network blip");
    });

    it("includes investigation graph stats when an entity is supplied", async () => {
      vi.mocked(indicesService.listIndices).mockResolvedValueOnce([]);
      vi.mocked(investigateService.investigateEntity).mockResolvedValueOnce({
        nodes: [
          { id: "n1", type: "host", value: "host-1" },
          { id: "n2", type: "user", value: "alice" },
        ],
        edges: [{ source: "n1", target: "n2", label: "logged-in" }],
      });

      const out = await server.tool("threat-hunt").callback({
        entity: { type: "host", value: "host-1" },
      });

      expect(investigateService.investigateEntity).toHaveBeenCalledWith(
        "host",
        "host-1"
      );
      const body = parseBootstrapToolText(out, "threat-hunt");
      expect(body.params.entity).toEqual({ type: "host", value: "host-1" });
      expect(body.entityGraph).toEqual({ nodeCount: 2, edgeCount: 1 });
    });

    it("swallows entity-investigation failures rather than failing the whole hunt", async () => {
      vi.mocked(indicesService.listIndices).mockResolvedValueOnce([]);
      vi.mocked(investigateService.investigateEntity).mockRejectedValueOnce(
        new Error("ES timeout")
      );

      const out = await server.tool("threat-hunt").callback({
        entity: { type: "user", value: "alice" },
      });

      const body = parseToolText<{ graph?: unknown; entity?: unknown }>(out);
      expect(body.graph).toBeUndefined();
      expect(body.entity).toBeUndefined();
    });
  });

  describe("execute-esql", () => {
    it("returns the EsqlResult on success", async () => {
      const result = { columns: [], values: [] };
      vi.mocked(esqlService.executeEsql).mockResolvedValueOnce(result);

      const out = await server
        .tool("execute-esql")
        .callback({ query: "FROM logs-*" });

      expect(esqlService.executeEsql).toHaveBeenCalledWith("FROM logs-*");
      expect(parseToolText(out)).toEqual(result);
    });

    it("wraps errors in {error} rather than throwing", async () => {
      vi.mocked(esqlService.executeEsql).mockRejectedValueOnce(
        new Error("boom")
      );

      const out = await server
        .tool("execute-esql")
        .callback({ query: "FROM logs-*" });

      expect(parseToolText(out)).toEqual({ error: "boom" });
    });

    it("stringifies non-Error rejections via String()", async () => {
      vi.mocked(esqlService.executeEsql).mockRejectedValueOnce("weird error");

      const out = await server
        .tool("execute-esql")
        .callback({ query: "FROM logs-*" });

      expect(parseToolText(out)).toEqual({ error: "weird error" });
    });
  });

  describe("list-indices", () => {
    it("forwards the optional pattern", async () => {
      vi.mocked(indicesService.listIndices).mockResolvedValueOnce([]);

      await server.tool("list-indices").callback({ pattern: "logs-*" });

      expect(indicesService.listIndices).toHaveBeenCalledWith("logs-*");
    });

    it("calls listIndices with undefined when no pattern is provided", async () => {
      vi.mocked(indicesService.listIndices).mockResolvedValueOnce([]);

      await server.tool("list-indices").callback({});

      expect(indicesService.listIndices).toHaveBeenCalledWith(undefined);
    });
  });

  describe("get-mapping", () => {
    it("delegates to IndicesService.getMapping", async () => {
      vi.mocked(indicesService.getMapping).mockResolvedValueOnce({
        "host.name": { type: "keyword" },
      });

      const out = await server
        .tool("get-mapping")
        .callback({ index: "logs-*" });

      expect(indicesService.getMapping).toHaveBeenCalledWith("logs-*");
      expect(parseToolText(out)).toEqual({ "host.name": { type: "keyword" } });
    });
  });

  describe("get-entity-detail", () => {
    it("forwards type + value to EntityDetailService", async () => {
      const detail = { type: "user", value: "alice", fields: [] };
      vi.mocked(entityDetailService.getEntityDetail).mockResolvedValueOnce(
        detail
      );

      const out = await server.tool("get-entity-detail").callback({
        entityType: "user",
        entityValue: "alice",
      });

      expect(entityDetailService.getEntityDetail).toHaveBeenCalledWith(
        "user",
        "alice"
      );
      expect(parseToolText(out)).toEqual(detail);
    });
  });

  describe("investigate-entity", () => {
    it("forwards type/value/timeRange to InvestigateService", async () => {
      const graph = { nodes: [], edges: [] };
      vi.mocked(investigateService.investigateEntity).mockResolvedValueOnce(
        graph
      );

      const out = await server.tool("investigate-entity").callback({
        entityType: "host",
        entityValue: "host-1",
        timeRange: "now-3d",
      });

      expect(investigateService.investigateEntity).toHaveBeenCalledWith(
        "host",
        "host-1",
        "now-3d"
      );
      expect(parseToolText(out)).toEqual(graph);
    });
  });

  describe("UI resource", () => {
    it("reads and serves the bundled view", async () => {
      const out = await server.resource(RESOURCE_URI).readCallback();
      expect(fs.readFileSync).toHaveBeenCalled();
      expect(out.contents[0].text).toBe("<html>hunt</html>");
    });
  });
});
