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
import type {
  EntityDetailService,
  EsqlService,
  IndicesService,
  InvestigateService,
} from "../elastic/service/index.js";
import { createMcpAppBootstrap } from "../shared/mcp-app-bootstrap.js";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import { registerTrackedAppTool } from "./tracked-app-tool.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://threat-hunt/mcp-app.html";

export interface ThreatHuntToolDeps {
  readonly esqlService: EsqlService;
  readonly indicesService: IndicesService;
  readonly investigateService: InvestigateService;
  readonly entityDetailService: EntityDetailService;
  readonly analytics: AnalyticsClient;
}

export function registerThreatHuntTools(
  server: McpServer,
  deps: ThreatHuntToolDeps
) {
  const { esqlService, indicesService, investigateService, entityDetailService, analytics } = deps;
  registerTrackedAppTool(
    analytics,
    server,
    "threat-hunt",
    {
      title: "Threat Hunt Workbench",
      description:
        "Open an interactive ES|QL query workbench for threat hunting. Explore indices, inspect field mappings, write and execute queries, and visualize results.",
      inputSchema: {
        query: z.string().optional().describe("Pre-populated ES|QL query"),
        description: z.string().optional().describe("Description of what to hunt for"),
        entity: z.object({
          type: z.enum(["user", "host", "ip", "process"]),
          value: z.string(),
        }).optional().describe("Start investigation centered on this entity. The UI renders an interactive graph showing related users, hosts, processes, IPs, and alerts."),
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ query, description, entity }) => {
      const indices = await indicesService.listIndices();
      const payload: {
        indexCount: number;
        indices: string[];
        params: { query?: string; description?: string; entity?: typeof entity };
        queryResult?: {
          columns: string[];
          rows: (string | number | boolean | null)[][];
          rowCount: number;
        };
        queryError?: string;
        entityGraph?: { nodeCount: number; edgeCount: number };
      } = {
        indexCount: indices.length,
        indices: indices.slice(0, 20).map((i) => i.index),
        params: { query, description, entity },
      };
      if (query) {
        try {
          const qr = await esqlService.executeEsql(query);
          payload.queryResult = {
            rowCount: qr.values.length,
            columns: qr.columns.map((c) => c.name),
            rows: qr.values.slice(0, 20).map((row) =>
              row.map((cell) => {
                if (cell === null || cell === undefined) return null;
                const value =
                  typeof cell === "string" ||
                  typeof cell === "number" ||
                  typeof cell === "boolean"
                    ? cell
                    : JSON.stringify(cell);
                const s = typeof value === "string" ? value : String(value);
                return s.length > 100 ? `${s.substring(0, 100)}...` : value;
              }),
            ),
          };
        } catch (e) {
          payload.queryError = e instanceof Error ? e.message : String(e);
        }
      }
      if (entity) {
        try {
          const graph = await investigateService.investigateEntity(entity.type, entity.value);
          payload.entityGraph = { nodeCount: graph.nodes.length, edgeCount: graph.edges.length };
        } catch { /* ignore */ }
      }
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(createMcpAppBootstrap("threat-hunt", payload)),
        }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "execute-esql",
    {
      title: "Execute ES|QL",
      description:
        "Run an ES|QL query. Uses Elasticsearch async ES|QL so frozen-tier and other long-running queries can complete.",
      inputSchema: { query: z.string() },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ query }) => {
      try {
        const result = await esqlService.executeEsql(query);
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
      } catch (e) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: e instanceof Error ? e.message : String(e) }) }],
        };
      }
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "list-indices",
    {
      title: "List Indices",
      description: "List available Elasticsearch indices",
      inputSchema: {
        pattern: z.string().optional().describe("Index pattern (default: logs-*,.alerts-security*)"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ pattern }) => {
      const result = await indicesService.listIndices(pattern);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "get-mapping",
    {
      title: "Get Index Mapping",
      description: "Get field mappings for an index",
      inputSchema: { index: z.string() },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ index }) => {
      const result = await indicesService.getMapping(index);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "get-entity-detail",
    {
      title: "Get Entity Detail",
      description: "Fetch detailed information about an entity from Elasticsearch",
      inputSchema: {
        entityType: z.enum(["user", "host", "ip", "process", "alert"]),
        entityValue: z.string(),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ entityType, entityValue }) => {
      const result = await entityDetailService.getEntityDetail(entityType, entityValue);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "investigate-entity",
    {
      title: "Investigate Entity",
      description: "Expand an entity in the investigation graph — returns related users, hosts, processes, IPs, and alerts",
      inputSchema: {
        entityType: z.enum(["user", "host", "ip", "process"]),
        entityValue: z.string(),
        timeRange: z.string().optional().describe("Time range (default: now-7d)"),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ entityType, entityValue, timeRange }) => {
      const result = await investigateService.investigateEntity(entityType, entityValue, timeRange);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result) }],
      };
    }
  );

  const viewPath = resolveViewPath("threat-hunt");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
