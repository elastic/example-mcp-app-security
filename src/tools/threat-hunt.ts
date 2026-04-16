/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppTool,
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import { executeEsql } from "../elastic/esql.js";
import { listIndices, getMapping } from "../elastic/indices.js";
import { investigateEntity } from "../elastic/investigate.js";
import { getEntityDetail } from "../elastic/entity-detail.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://threat-hunt/mcp-app.html";

export function registerThreatHuntTools(server: McpServer) {
  registerAppTool(
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
      const indices = await listIndices();
      const compact: Record<string, unknown> = {
        indexCount: indices.length,
        indices: indices.slice(0, 20).map((i) => i.index),
      };
      if (query) {
        try {
          const qr = await executeEsql(query);
          compact.query = query;
          compact.rowCount = qr.values.length;
          compact.columns = qr.columns.map((c) => c.name);
          compact.rows = qr.values.slice(0, 20).map((row) =>
            row.map((cell) => {
              if (cell === null || cell === undefined) return null;
              const s = typeof cell === "object" ? JSON.stringify(cell) : String(cell);
              return s.length > 100 ? s.substring(0, 100) + "..." : s;
            })
          );
        } catch (e) {
          compact.query = query;
          compact.queryError = e instanceof Error ? e.message : String(e);
        }
      }
      if (description) compact.description = description;
      if (entity) {
        try {
          const graph = await investigateEntity(entity.type, entity.value);
          compact.entity = entity;
          compact.graph = { nodeCount: graph.nodes.length, edgeCount: graph.edges.length };
        } catch { /* ignore */ }
      }
      compact.params = { query, description, entity };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(compact) }],
      };
    }
  );

  registerAppTool(
    server,
    "execute-esql",
    {
      title: "Execute ES|QL",
      description: "Run an ES|QL query",
      inputSchema: { query: z.string() },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ query }) => {
      try {
        const result = await executeEsql(query);
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
      } catch (e) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify({ error: e instanceof Error ? e.message : String(e) }) }],
        };
      }
    }
  );

  registerAppTool(
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
      const result = await listIndices(pattern);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "get-mapping",
    {
      title: "Get Index Mapping",
      description: "Get field mappings for an index",
      inputSchema: { index: z.string() },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ index }) => {
      const result = await getMapping(index);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
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
      const result = await getEntityDetail(entityType, entityValue);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
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
      const result = await investigateEntity(entityType, entityValue, timeRange);
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
