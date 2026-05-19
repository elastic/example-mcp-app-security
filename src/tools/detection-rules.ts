/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppTool,
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import type { RulesService } from "../elastic/service/index.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://manage-rules/mcp-app.html";

const namespaceSchema = z
  .string()
  .optional()
  .describe(
    "Kibana space ID whose detection rules to act on (default: 'default'). Detection rules are space-scoped — a rule created in one space is invisible from others. Use `list-namespaces` to discover available spaces."
  );

/** Services the detection-rules tools depend on (default cluster only, for now). */
export interface DetectionRuleToolDeps {
  readonly rulesService: RulesService;
}

export function registerDetectionRuleTools(
  server: McpServer,
  deps: DetectionRuleToolDeps
) {
  const { rulesService } = deps;
  registerAppTool(
    server,
    "manage-rules",
    {
      title: "Manage Detection Rules",
      description:
        "Browse, search, and manage Elastic Security detection rules. Opens an interactive rule management dashboard for creating, editing, testing, and tuning detection rules.",
      inputSchema: {
        filter: z.string().optional().describe("KQL filter for rules"),
        page: z.number().optional(),
        perPage: z.number().optional(),
        namespace: namespaceSchema,
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ filter, page, perPage, namespace }) => {
      const result = await rulesService.findRules({
        filter,
        page,
        perPage,
        namespace,
      });
      const compact = {
        total: result.total,
        rules: result.data.slice(0, 20).map((r) => ({
          id: r.id, name: r.name, type: r.type, severity: r.severity,
          enabled: r.enabled, risk_score: r.risk_score,
          description: r.description?.substring(0, 200),
          query: r.query?.substring(0, 300),
          language: r.language,
          tags: r.tags?.slice(0, 10),
          threat: r.threat?.map((t: any) => ({
            tactic: t.tactic?.name,
            techniques: t.technique?.map((tech: any) => tech.id + ' ' + tech.name) || [],
          })),
        })),
        params: { filter, page, perPage, namespace },
      };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(compact) }],
      };
    }
  );

  registerAppTool(
    server,
    "find-rules",
    {
      title: "Find Rules",
      description: "Search detection rules",
      inputSchema: {
        filter: z.string().optional(),
        page: z.number().optional(),
        perPage: z.number().optional(),
        sortField: z.string().optional(),
        sortOrder: z.string().optional(),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async (args) => {
      const result = await rulesService.findRules(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "get-rule",
    {
      title: "Get Rule",
      description: "Get a specific detection rule",
      inputSchema: { id: z.string(), namespace: namespaceSchema },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ id, namespace }) => {
      const result = await rulesService.getRule(id, namespace);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "create-rule",
    {
      title: "Create Detection Rule",
      description: "Create a new detection rule from JSON configuration",
      inputSchema: {
        rule: z.string().describe("JSON-encoded rule configuration"),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ rule: ruleJson, namespace }) => {
      const ruleConfig = JSON.parse(ruleJson) as Record<string, unknown>;
      const result = await rulesService.createRule(ruleConfig, namespace);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "patch-rule",
    {
      title: "Patch Rule",
      description: "Update specific fields of a detection rule",
      inputSchema: {
        id: z.string(),
        updates: z.string().describe("JSON-encoded field updates"),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ id, updates, namespace }) => {
      const result = await rulesService.patchRule(
        id,
        JSON.parse(updates) as Record<string, unknown>,
        namespace
      );
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "toggle-rule",
    {
      title: "Toggle Rule",
      description: "Enable or disable a detection rule",
      inputSchema: {
        id: z.string(),
        enabled: z.boolean(),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ id, enabled, namespace }) => {
      const result = await rulesService.toggleRule(id, enabled, namespace);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "validate-query",
    {
      title: "Validate Query",
      description: "Test KQL, EQL, or ES|QL query syntax",
      inputSchema: {
        query: z.string(),
        language: z.enum(["kuery", "eql", "esql"]),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ query, language, namespace }) => {
      const result = await rulesService.validateQuery(
        query,
        language,
        namespace
      );
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "noisy-rules",
    {
      title: "Noisy Rules",
      description: "Find the noisiest detection rules by alert volume",
      inputSchema: {
        days: z.number().optional(),
        limit: z.number().optional(),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ days, limit, namespace }) => {
      const result = await rulesService.noisyRules({ days, limit, namespace });
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "manage-exceptions",
    {
      title: "Manage Exceptions",
      description: "Add or list rule exceptions",
      inputSchema: {
        action: z.enum(["list", "add"]),
        ruleId: z.string().optional().describe("Rule ID (for add)"),
        listId: z.string().describe("Exception list ID"),
        exception: z.string().optional().describe("JSON-encoded exception (for add)"),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ action, ruleId, listId, exception: exceptionJson, namespace }) => {
      if (action === "list") {
        const result = await rulesService.listExceptions(listId, namespace);
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
      }
      if (!ruleId || !exceptionJson) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: "ruleId and exception required for add" }) }] };
      }
      const result = await rulesService.addException(
        ruleId,
        listId,
        JSON.parse(exceptionJson),
        namespace
      );
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  const viewPath = resolveViewPath("detection-rules");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
