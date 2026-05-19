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
import type {
  CasesService,
  SpacesService,
} from "../elastic/service/index.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://manage-cases/mcp-app.html";

const namespaceSchema = z
  .string()
  .optional()
  .describe(
    "Kibana space ID to scope the action to (default: 'default'). Must match the space the case lives in; for tools that touch alerts, also doubles as the Security alerts index namespace."
  );

/** Services the case-management tools depend on (default cluster only, for now). */
export interface CaseManagementToolDeps {
  readonly casesService: CasesService;
  readonly spacesService: SpacesService;
}

export function registerCaseManagementTools(
  server: McpServer,
  deps: CaseManagementToolDeps
) {
  const { casesService, spacesService } = deps;
  registerAppTool(
    server,
    "manage-cases",
    {
      title: "Manage Security Cases",
      description:
        "Browse, search, and manage Elastic Security cases. Opens an interactive case management dashboard for creating cases, tracking investigations, and linking alerts.",
      inputSchema: {
        status: z.enum(["open", "in-progress", "closed"]).optional().describe("Filter by status"),
        severity: z.enum(["low", "medium", "high", "critical"]).optional().describe("Filter by severity"),
        search: z.string().optional().describe("Search text"),
        namespace: namespaceSchema,
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ status, severity, search, namespace }) => {
      const result = await casesService.listCases({
        status,
        severity,
        search,
        namespace,
      });
      const compact = {
        total: result.total,
        cases: result.cases.slice(0, 20).map((c) => ({
          id: c.id, title: c.title, status: c.status, severity: c.severity,
          totalAlerts: c.totalAlerts, totalComment: c.totalComment,
          tags: c.tags?.slice(0, 10),
          description: c.description?.substring(0, 300),
          created_at: c.created_at, updated_at: c.updated_at,
          created_by: c.created_by?.username,
        })),
        params: { status, severity, search, namespace },
      };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(compact) }],
      };
    }
  );

  registerAppTool(
    server,
    "list-cases",
    {
      title: "List Cases",
      description: "List cases with filters",
      inputSchema: {
        status: z.string().optional(),
        severity: z.string().optional(),
        search: z.string().optional(),
        tags: z.string().optional().describe("Comma-separated tags"),
        page: z.number().optional(),
        perPage: z.number().optional(),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ status, severity, search, tags, page, perPage, namespace }) => {
      const result = await casesService.listCases({
        status,
        severity,
        search,
        tags: tags ? tags.split(",") : undefined,
        page,
        perPage,
        namespace,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "get-case",
    {
      title: "Get Case",
      description: "Get a specific case by ID",
      inputSchema: { caseId: z.string(), namespace: namespaceSchema },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId, namespace }) => {
      const result = await casesService.getCase(caseId, namespace);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "create-case",
    {
      title: "Create Case",
      description: "Create a new security case. Call this directly to create cases from attack discoveries or alert triage findings. Pass alertIds to automatically attach alerts to the case.",
      inputSchema: {
        title: z.string(),
        description: z.string(),
        tags: z.string().optional().describe("Comma-separated tags"),
        severity: z.string().optional(),
        alertIds: z.array(z.string()).optional().describe("Alert document IDs to attach to the case"),
        namespace: namespaceSchema,
      },
      _meta: { ui: {} },
    },
    async ({ title, description, tags, severity, alertIds, namespace }) => {
      const result = await casesService.createCase({
        title,
        description,
        tags: tags ? tags.split(",") : undefined,
        severity,
        namespace,
      });

      const alertsAttached = await casesService.attachAlertsByIds(
        result.id,
        alertIds || [],
        namespace
      );

      return { content: [{ type: "text" as const, text: JSON.stringify({ ...result, alertsAttached }) }] };
    }
  );

  registerAppTool(
    server,
    "update-case",
    {
      title: "Update Case",
      description: "Update case status, severity, or tags",
      inputSchema: {
        caseId: z.string(),
        version: z.string(),
        status: z.string().optional(),
        severity: z.string().optional(),
        tags: z.string().optional().describe("Comma-separated tags"),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId, version, status, severity, tags, namespace }) => {
      const result = await casesService.updateCase(
        caseId,
        version,
        {
          status,
          severity,
          tags: tags ? tags.split(",") : undefined,
        },
        namespace
      );
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "add-case-comment",
    {
      title: "Add Case Comment",
      description: "Add investigation notes to a case",
      inputSchema: {
        caseId: z.string(),
        comment: z.string(),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId, comment, namespace }) => {
      const result = await casesService.addComment(caseId, comment, namespace);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "attach-alert-to-case",
    {
      title: "Attach Alert to Case",
      description: "Link an alert to a case",
      inputSchema: {
        caseId: z.string(),
        alertId: z.string(),
        alertIndex: z.string(),
        ruleId: z.string(),
        ruleName: z.string(),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId, alertId, alertIndex, ruleId, ruleName, namespace }) => {
      const result = await casesService.attachAlert(
        caseId,
        alertId,
        alertIndex,
        ruleId,
        ruleName,
        namespace
      );
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "get-case-alerts",
    {
      title: "Get Case Alerts",
      description: "Fetch alerts attached to a case with their details",
      inputSchema: { caseId: z.string(), namespace: namespaceSchema },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId, namespace }) => {
      try {
        const attachments = await casesService.getCaseAlerts(caseId, namespace);
        return { content: [{ type: "text" as const, text: JSON.stringify(attachments) }] };
      } catch {
        return { content: [{ type: "text" as const, text: JSON.stringify([]) }] };
      }
    }
  );

  registerAppTool(
    server,
    "get-case-comments",
    {
      title: "Get Case Comments",
      description: "Fetch comments for a case",
      inputSchema: { caseId: z.string(), namespace: namespaceSchema },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId, namespace }) => {
      const result = await casesService.getComments(caseId, namespace);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "get-user-profile",
    {
      title: "Get User Profile",
      description: "Fetch the current user's Kibana profile including avatar",
      inputSchema: {},
      _meta: { ui: { visibility: ["app"] } },
    },
    async () => {
      try {
        const result = await casesService.getUserProfile();
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
      } catch {
        return { content: [{ type: "text" as const, text: JSON.stringify({ username: "", avatar: {} }) }] };
      }
    }
  );

  registerAppTool(
    server,
    "list-namespaces",
    {
      title: "List Available Namespaces (Kibana Spaces)",
      description:
        "List the Kibana spaces (namespaces) the API key can see. Call this before fanning out case tools across a deployment — e.g. when the user asks for 'all open cases in the deployment' or otherwise wants a view that isn't scoped to a single space. Returns one entry per space: { id, name, description? }. Pass the `id` as the `namespace` parameter on subsequent case tool calls.",
      inputSchema: {},
      _meta: { ui: {} },
    },
    async () => {
      const spaces = await spacesService.listSpaces();
      return {
        content: [{ type: "text" as const, text: JSON.stringify(spaces) }],
      };
    }
  );

  const viewPath = resolveViewPath("case-management");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
