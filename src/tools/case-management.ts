import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppTool,
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import * as cases from "../elastic/cases.js";
import { esRequest } from "../elastic/client.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://manage-cases/mcp-app.html";

export function registerCaseManagementTools(server: McpServer) {
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
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ status, severity, search }) => {
      const result = await cases.listCases({ status, severity, search });
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
        params: { status, severity, search },
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
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ status, severity, search, tags, page, perPage }) => {
      const result = await cases.listCases({
        status,
        severity,
        search,
        tags: tags ? tags.split(",") : undefined,
        page,
        perPage,
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
      inputSchema: { caseId: z.string() },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId }) => {
      const result = await cases.getCase(caseId);
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
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ title, description, tags, severity, alertIds }) => {
      const result = await cases.createCase({
        title,
        description,
        tags: tags ? tags.split(",") : undefined,
        severity,
      });

      let alertsAttached = 0;
      if (alertIds && alertIds.length > 0) {
        try {
          const alertDocs = await esRequest<{
            docs: Array<{ _index: string; _id: string; found: boolean; _source?: Record<string, unknown> }>;
          }>("/.alerts-security.alerts-default/_mget", {
            body: { ids: alertIds },
          });

          for (const doc of alertDocs.docs) {
            if (!doc.found || !doc._source) continue;
            try {
              const ruleId = (doc._source["kibana.alert.rule.uuid"] as string) || "";
              const ruleName = (doc._source["kibana.alert.rule.name"] as string) || "Unknown Rule";
              await cases.attachAlert(result.id, doc._id, doc._index, ruleId, ruleName);
              alertsAttached++;
            } catch {
              // skip individual alert attachment failures
            }
          }
        } catch {
          // alert lookup failed — case still created
        }
      }

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
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId, version, status, severity, tags }) => {
      const result = await cases.updateCase(caseId, version, {
        status,
        severity,
        tags: tags ? tags.split(",") : undefined,
      });
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
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId, comment }) => {
      const result = await cases.addComment(caseId, comment);
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
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId, alertId, alertIndex, ruleId, ruleName }) => {
      const result = await cases.attachAlert(caseId, alertId, alertIndex, ruleId, ruleName);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "get-case-alerts",
    {
      title: "Get Case Alerts",
      description: "Fetch alerts attached to a case with their details",
      inputSchema: { caseId: z.string() },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId }) => {
      try {
        const attachments = await cases.getCaseAlerts(caseId);
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
      inputSchema: { caseId: z.string() },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ caseId }) => {
      const result = await cases.getComments(caseId);
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
        const result = await cases.getUserProfile();
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
      } catch {
        return { content: [{ type: "text" as const, text: JSON.stringify({ username: "", avatar: {} }) }] };
      }
    }
  );

  const viewPath = resolveViewPath("case-management");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
