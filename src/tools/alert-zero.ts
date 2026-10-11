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
import { createMcpAppBootstrap } from "../shared/mcp-app-bootstrap.js";
import {
  ALERT_ZERO_CATEGORIES,
  DISMISS_REASONS,
  PROPOSAL_SCOPES,
  type AlertZeroInvestigation,
  type AlertZeroLinks,
  type AlertZeroProposalDetail,
  type AlertZeroServiceApi,
  type EnrichedAlert,
  type InvestigationMetadata,
  type ProposalWithMetadata,
  type ResolvedUser,
} from "../shared/alert-zero-types.js";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import { registerTrackedAppTool } from "./tracked-app-tool.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://review-alert-zero-proposals/mcp-app.html";

const CATEGORY_FILTERS = ["all", ...ALERT_ZERO_CATEGORIES] as const;

const NARRATION_MAX = 1500;
const ATTACHMENT_DATA_MAX = 2000;
const ROUND_INPUT_MAX = 1500;
const ROUND_RESPONSE_MAX = 3000;
const TOOL_PARAMS_MAX = 500;

const spaceIdSchema = z
  .string()
  .optional()
  .describe("Kibana space id; defaults to the default space");

const scopeSchema = z
  .enum(PROPOSAL_SCOPES)
  .optional()
  .describe(
    "all = everything awaiting a decision in the space (default); mine = proposals on investigations assigned to the current user; unassigned = proposals on investigations with no assignee",
  );

const categorySchema = z
  .enum(CATEGORY_FILTERS)
  .optional()
  .describe("Alert Zero queue category to show (default: all)");

const rationaleSchema = z
  .string()
  .max(4096)
  .optional()
  .describe("Optional note recorded with the decision");

export interface AlertZeroToolDeps {
  readonly alertZeroService: AlertZeroServiceApi;
  readonly analytics: AnalyticsClient;
}

export interface ProposalRevisionSummary {
  readonly id: string;
  readonly title: string;
  readonly status: ProposalWithMetadata["status"];
  readonly decision?: ProposalWithMetadata["decision"];
  readonly revision?: number;
  readonly createdAt: string;
  readonly decidedAt?: string;
  readonly decidedBy?: ProposalWithMetadata["decidedBy"];
  readonly dismissReason?: ProposalWithMetadata["dismissReason"];
  readonly executionError?: string;
}

export interface InvestigationDigest {
  readonly id: string;
  readonly title?: string;
  readonly agentId?: string;
  readonly metadata?: InvestigationMetadata;
  readonly assignees: readonly ResolvedUser[];
  readonly narration: readonly { at: string; actor?: string; message: string }[];
  readonly attachmentEvents: readonly {
    at: string;
    type: string;
    attachment_type?: string;
    attachment_id?: string;
  }[];
  readonly attachments: readonly {
    id: string;
    type: string;
    description?: string;
    current_version: number;
    active?: boolean;
    origin?: string;
    data: string;
    truncated?: true;
  }[];
  readonly rounds: readonly {
    started_at?: string;
    status?: string;
    input?: string;
    response?: string;
    toolCalls: readonly { tool_id?: string; params?: string; resultTypes: readonly string[] }[];
    reasoningCount: number;
  }[];
  readonly alerts: Record<string, EnrichedAlert>;
}

export interface ProposalDigest {
  readonly proposal: AlertZeroProposalDetail["proposal"];
  readonly revisionChain: readonly ProposalRevisionSummary[];
  readonly siblings: readonly ProposalRevisionSummary[];
  readonly ruleContext?: AlertZeroProposalDetail["ruleContext"];
  readonly canDecide: boolean;
  readonly investigation?: InvestigationDigest;
  readonly links: AlertZeroLinks;
}

function truncateText(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…[+${text.length - max} chars]` : text;
}

function toJsonText(value: unknown): string {
  if (value === undefined) return "";
  return typeof value === "string" ? value : JSON.stringify(value);
}

function summarizeRevision(p: ProposalWithMetadata): ProposalRevisionSummary {
  return {
    id: p.id,
    title: p.title,
    status: p.status,
    decision: p.decision,
    revision: p.revision,
    createdAt: p.createdAt,
    decidedAt: p.decidedAt,
    decidedBy: p.decidedBy,
    dismissReason: p.dismissReason,
    executionError: p.executionError,
  };
}

function digestInvestigation(investigation: AlertZeroInvestigation): InvestigationDigest {
  const { conversation, assignees, alerts } = investigation;
  const events = conversation.events ?? [];
  return {
    id: conversation.id,
    title: conversation.title,
    agentId: conversation.agent_id,
    metadata: conversation.metadata,
    assignees,
    narration: events
      .filter((e) => e.type === "user_message")
      .map((e) => ({
        at: e.created_at,
        actor: e.actor?.username ?? e.actor?.type,
        message: truncateText(toJsonText(e.data?.message), NARRATION_MAX),
      })),
    attachmentEvents: events
      .filter((e) => e.type.startsWith("attachment_"))
      .map((e) => ({
        at: e.created_at,
        type: e.type,
        attachment_type: typeof e.data?.attachment_type === "string" ? e.data.attachment_type : undefined,
        attachment_id: typeof e.data?.attachment_id === "string" ? e.data.attachment_id : undefined,
      })),
    attachments: (conversation.attachments ?? []).map((a) => {
      const current =
        a.versions.find((v) => v.version === a.current_version) ?? a.versions[a.versions.length - 1];
      const raw = toJsonText(current?.data);
      const truncated = raw.length > ATTACHMENT_DATA_MAX;
      return {
        id: a.id,
        type: a.type,
        description: a.description,
        current_version: a.current_version,
        active: a.active,
        origin: a.origin,
        data: truncated ? raw.slice(0, ATTACHMENT_DATA_MAX) : raw,
        ...(truncated ? { truncated: true as const } : {}),
      };
    }),
    rounds: (conversation.rounds ?? []).map((r) => {
      const steps = r.steps ?? [];
      return {
        started_at: r.started_at,
        status: r.status,
        input: r.input?.message === undefined ? undefined : truncateText(r.input.message, ROUND_INPUT_MAX),
        response:
          r.response?.message === undefined ? undefined : truncateText(r.response.message, ROUND_RESPONSE_MAX),
        toolCalls: steps
          .filter((s) => s.type === "tool_call")
          .map((s) => ({
            tool_id: s.tool_id,
            params: s.params === undefined ? undefined : truncateText(JSON.stringify(s.params), TOOL_PARAMS_MAX),
            resultTypes: (s.results ?? []).map((res) => res.type),
          })),
        reasoningCount: steps.filter((s) => s.type === "reasoning").length,
      };
    }),
    alerts,
  };
}

/**
 * Bounded, LLM-facing view of a proposal: the proposal record is kept whole,
 * only the investigation's free-text activity and attachment bodies are
 * truncated.
 */
export function buildProposalDigest(
  detail: AlertZeroProposalDetail,
  investigation?: AlertZeroInvestigation,
): ProposalDigest {
  return {
    proposal: detail.proposal,
    revisionChain: detail.revisionChain.map(summarizeRevision),
    siblings: detail.siblings.map(summarizeRevision),
    ...(detail.ruleContext ? { ruleContext: detail.ruleContext } : {}),
    canDecide: detail.canDecide,
    ...(investigation ? { investigation: digestInvestigation(investigation) } : {}),
    links: detail.links,
  };
}

function jsonText(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value) }] };
}

export function registerAlertZeroTools(server: McpServer, deps: AlertZeroToolDeps) {
  const { alertZeroService, analytics } = deps;

  registerTrackedAppTool(
    analytics,
    server,
    "review-alert-zero-proposals",
    {
      title: "Review Alert Zero Proposals",
      description:
        "Show the Alert Zero proposals awaiting a human decision: the response, investigation and configuration actions Alert Zero's AI SOC agents propose (close alerts, isolate a host, kill a process, edit or create a rule, …). Use this when the user asks \"tell me my open proposals\", \"what does Alert Zero want me to approve\", \"pending actions\", \"proposed actions\", or \"what needs my decision\". Opens an interactive view listing every pending proposal, with a detail pane showing every proposal field, the investigation's agent activity, attached evidence, and Approve/Decline buttons. Only the user can approve or decline, from the view. If Alert Zero is unavailable, the result's status explains why. Use get-alert-zero-proposal to explain one proposal in depth.",
      inputSchema: {
        scope: scopeSchema,
        category: categorySchema,
        spaceId: spaceIdSchema,
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ scope, category, spaceId }) => {
      const result = await alertZeroService.listOpenProposals({ scope, category, spaceId });
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(createMcpAppBootstrap("alert-zero", result)),
        }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "get-alert-zero-proposal",
    {
      title: "Get Alert Zero Proposal",
      description:
        "Get everything about one Alert Zero proposal: the full record (comment, action input, action metadata), its revision history, other proposals on the same investigation, current rule state for rule actions, and a digest of the investigation's agent activity, attachments and alerts. Use when the user asks why Alert Zero proposed something or what a specific proposal would do, or before advising whether to approve or decline it. This tool cannot approve or decline; only the user can, from the review-alert-zero-proposals view.",
      inputSchema: {
        proposalId: z.string().describe("Proposal id"),
        spaceId: spaceIdSchema,
      },
      _meta: { ui: {} },
    },
    async ({ proposalId, spaceId }) => {
      const detail = await alertZeroService.getProposalDetail({ proposalId, spaceId });
      let investigation: AlertZeroInvestigation | undefined;
      let investigationError: string | undefined;
      try {
        investigation = await alertZeroService.getInvestigation({
          conversationId: detail.proposal.conversationId,
          spaceId,
        });
      } catch (e) {
        investigationError = e instanceof Error ? e.message : String(e);
      }
      const digest = buildProposalDigest(detail, investigation);
      return jsonText(investigationError ? { ...digest, investigationError } : digest);
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "check-alert-zero-status",
    {
      title: "Check Alert Zero Status",
      description:
        "Check whether Alert Zero is enabled and usable in a Kibana space and, if not, exactly why (plugin disabled, disabled in the space, license or serverless tier, missing privileges, dependencies unavailable, unreachable) and how to fix it. Use when the user asks if Alert Zero is enabled or available, or before other Alert Zero tools if unsure.",
      inputSchema: { spaceId: spaceIdSchema },
      _meta: { ui: {} },
    },
    async ({ spaceId }) => jsonText(await alertZeroService.getStatus({ spaceId }))
  );

  registerTrackedAppTool(
    analytics,
    server,
    "list-alert-zero-proposals",
    {
      title: "List Alert Zero Proposals",
      description: "List Alert Zero proposals awaiting a decision",
      inputSchema: {
        scope: scopeSchema,
        category: categorySchema,
        spaceId: spaceIdSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ scope, category, spaceId }) =>
      jsonText(await alertZeroService.listOpenProposals({ scope, category, spaceId }))
  );

  registerTrackedAppTool(
    analytics,
    server,
    "get-alert-zero-proposal-detail",
    {
      title: "Get Alert Zero Proposal Detail",
      description: "Fetch a proposal with its revision chain, siblings, and rule context",
      inputSchema: {
        proposalId: z.string(),
        spaceId: spaceIdSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ proposalId, spaceId }) =>
      jsonText(await alertZeroService.getProposalDetail({ proposalId, spaceId }))
  );

  registerTrackedAppTool(
    analytics,
    server,
    "get-alert-zero-investigation",
    {
      title: "Get Alert Zero Investigation",
      description: "Fetch an Alert Zero investigation conversation with attachments and enriched alerts",
      inputSchema: {
        conversationId: z.string(),
        spaceId: spaceIdSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ conversationId, spaceId }) =>
      jsonText(await alertZeroService.getInvestigation({ conversationId, spaceId }))
  );

  registerTrackedAppTool(
    analytics,
    server,
    "approve-alert-zero-proposal",
    {
      title: "Approve Alert Zero Proposal",
      description: "Approve a proposal (optionally with edited action input)",
      inputSchema: {
        proposalId: z.string(),
        actionInput: z.record(z.string(), z.unknown()).optional(),
        rationale: rationaleSchema,
        spaceId: spaceIdSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ proposalId, actionInput, rationale, spaceId }) =>
      jsonText(await alertZeroService.approveProposal({ proposalId, actionInput, rationale, spaceId }))
  );

  registerTrackedAppTool(
    analytics,
    server,
    "dismiss-alert-zero-proposal",
    {
      title: "Dismiss Alert Zero Proposal",
      description: "Decline a proposal with a reason",
      inputSchema: {
        proposalId: z.string(),
        dismissReason: z.enum(DISMISS_REASONS),
        rationale: rationaleSchema,
        spaceId: spaceIdSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ proposalId, dismissReason, rationale, spaceId }) =>
      jsonText(await alertZeroService.dismissProposal({ proposalId, dismissReason, rationale, spaceId }))
  );

  const viewPath = resolveViewPath("alert-zero");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
