/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Shared Alert Zero types and pure helpers, imported by both the server
 * (tools, service) and the `alert-zero` view. Must stay free of DOM and Node
 * APIs.
 *
 * Proposal shapes mirror Kibana's `@kbn/proposals-common` (`proposal.ts`) and
 * Alert Zero's `ProposalItem` (`alertzero/common/proposals/list.ts`). These are
 * internal Kibana APIs: fields the server adds later are not typed here, so
 * the view renders any unrecognised key in an "Other fields" section.
 */

export const PROPOSAL_STATUSES = [
  "pending",
  "executing",
  "succeeded",
  "failed",
  "expired",
  "no_action",
  "superseded",
] as const;
export type ProposalStatus = (typeof PROPOSAL_STATUSES)[number];

export type ProposalDecision = "approved" | "dismissed";
export type ProposalImpact = "low" | "medium" | "high" | "critical";
export type ProposalConfidence = "low" | "medium" | "high";
export type ProposalOrigin = "alertzero" | "nightshift" | "context_engine" | "agent_builder";

export const DISMISS_REASONS = [
  "no_reason",
  "duplicate",
  "false_positive",
  "handled_elsewhere",
  "risk_accepted",
  "other",
] as const;
export type DismissReason = (typeof DISMISS_REASONS)[number];

export const DISMISS_REASON_LABELS: Record<DismissReason, string> = {
  no_reason: "No reason",
  duplicate: "Duplicate",
  false_positive: "False positive",
  handled_elsewhere: "Handled elsewhere",
  risk_accepted: "Risk accepted",
  other: "Other",
};

export const ALERT_ZERO_CATEGORIES = ["respond", "investigate", "configure"] as const;
export type AlertZeroCategory = (typeof ALERT_ZERO_CATEGORIES)[number];
export type AlertZeroCategoryFilter = AlertZeroCategory | "all";

export const PROPOSAL_SCOPES = ["all", "mine", "unassigned"] as const;
export type ProposalScope = (typeof PROPOSAL_SCOPES)[number];

/** Managed action workflows Alert Zero Workers propose (`actionWorkflowId`). */
export const ACTION_WORKFLOW_IDS = {
  closeAlertsFp: "system-alertzero-action-close-alerts-fp",
  handoffToForensics: "system-alertzero-action-handoff-to-forensics",
  editRule: "system-alertzero-action-edit-rule",
  addRuleException: "system-alertzero-action-add-rule-exception",
  createRule: "system-alertzero-action-create-rule",
  enableRule: "system-alertzero-action-enable-rule",
  installPrebuiltRule: "system-alertzero-action-install-prebuilt-rule",
  isolateHost: "system-alertzero-action-isolate-host",
  killProcess: "system-alertzero-action-kill-process",
  suspendProcess: "system-alertzero-action-suspend-process",
} as const;

export interface ProposalUser {
  readonly username: string | null;
  readonly fullName: string | null;
  readonly email: string | null;
  readonly profileUid?: string;
}

/** Live action metadata the proposals service resolves from the action workflow. */
export interface ProposalActionMetadata {
  readonly name: string;
  readonly description?: string;
  readonly category?: string;
  readonly impact?: ProposalImpact;
  readonly reversible?: boolean;
  readonly approvalPolicy?: "always-gate" | "autonomy-dependent";
}

/** Stored proposal record (`proposalSchema`). */
export interface Proposal {
  readonly id: string;
  readonly spaceId: string;
  readonly conversationId: string;
  readonly title: string;
  readonly comment: string;
  readonly actionWorkflowId?: string;
  readonly actionInput?: Record<string, unknown>;
  readonly status: ProposalStatus;
  readonly decision?: ProposalDecision;
  readonly supersededBy?: string;
  readonly rootProposalId?: string;
  readonly supersedes?: string;
  readonly revision?: number;
  readonly impact: ProposalImpact;
  readonly confidence: ProposalConfidence;
  readonly category?: string;
  readonly origin: ProposalOrigin;
  readonly expiresAt?: string;
  readonly decidedBy?: ProposalUser;
  readonly decidedAt?: string;
  readonly dismissReason?: DismissReason;
  readonly rationale?: string;
  readonly executionError?: string;
  readonly previousExecutionError?: string;
  readonly workflowExecutionId?: string;
  readonly createdAt: string;
  readonly createdBy?: ProposalUser;
}

export interface ProposalWithMetadata extends Proposal {
  readonly action?: ProposalActionMetadata;
}

/** Row returned by `/internal/alertzero/proposals/category/{category}`. */
export interface ProposalItem extends ProposalWithMetadata {
  readonly conversationTitle?: string;
  readonly conversationAgentId?: string;
  readonly conversationAssignees: readonly string[];
  readonly entityIds?: readonly string[];
}

/**
 * Every top-level key a proposal response can carry today. The view's
 * field-coverage test asserts each one is rendered somewhere.
 */
export const PROPOSAL_FIELD_KEYS = [
  "id",
  "spaceId",
  "conversationId",
  "title",
  "comment",
  "actionWorkflowId",
  "actionInput",
  "status",
  "decision",
  "supersededBy",
  "rootProposalId",
  "supersedes",
  "revision",
  "impact",
  "confidence",
  "category",
  "origin",
  "expiresAt",
  "decidedBy",
  "decidedAt",
  "dismissReason",
  "rationale",
  "executionError",
  "previousExecutionError",
  "workflowExecutionId",
  "createdAt",
  "createdBy",
  "action",
  "conversationTitle",
  "conversationAgentId",
  "conversationAssignees",
  "entityIds",
] as const satisfies readonly (keyof ProposalItem)[];

/** A user profile UID resolved to display fields (best effort). */
export interface ResolvedUser {
  readonly uid: string;
  readonly username?: string;
  readonly fullName?: string;
  readonly email?: string;
}

/** Compact list row: everything a card needs, plus the agent-facing summary. */
export interface AlertZeroProposalCard {
  readonly id: string;
  readonly conversationId: string;
  readonly title: string;
  readonly status: ProposalStatus;
  readonly category?: string;
  readonly impact: ProposalImpact;
  readonly confidence: ProposalConfidence;
  readonly actionWorkflowId?: string;
  readonly actionName?: string;
  readonly reversible?: boolean;
  readonly approvalPolicy?: ProposalActionMetadata["approvalPolicy"];
  readonly createdAt: string;
  readonly expiresAt?: string;
  readonly revision?: number;
  readonly hasPreviousExecutionError: boolean;
  readonly investigationTitle?: string;
  readonly agentId?: string;
  readonly assignees: readonly ResolvedUser[];
  readonly assignedToMe: boolean;
  readonly entityIds?: readonly string[];
  readonly priorityScore: number;
  /** First ~300 characters of `comment`, markdown stripped to plain text. */
  readonly commentExcerpt: string;
  /** Human-readable targets derived from `actionInput` (see `summarizeActionTargets`). */
  readonly targets: readonly string[];
}

export type AlertZeroAvailabilityState =
  | "enabled"
  | "plugin_disabled"
  | "space_not_found"
  | "disabled_in_space"
  | "license"
  | "serverless_tier"
  | "missing_privileges"
  | "dependencies_unavailable"
  | "unreachable";

export interface AlertZeroStatus {
  readonly state: AlertZeroAvailabilityState;
  readonly available: boolean;
  readonly spaceId: string;
  /** One sentence on what is wrong (or "Alert Zero is enabled"). */
  readonly reason: string;
  /** What to do about it, when there is something to do. */
  readonly remediation?: string;
  readonly canRead: boolean;
  readonly canDecide: boolean;
  readonly investigationCount?: number;
  readonly httpStatus?: number;
}

export interface AlertZeroListResult {
  readonly status: AlertZeroStatus;
  readonly spaceId: string;
  /** Kibana base URL including any basePath, without trailing slash. */
  readonly kibanaUrl: string;
  readonly currentUser?: ResolvedUser;
  readonly scope: ProposalScope;
  readonly category: AlertZeroCategoryFilter;
  /** Pending proposals in the space before the scope filter is applied. */
  readonly totalAwaitingDecision: number;
  /** Pending proposals per category before the scope filter is applied. */
  readonly countsByCategory: Record<AlertZeroCategory, number>;
  /** Rows after the scope + category filters, sorted by priority. */
  readonly proposals: readonly AlertZeroProposalCard[];
  /** True when the server had more rows than the pagination cap allowed. */
  readonly truncated: boolean;
  /** Caveat about the result the user should hear (e.g. "mine" couldn't be evaluated). */
  readonly notice?: string;
}

export interface AlertZeroLinks {
  readonly alertZero: string;
  readonly agentBuilder: string;
}

export interface AlertZeroProposalDetail {
  /** Full record from `GET /internal/proposals/{id}` merged with the list-only fields when known. */
  readonly proposal: ProposalWithMetadata & Partial<ProposalItem>;
  /** Every proposal sharing `rootProposalId`, ordered oldest revision first (includes `proposal`). */
  readonly revisionChain: readonly ProposalWithMetadata[];
  /** Other proposals on the same investigation, any status, excluding the revision chain. */
  readonly siblings: readonly ProposalWithMetadata[];
  /** Current state of the targeted rule for rule-editing actions (fail-soft). */
  readonly ruleContext?: {
    readonly current?: Record<string, unknown>;
    readonly error?: string;
  };
  readonly links: AlertZeroLinks;
  readonly kibanaUrl: string;
  readonly spaceId: string;
  readonly canDecide: boolean;
}

export interface ConversationActor {
  readonly type: string;
  readonly id?: string;
  readonly username?: string;
  readonly [key: string]: unknown;
}

export interface ConversationEvent {
  readonly id: string;
  /** `user_message`, `prompt_response`, `execution_*`, `attachment_added|updated|deleted`, … */
  readonly type: string;
  readonly created_at: string;
  readonly actor?: ConversationActor;
  readonly data?: Record<string, unknown>;
}

export interface AttachmentVersion {
  readonly version: number;
  readonly data: unknown;
  readonly created_at?: string;
  readonly content_hash?: string;
  readonly estimated_tokens?: number;
}

export interface ConversationAttachment {
  readonly id: string;
  readonly type: string;
  readonly versions: readonly AttachmentVersion[];
  readonly current_version: number;
  readonly active?: boolean;
  readonly hidden?: boolean;
  readonly readonly?: boolean;
  readonly description?: string;
  readonly origin?: string;
  readonly origin_snapshot_at?: string;
  readonly client_id?: string;
  readonly group_id?: string;
}

export interface ToolResult {
  readonly tool_result_id?: string;
  /** `resource`, `resource_list`, `esql_results`, `query`, `visualization`, `other`, `error`, … */
  readonly type: string;
  readonly data: unknown;
}

/**
 * One step inside a round. `tool_call` steps carry `tool_call_id`, `tool_id`,
 * `params`, `results`; `reasoning` steps carry `reasoning`. Other step types
 * are passed through untouched.
 */
export interface RoundStep {
  readonly type: string;
  readonly tool_call_id?: string;
  readonly tool_id?: string;
  readonly params?: Record<string, unknown>;
  readonly results?: readonly ToolResult[];
  readonly reasoning?: string;
  readonly [key: string]: unknown;
}

export interface ConversationRound {
  readonly id: string;
  readonly status?: string;
  readonly input?: { readonly message?: string; readonly attachment_refs?: readonly unknown[] };
  readonly steps?: readonly RoundStep[];
  readonly response?: { readonly message?: string; readonly structured_output?: unknown };
  readonly started_at?: string;
  readonly author?: unknown;
  readonly model_usage?: Record<string, unknown>;
  readonly time_to_first_token?: number;
  readonly time_to_last_token?: number;
  readonly trace_id?: string;
  readonly interruption?: unknown;
}

export interface InvestigationMetadata {
  readonly status?: "open" | "closed";
  readonly severity?: string;
  readonly assignees?: readonly string[];
  readonly verdict?: string;
  readonly summary?: string;
  readonly description?: string;
  readonly close_reason?: string;
  readonly workflow_execution_ids?: readonly string[];
  readonly [key: string]: unknown;
}

export interface Conversation {
  readonly id: string;
  readonly agent_id?: string;
  readonly user?: { readonly id?: string; readonly username?: string };
  readonly title?: string;
  readonly created_at?: string;
  readonly updated_at?: string;
  readonly metadata?: InvestigationMetadata;
  readonly template_id?: string;
  readonly template_version?: number | string;
  readonly rounds: readonly ConversationRound[];
  readonly attachments: readonly ConversationAttachment[];
  readonly events: readonly ConversationEvent[];
  readonly [key: string]: unknown;
}

/** Alert document summary used to enrich `security.alerts` attachments. */
export interface EnrichedAlert {
  readonly id: string;
  readonly index?: string;
  readonly ruleName?: string;
  readonly severity?: string;
  readonly riskScore?: number;
  readonly host?: string;
  readonly user?: string;
  readonly timestamp?: string;
  readonly reason?: string;
  readonly workflowStatus?: string;
}

export interface AlertZeroInvestigation {
  /** Conversation with attachments merged from `?include_deleted=true` (inactive ones keep `active: false`). */
  readonly conversation: Conversation;
  readonly assignees: readonly ResolvedUser[];
  /** Alert id → summary for ids referenced by `security.alerts` / `security.attack_discovery` attachments. */
  readonly alerts: Record<string, EnrichedAlert>;
  readonly links: AlertZeroLinks;
}

export interface AlertZeroDecisionResult {
  readonly ok: boolean;
  /** True once a poll observed `decision` set on the proposal. */
  readonly decisionRecorded: boolean;
  readonly proposal?: ProposalWithMetadata;
  readonly error?: string;
  readonly httpStatus?: number;
}

export interface AlertZeroSpaceOption {
  readonly spaceId?: string;
}

/** The service surface tools depend on. Implemented by `AlertZeroService`. */
export interface AlertZeroServiceApi {
  readonly kibanaUrl: string;
  getStatus(opts?: AlertZeroSpaceOption): Promise<AlertZeroStatus>;
  listOpenProposals(
    opts?: AlertZeroSpaceOption & {
      readonly scope?: ProposalScope;
      readonly category?: AlertZeroCategoryFilter;
    },
  ): Promise<AlertZeroListResult>;
  getProposal(opts: AlertZeroSpaceOption & { readonly proposalId: string }): Promise<ProposalWithMetadata>;
  getProposalDetail(
    opts: AlertZeroSpaceOption & { readonly proposalId: string },
  ): Promise<AlertZeroProposalDetail>;
  getInvestigation(
    opts: AlertZeroSpaceOption & { readonly conversationId: string },
  ): Promise<AlertZeroInvestigation>;
  approveProposal(
    opts: AlertZeroSpaceOption & {
      readonly proposalId: string;
      readonly actionInput?: Record<string, unknown>;
      readonly rationale?: string;
    },
  ): Promise<AlertZeroDecisionResult>;
  dismissProposal(
    opts: AlertZeroSpaceOption & {
      readonly proposalId: string;
      readonly dismissReason: DismissReason;
      readonly rationale?: string;
    },
  ): Promise<AlertZeroDecisionResult>;
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

const IMPACT_RANK: Record<ProposalImpact, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const CONFIDENCE_RANK: Record<ProposalConfidence, number> = { high: 3, medium: 2, low: 1 };

/** Alert Zero's queue ordering: impact first, then confidence (max 95). */
export function priorityScore(impact: ProposalImpact, confidence: ProposalConfidence): number {
  return (IMPACT_RANK[impact] ?? 1) * 20 + (CONFIDENCE_RANK[confidence] ?? 1) * 5;
}

export function isAwaitingDecision(p: Pick<Proposal, "status" | "decision">): boolean {
  return p.status === "pending" && !p.decision;
}

export function spacePrefix(spaceId?: string): string {
  return !spaceId || spaceId === "default" ? "" : `/s/${encodeURIComponent(spaceId)}`;
}

function trimTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

export function alertZeroLink(kibanaUrl: string, spaceId: string | undefined, conversationId: string): string {
  return `${trimTrailingSlash(kibanaUrl)}${spacePrefix(spaceId)}/app/alertzero?selectedConversationId=${encodeURIComponent(conversationId)}`;
}

export function agentBuilderLink(
  kibanaUrl: string,
  spaceId: string | undefined,
  conversationId: string,
  agentId?: string,
): string {
  const base = `${trimTrailingSlash(kibanaUrl)}${spacePrefix(spaceId)}/app/agent_builder`;
  const id = encodeURIComponent(conversationId);
  return agentId
    ? `${base}/agents/${encodeURIComponent(agentId)}/conversations/${id}`
    : `${base}/conversations/${id}`;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** Entity ids share long prefixes, so keep the distinguishing tail. */
function tailEllipsis(value: string, keep = 14): string {
  return value.length > keep + 1 ? `…${value.slice(-keep)}` : value;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/**
 * Short, human-readable description of what a proposal's `actionInput`
 * targets, e.g. `["3 endpoints", "pid 4242"]`. Unknown actions fall back to
 * the input's top-level keys so nothing is silently hidden.
 */
export function summarizeActionTargets(
  actionWorkflowId: string | undefined,
  actionInput: Record<string, unknown> | undefined,
): string[] {
  if (!actionInput) return [];
  const input = actionInput;
  const endpoints = asStringArray(input.endpoint_ids);
  const params = (input.parameters ?? {}) as Record<string, unknown>;
  switch (actionWorkflowId) {
    case ACTION_WORKFLOW_IDS.isolateHost:
      return [plural(endpoints.length, "endpoint")];
    case ACTION_WORKFLOW_IDS.killProcess:
    case ACTION_WORKFLOW_IDS.suspendProcess: {
      const proc =
        params.pid !== undefined
          ? `pid ${String(params.pid)}`
          : params.entity_id !== undefined
            ? `entity ${tailEllipsis(String(params.entity_id))}`
            : "process";
      const out = [proc, plural(endpoints.length, "endpoint")];
      if (params.kill_descendants === true) out.push("with descendants");
      return out;
    }
    case ACTION_WORKFLOW_IDS.closeAlertsFp:
      return [plural(asStringArray(input.alertIds).length, "alert")];
    case ACTION_WORKFLOW_IDS.editRule:
      return [`rule ${String(input.id ?? "?")}`, ...Object.keys(input).filter((k) => !["id", "expected_revision"].includes(k))];
    case ACTION_WORKFLOW_IDS.addRuleException:
      return [`rule ${String(input.rule_id ?? "?")}`, plural(Array.isArray(input.entries) ? input.entries.length : 0, "entry")];
    case ACTION_WORKFLOW_IDS.createRule:
      return [`new ${String(input.type ?? "")} rule "${String(input.name ?? "")}"`.replace(/\s+/g, " ")];
    case ACTION_WORKFLOW_IDS.enableRule:
      return [`rule ${String(input.id ?? "?")}`];
    case ACTION_WORKFLOW_IDS.installPrebuiltRule:
      return [`prebuilt rule ${String(input.rule_id ?? "?")} v${String(input.version ?? "?")}`];
    case ACTION_WORKFLOW_IDS.handoffToForensics:
      return [`attack discovery ${String(input.attack_discovery_id ?? "?")}`];
    default:
      return Object.keys(input);
  }
}

/** Plain-text excerpt of a markdown body for compact listings. */
export function plainExcerpt(markdown: string | undefined, max = 300): string {
  if (!markdown) return "";
  const text = markdown
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`([^`]*)`/g, "$1")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[*_#>|]+/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return text.length > max ? `${text.slice(0, max - 1).trimEnd()}…` : text;
}

/**
 * Build a list card from a proposal record. Used by the service for list rows
 * and by the view when navigating to a proposal that is not in the list
 * (a sibling or an older revision).
 */
export function toProposalCard(
  p: ProposalWithMetadata & Partial<ProposalItem>,
  opts: { readonly assignees?: readonly ResolvedUser[]; readonly currentUserUid?: string } = {},
): AlertZeroProposalCard {
  const assigneeUids = p.conversationAssignees ?? [];
  const assignees = opts.assignees ?? assigneeUids.map((uid) => ({ uid }));
  return {
    id: p.id,
    conversationId: p.conversationId,
    title: p.title,
    status: p.status,
    category: p.category ?? p.action?.category,
    impact: p.impact,
    confidence: p.confidence,
    actionWorkflowId: p.actionWorkflowId,
    actionName: p.action?.name,
    reversible: p.action?.reversible,
    approvalPolicy: p.action?.approvalPolicy,
    createdAt: p.createdAt,
    expiresAt: p.expiresAt,
    revision: p.revision,
    hasPreviousExecutionError: Boolean(p.previousExecutionError),
    investigationTitle: p.conversationTitle,
    agentId: p.conversationAgentId,
    assignees,
    assignedToMe: Boolean(opts.currentUserUid && assigneeUids.includes(opts.currentUserUid)),
    entityIds: p.entityIds,
    priorityScore: priorityScore(p.impact, p.confidence),
    commentExcerpt: plainExcerpt(p.comment),
    targets: summarizeActionTargets(p.actionWorkflowId, p.actionInput),
  };
}

/** Bootstrap payload for the `alert-zero` view (same shape as the list result). */
export type AlertZeroBootstrapPayload = AlertZeroListResult;
