/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  ACTION_WORKFLOW_IDS,
  ALERT_ZERO_CATEGORIES,
  DISMISS_REASONS,
  agentBuilderLink,
  alertZeroLink,
  isAwaitingDecision,
  toProposalCard,
  type AlertZeroAvailabilityState,
  type AlertZeroCategory,
  type AlertZeroCategoryFilter,
  type AlertZeroDecisionResult,
  type AlertZeroInvestigation,
  type AlertZeroLinks,
  type AlertZeroListResult,
  type AlertZeroProposalDetail,
  type AlertZeroServiceApi,
  type AlertZeroSpaceOption,
  type AlertZeroStatus,
  type Conversation,
  type ConversationAttachment,
  type DismissReason,
  type EnrichedAlert,
  type ProposalItem,
  type ProposalScope,
  type ProposalWithMetadata,
  type ResolvedUser,
} from "../../shared/alert-zero-types.js";
import { createStderrLogger, type Logger } from "../../shared/logger.js";
import type {
  AlertZeroClient,
  KibanaCapabilities,
  UserProfileSummary,
} from "../client/alertZeroClient.js";
import { KibanaHttpError } from "../kibana-client/kibana-http-error.js";

const DEFAULT_SPACE = "default";
const PAGE_SIZE = 100;
const MAX_ROWS_PER_CATEGORY = 1000;
const MAX_CONVERSATION_PROPOSALS = 300;
const MAX_ENRICHED_ALERTS = 200;

const ALERT_SOURCE_FIELDS = [
  "kibana.alert.rule.name",
  "kibana.alert.severity",
  "kibana.alert.risk_score",
  "host.name",
  "user.name",
  "@timestamp",
  "kibana.alert.reason",
  "kibana.alert.workflow_status",
] as const;

const PRIVILEGES_REMEDIATION =
  "Grant the API key's role the Kibana feature privileges Alert Zero (read), " +
  "Proposed Actions (read; all to approve/decline) and Agent Builder (read).";

interface AlertZeroServiceOptions {
  readonly alertZeroClient: AlertZeroClient;
  readonly kibanaUrl: string;
  readonly logger?: Pick<Logger, "warn">;
  readonly pollIntervalMs?: number;
  readonly pollAttempts?: number;
  readonly sleep?: (ms: number) => Promise<void>;
}

type StatusFields = Pick<AlertZeroStatus, "state" | "reason" | "remediation" | "httpStatus">;

function statusOf(err: unknown): number | undefined {
  return err instanceof KibanaHttpError ? err.status : undefined;
}

/** Prefer Kibana's `body.message` over the transport's `Kibana [cluster] <status>: <json>` text. */
function readableError(err: unknown): string {
  if (err instanceof KibanaHttpError && err.body && typeof err.body === "object") {
    const { message } = err.body as { message?: unknown };
    if (typeof message === "string" && message.trim()) return message;
  }
  return err instanceof Error ? err.message : String(err);
}

/** The transport keeps only `err.message`, which is empty for Node's dual-stack `ECONNREFUSED`. */
function networkDetail(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  const detail = raw
    .replace(/^Kibana \[[^\]]*\] network: /, "")
    .replace(/^"(.*)"$/, "$1")
    .trim();
  return detail || "no response (connection refused, DNS failure or timeout)";
}

function capabilityFlag(caps: KibanaCapabilities | undefined, feature: string, flag: string): boolean {
  return caps?.[feature]?.[flag] === true;
}

function currentVersionData(attachment: ConversationAttachment): unknown {
  const versions = attachment.versions ?? [];
  const current = versions.find((v) => v.version === attachment.current_version);
  return (current ?? versions[versions.length - 1])?.data;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** Reads `a.b.c` from a `_source` stored flat (`"a.b.c"`), nested, or a mix of both. */
function readField(source: unknown, path: string): unknown {
  if (!source || typeof source !== "object") return undefined;
  const obj = source as Record<string, unknown>;
  if (path in obj) return obj[path];
  const parts = path.split(".");
  for (let i = parts.length - 1; i > 0; i--) {
    const head = parts.slice(0, i).join(".");
    if (head in obj) {
      const value = readField(obj[head], parts.slice(i).join("."));
      if (value !== undefined) return value;
    }
  }
  return undefined;
}

function firstString(value: unknown): string | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  return typeof v === "string" ? v : undefined;
}

function firstNumber(value: unknown): number | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  return typeof v === "number" ? v : undefined;
}

function toResolvedUser(profile: UserProfileSummary): ResolvedUser {
  const { username, full_name: fullName, email } = profile.user ?? {};
  return {
    uid: profile.uid,
    ...(username ? { username } : {}),
    ...(fullName ? { fullName } : {}),
    ...(email ? { email } : {}),
  };
}

function timeOf(iso: string | undefined): number {
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isNaN(t) ? 0 : t;
}

function zeroCounts(): Record<AlertZeroCategory, number> {
  return { respond: 0, investigate: 0, configure: 0 };
}

/**
 * Business logic for Alert Zero proposals: availability diagnosis, the
 * pending-proposal queue across categories, proposal detail (revision chain,
 * siblings, targeted rule), the investigation behind a proposal, and
 * approve / dismiss with a read-back of the recorded decision.
 */
export class AlertZeroService implements AlertZeroServiceApi {
  readonly kibanaUrl: string;
  private readonly client: AlertZeroClient;
  private readonly logger: Pick<Logger, "warn">;
  private readonly pollIntervalMs: number;
  private readonly pollAttempts: number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(options: AlertZeroServiceOptions) {
    this.client = options.alertZeroClient;
    this.kibanaUrl = options.kibanaUrl.replace(/\/+$/, "");
    this.logger = options.logger ?? createStderrLogger(["alert-zero"]);
    this.pollIntervalMs = options.pollIntervalMs ?? 750;
    this.pollAttempts = options.pollAttempts ?? 8;
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  async getStatus({ spaceId = DEFAULT_SPACE }: AlertZeroSpaceOption = {}): Promise<AlertZeroStatus> {
    const [capsResult, countResult] = await Promise.allSettled([
      this.client.getCapabilities(spaceId),
      this.client.getInvestigationsCount(spaceId),
    ]);
    const caps = capsResult.status === "fulfilled" ? capsResult.value : undefined;
    const fields = this.classify(spaceId, caps, countResult);
    return {
      ...fields,
      available: fields.state === "enabled",
      spaceId,
      canRead: capabilityFlag(caps, "alertzero", "show") && capabilityFlag(caps, "proposals", "showProposals"),
      canDecide: capabilityFlag(caps, "proposals", "decideProposals"),
      ...(countResult.status === "fulfilled" ? { investigationCount: countResult.value.total } : {}),
    };
  }

  private classify(
    spaceId: string,
    caps: KibanaCapabilities | undefined,
    countResult: PromiseSettledResult<{ total: number }>
  ): StatusFields {
    const err = countResult.status === "rejected" ? countResult.reason : undefined;
    const httpStatus = statusOf(err);
    const message = err === undefined ? "" : readableError(err);
    const state = (s: AlertZeroAvailabilityState, reason: string, remediation?: string): StatusFields => ({
      state: s,
      reason,
      ...(remediation ? { remediation } : {}),
      ...(httpStatus !== undefined ? { httpStatus } : {}),
    });

    if (err !== undefined && httpStatus === undefined) {
      return state("unreachable", `Couldn't reach Kibana at ${this.kibanaUrl}: ${networkDetail(err)}`);
    }
    if (caps && !("alertzero" in caps)) {
      return state(
        "plugin_disabled",
        "Alert Zero isn't installed or is switched off for this Kibana.",
        "Set xpack.alertzero.enabled, xpack.proposals.enabled and xpack.agenticInvestigations.enabled " +
          "to true in kibana.yml and restart Kibana."
      );
    }
    if (countResult.status === "fulfilled") {
      return state("enabled", "Alert Zero is enabled.");
    }
    if (httpStatus === 404) {
      if (caps?.alertzero?.show === false) {
        return state(
          "missing_privileges",
          `The API key's role can't see Alert Zero in space "${spaceId}".`,
          PRIVILEGES_REMEDIATION
        );
      }
      return state(
        "disabled_in_space",
        `Alert Zero is turned off in space "${spaceId}".`,
        `Enable the "securitySolution:enableAlertZero" Advanced Setting ` +
          `(Stack Management → Advanced Settings) in space "${spaceId}".`
      );
    }
    if (httpStatus === 403) {
      if (/Security Complete/i.test(message)) {
        return state(
          "serverless_tier",
          "Alert Zero requires the Security Complete subscription.",
          "Upgrade this Serverless project to the Security Complete tier."
        );
      }
      if (/Enterprise license/i.test(message)) {
        return state(
          "license",
          "Alert Zero requires an active Enterprise license.",
          "Upgrade to an Enterprise license or start a trial (Stack Management → License Management)."
        );
      }
      return state(
        "missing_privileges",
        `The API key isn't allowed to use Alert Zero: ${message}`,
        PRIVILEGES_REMEDIATION
      );
    }
    if (httpStatus === 503) {
      return state(
        "dependencies_unavailable",
        "Alert Zero is enabled but its dependencies are unavailable.",
        "Make sure the agentBuilder, proposals and agenticInvestigations plugins are enabled " +
          "and that Kibana service accounts are available, then restart Kibana."
      );
    }
    return state("unreachable", `Kibana returned an error checking Alert Zero at ${this.kibanaUrl}: ${message}`);
  }

  async listOpenProposals({
    spaceId = DEFAULT_SPACE,
    scope = "all",
    category = "all",
  }: AlertZeroSpaceOption & {
    readonly scope?: ProposalScope;
    readonly category?: AlertZeroCategoryFilter;
  } = {}): Promise<AlertZeroListResult> {
    const status = await this.getStatus({ spaceId });
    const base = { status, spaceId, kibanaUrl: this.kibanaUrl, scope, category };
    if (!status.available) {
      return {
        ...base,
        totalAwaitingDecision: 0,
        countsByCategory: zeroCounts(),
        proposals: [],
        truncated: false,
      };
    }

    const [pages, currentUser] = await Promise.all([
      Promise.all(ALERT_ZERO_CATEGORIES.map((c) => this.fetchCategory(c, spaceId))),
      this.fetchCurrentUser(spaceId),
    ]);

    const countsByCategory = zeroCounts();
    const seen = new Set<string>();
    const rows: { item: ProposalItem; category: AlertZeroCategory }[] = [];
    let truncated = false;
    pages.forEach((page, i) => {
      const cat = ALERT_ZERO_CATEGORIES[i];
      const pending = page.rows.filter((r) => isAwaitingDecision(r) && !seen.has(r.id));
      for (const item of pending) {
        seen.add(item.id);
        rows.push({ item, category: cat });
      }
      truncated ||= page.truncated;
      countsByCategory[cat] = page.truncated
        ? Math.max(pending.length, page.total - (page.rows.length - pending.length))
        : pending.length;
    });

    const assigneeUids = [...new Set(rows.flatMap((r) => r.item.conversationAssignees ?? []))];
    const users = await this.resolveUsers(assigneeUids, spaceId);

    const cards = rows
      .map(({ item, category: cat }) => ({
        cat,
        card: toProposalCard(item, {
          assignees: (item.conversationAssignees ?? []).map((uid) => users.get(uid) ?? { uid }),
          currentUserUid: currentUser?.uid,
        }),
      }))
      .filter(({ cat, card }) => {
        if (category !== "all" && cat !== category) return false;
        if (scope === "mine") return card.assignedToMe;
        if (scope === "unassigned") return card.assignees.length === 0;
        return true;
      })
      .map(({ card }) => card)
      .sort((a, b) => b.priorityScore - a.priorityScore || timeOf(b.createdAt) - timeOf(a.createdAt));

    return {
      ...base,
      ...(currentUser ? { currentUser } : {}),
      totalAwaitingDecision: Object.values(countsByCategory).reduce((sum, n) => sum + n, 0),
      countsByCategory,
      proposals: cards,
      truncated,
    };
  }

  private async fetchCategory(
    category: AlertZeroCategory,
    spaceId: string
  ): Promise<{ rows: ProposalItem[]; total: number; truncated: boolean }> {
    const rows: ProposalItem[] = [];
    let from = 0;
    let total = 0;
    do {
      const page = await this.client.getProposalsByCategory(category, { size: PAGE_SIZE, from }, spaceId);
      total = page.total;
      rows.push(...page.proposals);
      if (page.proposals.length === 0) break;
      from += PAGE_SIZE;
    } while (from < total && rows.length < MAX_ROWS_PER_CATEGORY);
    const capped = rows.slice(0, MAX_ROWS_PER_CATEGORY);
    return { rows: capped, total, truncated: total > capped.length && rows.length >= MAX_ROWS_PER_CATEGORY };
  }

  private async fetchCurrentUser(spaceId: string): Promise<ResolvedUser | undefined> {
    try {
      const profile = await this.client.getCurrentUserProfile(spaceId);
      return profile?.uid ? toResolvedUser(profile) : undefined;
    } catch (e) {
      this.logger.warn(`Alert Zero: couldn't load the current user profile: ${readableError(e)}`);
      return undefined;
    }
  }

  private async resolveUsers(uids: readonly string[], spaceId: string): Promise<Map<string, ResolvedUser>> {
    const users = new Map<string, ResolvedUser>();
    if (uids.length === 0) return users;
    try {
      const profiles = await this.client.bulkGetUserProfiles(uids, spaceId);
      for (const profile of profiles ?? []) {
        if (profile?.uid) users.set(profile.uid, toResolvedUser(profile));
      }
    } catch (e) {
      this.logger.warn(`Alert Zero: couldn't resolve ${uids.length} assignee profile(s): ${readableError(e)}`);
    }
    return users;
  }

  getProposal({
    proposalId,
    spaceId = DEFAULT_SPACE,
  }: AlertZeroSpaceOption & { readonly proposalId: string }): Promise<ProposalWithMetadata> {
    return this.client.getProposal(proposalId, spaceId);
  }

  async getProposalDetail({
    proposalId,
    spaceId = DEFAULT_SPACE,
  }: AlertZeroSpaceOption & { readonly proposalId: string }): Promise<AlertZeroProposalDetail> {
    const proposal = await this.client.getProposal(proposalId, spaceId);
    const [related, conversation, caps, ruleContext] = await Promise.all([
      this.fetchConversationProposals(proposal.conversationId, spaceId),
      this.client.getConversation(proposal.conversationId, spaceId).catch((e: unknown) => {
        this.logger.warn(`Alert Zero: couldn't load conversation ${proposal.conversationId}: ${readableError(e)}`);
        return undefined;
      }),
      this.client.getCapabilities(spaceId).catch(() => undefined),
      this.fetchRuleContext(proposal, spaceId),
    ]);

    const merged: AlertZeroProposalDetail["proposal"] = conversation
      ? { ...proposal, ...this.listOnlyFields(conversation) }
      : proposal;

    const byId = new Map<string, ProposalWithMetadata>(related.map((p) => [p.id, p]));
    byId.set(proposal.id, proposal);
    const root = proposal.rootProposalId ?? proposal.id;
    const inChain = (p: ProposalWithMetadata): boolean => p.rootProposalId === root || p.id === root;
    const all = [...byId.values()];
    const revisionChain = all
      .filter(inChain)
      .sort((a, b) => (a.revision ?? 0) - (b.revision ?? 0) || timeOf(a.createdAt) - timeOf(b.createdAt));
    const siblings = all.filter((p) => !inChain(p));

    return {
      proposal: merged,
      revisionChain,
      siblings,
      ...(ruleContext ? { ruleContext } : {}),
      links: this.links(spaceId, proposal.conversationId, conversation?.agent_id),
      kibanaUrl: this.kibanaUrl,
      spaceId,
      canDecide: capabilityFlag(caps, "proposals", "decideProposals"),
    };
  }

  private listOnlyFields(conversation: Conversation): Partial<ProposalItem> {
    const impact = (conversation.attachments ?? []).find((a) => a.type === "investigation_impact");
    const entities = impact ? (currentVersionData(impact) as { entities?: unknown } | undefined)?.entities : undefined;
    const entityIds = Array.isArray(entities)
      ? entities.map((e) => (e as { id?: unknown })?.id).filter((id): id is string => typeof id === "string")
      : undefined;
    return {
      conversationTitle: conversation.title,
      conversationAgentId: conversation.agent_id,
      conversationAssignees: conversation.metadata?.assignees ?? [],
      ...(entityIds ? { entityIds } : {}),
    };
  }

  private async fetchConversationProposals(
    conversationId: string,
    spaceId: string
  ): Promise<ProposalWithMetadata[]> {
    const rows: ProposalWithMetadata[] = [];
    try {
      let from = 0;
      let total = 0;
      do {
        const page = await this.client.listProposalsByConversation(conversationId, { size: PAGE_SIZE, from }, spaceId);
        total = page.total;
        rows.push(...page.proposals);
        if (page.proposals.length === 0) break;
        from += PAGE_SIZE;
      } while (from < total && rows.length < MAX_CONVERSATION_PROPOSALS);
    } catch (e) {
      this.logger.warn(`Alert Zero: couldn't list proposals for conversation ${conversationId}: ${readableError(e)}`);
    }
    return rows.slice(0, MAX_CONVERSATION_PROPOSALS);
  }

  private async fetchRuleContext(
    proposal: ProposalWithMetadata,
    spaceId: string
  ): Promise<AlertZeroProposalDetail["ruleContext"]> {
    const input = proposal.actionInput ?? {};
    let ruleRef: unknown;
    let bySignatureId = false;
    switch (proposal.actionWorkflowId) {
      case ACTION_WORKFLOW_IDS.editRule:
      case ACTION_WORKFLOW_IDS.enableRule:
        ruleRef = input.id;
        break;
      case ACTION_WORKFLOW_IDS.addRuleException:
        // `rule_id` here is the rule's saved-object id, not its signature id.
        ruleRef = input.rule_id;
        break;
      case ACTION_WORKFLOW_IDS.installPrebuiltRule:
        ruleRef = input.rule_id;
        bySignatureId = true;
        break;
      default:
        return undefined;
    }
    if (typeof ruleRef !== "string" || !ruleRef) {
      return { error: "The proposal's actionInput doesn't name a rule." };
    }
    try {
      const current = bySignatureId
        ? await this.client.getRuleByRuleId(ruleRef, spaceId)
        : await this.client.getRuleById(ruleRef, spaceId);
      return { current };
    } catch (e) {
      if (bySignatureId && statusOf(e) === 404) return { error: "Not installed yet" };
      return { error: readableError(e) };
    }
  }

  async getInvestigation({
    conversationId,
    spaceId = DEFAULT_SPACE,
  }: AlertZeroSpaceOption & { readonly conversationId: string }): Promise<AlertZeroInvestigation> {
    const [raw, allAttachments] = await Promise.all([
      this.client.getConversation(conversationId, spaceId),
      this.client
        .getConversationAttachments(conversationId, spaceId)
        .then((r) => (Array.isArray(r?.results) ? r.results : undefined))
        .catch((e: unknown) => {
          this.logger.warn(`Alert Zero: couldn't list attachments for conversation ${conversationId}: ${readableError(e)}`);
          return undefined;
        }),
    ]);
    const conversation: Conversation = {
      ...raw,
      rounds: raw.rounds ?? [],
      events: raw.events ?? [],
      attachments: allAttachments ?? raw.attachments ?? [],
    };

    const [users, alerts] = await Promise.all([
      this.resolveUsers(conversation.metadata?.assignees ?? [], spaceId),
      this.enrichAlerts(conversation.attachments),
    ]);

    return {
      conversation,
      assignees: (conversation.metadata?.assignees ?? []).map((uid) => users.get(uid) ?? { uid }),
      alerts,
      links: this.links(spaceId, conversationId, conversation.agent_id),
    };
  }

  /**
   * Attachment alert ids are ES `_id`s (`<hash>:<rule execution uuid>` for
   * Defend-derived alerts). The pre-colon form is queried too so ids recorded
   * either way still resolve; hits are keyed back to the attachment's id.
   */
  private async enrichAlerts(
    attachments: readonly ConversationAttachment[]
  ): Promise<Record<string, EnrichedAlert>> {
    const ids = [
      ...new Set(
        attachments.flatMap((a) => {
          const data = currentVersionData(a) as Record<string, unknown> | undefined;
          if (a.type === "security.alerts") return stringList(data?.alertIds);
          if (a.type === "security.attack_discovery") return stringList(data?.alert_ids);
          return [];
        })
      ),
    ].slice(0, MAX_ENRICHED_ALERTS);
    if (ids.length === 0) return {};

    const byQueryId = new Map<string, string[]>();
    const addAlias = (queryId: string, original: string): void => {
      const list = byQueryId.get(queryId) ?? [];
      if (!list.includes(original)) list.push(original);
      byQueryId.set(queryId, list);
    };
    for (const id of ids) {
      addAlias(id, id);
      const colon = id.indexOf(":");
      if (colon > 0) addAlias(id.slice(0, colon), id);
    }

    const alerts: Record<string, EnrichedAlert> = {};
    try {
      const hits = await this.client.searchAlertsByIds([...byQueryId.keys()], ALERT_SOURCE_FIELDS);
      for (const hit of hits) {
        const src = hit._source ?? {};
        const exact = ids.includes(hit._id);
        const targets = exact ? [hit._id] : (byQueryId.get(hit._id) ?? []);
        for (const id of targets) {
          if (alerts[id] && !exact) continue;
          alerts[id] = {
            id,
            index: hit._index,
            ruleName: firstString(readField(src, "kibana.alert.rule.name")),
            severity: firstString(readField(src, "kibana.alert.severity")),
            riskScore: firstNumber(readField(src, "kibana.alert.risk_score")),
            host: firstString(readField(src, "host.name")),
            user: firstString(readField(src, "user.name")),
            timestamp: firstString(readField(src, "@timestamp")),
            reason: firstString(readField(src, "kibana.alert.reason")),
            workflowStatus: firstString(readField(src, "kibana.alert.workflow_status")),
          };
        }
      }
    } catch (e) {
      this.logger.warn(`Alert Zero: couldn't enrich ${ids.length} alert(s): ${readableError(e)}`);
      return {};
    }
    return alerts;
  }

  private links(spaceId: string, conversationId: string, agentId?: string): AlertZeroLinks {
    return {
      alertZero: alertZeroLink(this.kibanaUrl, spaceId, conversationId),
      agentBuilder: agentBuilderLink(this.kibanaUrl, spaceId, conversationId, agentId),
    };
  }

  async approveProposal({
    proposalId,
    actionInput,
    rationale,
    spaceId = DEFAULT_SPACE,
  }: AlertZeroSpaceOption & {
    readonly proposalId: string;
    readonly actionInput?: Record<string, unknown>;
    readonly rationale?: string;
  }): Promise<AlertZeroDecisionResult> {
    try {
      // The server rejects an approval (409) unless `actionInput` deep-equals the stored one.
      const input = actionInput ?? (await this.client.getProposal(proposalId, spaceId)).actionInput;
      await this.client.approveProposal(
        proposalId,
        { ...(input !== undefined ? { actionInput: input } : {}), ...(rationale ? { rationale } : {}) },
        spaceId
      );
    } catch (e) {
      return this.decisionError(e);
    }
    return this.awaitDecision(proposalId, spaceId);
  }

  async dismissProposal({
    proposalId,
    dismissReason,
    rationale,
    spaceId = DEFAULT_SPACE,
  }: AlertZeroSpaceOption & {
    readonly proposalId: string;
    readonly dismissReason: DismissReason;
    readonly rationale?: string;
  }): Promise<AlertZeroDecisionResult> {
    if (!(DISMISS_REASONS as readonly string[]).includes(dismissReason)) {
      return {
        ok: false,
        decisionRecorded: false,
        error: `Unknown dismiss reason "${String(dismissReason)}". Use one of: ${DISMISS_REASONS.join(", ")}.`,
      };
    }
    if (dismissReason === "other" && !rationale?.trim()) {
      return {
        ok: false,
        decisionRecorded: false,
        error: 'A rationale is required when the dismiss reason is "other".',
      };
    }
    try {
      await this.client.dismissProposal(
        proposalId,
        { dismissReason, ...(rationale ? { rationale } : {}) },
        spaceId
      );
    } catch (e) {
      return this.decisionError(e);
    }
    return this.awaitDecision(proposalId, spaceId);
  }

  private decisionError(e: unknown): AlertZeroDecisionResult {
    if (!(e instanceof KibanaHttpError)) throw e;
    return {
      ok: false,
      decisionRecorded: false,
      error: readableError(e),
      ...(e.status !== undefined ? { httpStatus: e.status } : {}),
    };
  }

  /** The decide routes respond before the gate workflow writes `decision`, so read it back. */
  private async awaitDecision(proposalId: string, spaceId: string): Promise<AlertZeroDecisionResult> {
    let last: ProposalWithMetadata | undefined;
    for (let attempt = 0; attempt < this.pollAttempts; attempt++) {
      if (attempt > 0) await this.sleep(this.pollIntervalMs);
      try {
        last = await this.client.getProposal(proposalId, spaceId);
      } catch (e) {
        this.logger.warn(`Alert Zero: couldn't read back proposal ${proposalId}: ${readableError(e)}`);
        continue;
      }
      if (last.decision) return { ok: true, decisionRecorded: true, proposal: last };
    }
    return { ok: true, decisionRecorded: false, ...(last ? { proposal: last } : {}) };
  }
}
