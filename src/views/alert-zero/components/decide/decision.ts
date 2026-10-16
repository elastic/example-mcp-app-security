/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  isAwaitingDecision,
  type AlertZeroDecisionResult,
  type AlertZeroProposalDetail,
  type DismissReason,
  type Proposal,
  type ProposalImpact,
  type ProposalWithMetadata,
} from "../../../../shared/alert-zero-types";
import type { ToastTone } from "../../../../shared/components";
import { getProposalPhase, humanize, parseTime } from "../detail/helpers";

export const RATIONALE_MAX = 4096;
export const APPLY_POLL_INTERVAL_MS = 3000;
/** ~3 minutes of polling before handing the wait back to the user. */
export const APPLY_POLL_MAX_ATTEMPTS = 60;

export const NO_PRIVILEGE_REASON =
  "Your API key can't approve or decline proposals — it needs the Proposed Actions: All privilege.";
export const PAST_DEADLINE_REASON = "Past deadline — Alert Zero will expire this proposal.";
export const CONFLICT_MESSAGE = "This proposal changed or was already decided. Refreshing…";
export const FORBIDDEN_MESSAGE =
  "You don't have permission to decide on this proposal. Your API key needs the Proposed Actions: All privilege.";
export const GENERIC_DECISION_ERROR = "Couldn't record the decision. Try again.";
export const OTHER_RATIONALE_REQUIRED = "A rationale is required when declining as Other.";
export const RATIONALE_TOO_LONG = `Rationale must be ${RATIONALE_MAX.toLocaleString("en-US")} characters or fewer.`;

type StatusAndDecision = Pick<Proposal, "status" | "decision">;

export type DecisionAvailability =
  | { readonly kind: "decide"; readonly disabledReason?: string }
  | { readonly kind: "applying" }
  | { readonly kind: "none" };

export function isPastDeadline(expiresAt: string | undefined, now: number): boolean {
  const t = parseTime(expiresAt);
  return t !== undefined && t <= now;
}

/** Approved and the action workflow has not settled yet. */
export function isApplying(p: StatusAndDecision): boolean {
  return p.decision === "approved" && (p.status === "pending" || p.status === "executing");
}

/** Nothing left to wait for: decided (or closed by Alert Zero) and not still running. */
export function isSettled(p: StatusAndDecision): boolean {
  return !isApplying(p) && !isAwaitingDecision(p);
}

export function hasAutomatedAction(p: Pick<Proposal, "actionWorkflowId">): boolean {
  return Boolean(p.actionWorkflowId);
}

export function decisionAvailability(
  detail: Pick<AlertZeroProposalDetail, "proposal" | "canDecide">,
  now: number = Date.now(),
): DecisionAvailability {
  const p = detail.proposal;
  if (isApplying(p)) return { kind: "applying" };
  if (!isAwaitingDecision(p)) return { kind: "none" };
  if (isPastDeadline(p.expiresAt, now)) return { kind: "decide", disabledReason: PAST_DEADLINE_REASON };
  if (!detail.canDecide) return { kind: "decide", disabledReason: NO_PRIVILEGE_REASON };
  return { kind: "decide" };
}

export function proposalImpact(p: Pick<ProposalWithMetadata, "impact" | "action">): ProposalImpact | undefined {
  return p.impact ?? p.action?.impact;
}

export function approveButtonTone(impact: ProposalImpact | undefined): "danger" | "primary" {
  return impact === "high" || impact === "critical" ? "danger" : "primary";
}

export function validateRationale(rationale: string): string | undefined {
  return rationale.length > RATIONALE_MAX ? RATIONALE_TOO_LONG : undefined;
}

export function validateDecline(reason: DismissReason, rationale: string): string | undefined {
  if (reason === "other" && rationale.trim() === "") return OTHER_RATIONALE_REQUIRED;
  return validateRationale(rationale);
}

export function approveArgs(
  proposal: Pick<Proposal, "id" | "actionInput">,
  rationale: string,
  spaceId: string,
): Record<string, unknown> {
  return { proposalId: proposal.id, actionInput: proposal.actionInput, rationale: rationale.trim() || undefined, spaceId };
}

export function dismissArgs(
  proposalId: string,
  dismissReason: DismissReason,
  rationale: string,
  spaceId: string,
): Record<string, unknown> {
  return { proposalId, dismissReason, rationale: rationale.trim() || undefined, spaceId };
}

export type DecisionKind = "approve" | "dismiss";

export type DecisionOutcome =
  /** Decision recorded; `watch` when an approved action is still running. */
  | { readonly type: "recorded"; readonly message: string; readonly tone: ToastTone; readonly watch: boolean }
  /** Accepted by Kibana but not yet visible on the proposal. */
  | { readonly type: "submitted"; readonly message: string }
  | { readonly type: "conflict"; readonly message: string }
  | { readonly type: "error"; readonly message: string; readonly detail?: string };

export function interpretDecisionResult(
  kind: DecisionKind,
  result: AlertZeroDecisionResult,
  proposal: Pick<Proposal, "actionWorkflowId">,
): DecisionOutcome {
  if (result.ok) {
    if (!result.decisionRecorded) {
      return { type: "submitted", message: "Decision submitted — Alert Zero is still recording it" };
    }
    if (kind === "dismiss") return { type: "recorded", message: "Declined", tone: "success", watch: false };
    if (!hasAutomatedAction(proposal)) return { type: "recorded", message: "Approved", tone: "success", watch: false };
    if (result.proposal && isSettled(result.proposal)) {
      return { type: "recorded", ...settledToast(result.proposal), watch: false };
    }
    return { type: "recorded", message: "Approved — Alert Zero is applying the action", tone: "success", watch: true };
  }
  if (result.httpStatus === 409) return { type: "conflict", message: CONFLICT_MESSAGE };
  if (result.httpStatus === 403) return { type: "error", message: FORBIDDEN_MESSAGE, detail: result.error };
  return { type: "error", message: result.error || GENERIC_DECISION_ERROR };
}

/** Status line while watching a decision settle. */
export function watchingLabel(p: StatusAndDecision & Pick<Proposal, "actionWorkflowId">, mode: "applying" | "recording"): string {
  if (mode === "recording" && isAwaitingDecision(p)) return "Recording your decision…";
  return hasAutomatedAction(p) ? "Applying… typically takes 3–5 minutes" : "Finishing up…";
}

export interface SettledToast {
  readonly message: string;
  readonly tone: ToastTone;
}

/** Toast for the final state a watched proposal reached. */
export function settledToast(p: ProposalWithMetadata): SettledToast {
  const title = `"${p.title}"`;
  switch (getProposalPhase(p)) {
    case "applied":
      return { message: `Applied — ${title}`, tone: "success" };
    case "failed": {
      const reason = p.executionError ? `: ${p.executionError}` : "";
      const retry = p.supersededBy ? " Alert Zero re-offered it as a new proposal." : "";
      return { message: `Action failed — ${title}${reason}.${retry}`, tone: "danger" };
    }
    case "approved_no_action":
    case "no_action":
      return { message: `Approved — no action to run for ${title}`, tone: "info" };
    case "declined":
      return { message: `Declined — ${title}`, tone: "success" };
    case "expired":
      return { message: `${title} expired before it ran`, tone: "info" };
    case "superseded":
      return { message: `${title} was replaced by a newer revision`, tone: "info" };
    default:
      return { message: `${title} is now ${humanize(p.status).toLowerCase()}`, tone: "info" };
  }
}

/** Toast when polling gives up before the proposal settled. */
export function stillWaitingMessage(p: StatusAndDecision): string {
  return isAwaitingDecision(p)
    ? "Alert Zero hasn't recorded the decision yet. Reload the proposal later to check."
    : "Still applying — Alert Zero will finish in the background. Reload the proposal to check the result.";
}
