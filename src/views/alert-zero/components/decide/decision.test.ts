/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import type { ProposalStatus, ProposalWithMetadata } from "../../../../shared/alert-zero-types";
import {
  CONFLICT_MESSAGE,
  FORBIDDEN_MESSAGE,
  NO_PRIVILEGE_REASON,
  OTHER_RATIONALE_REQUIRED,
  PAST_DEADLINE_REASON,
  RATIONALE_MAX,
  RATIONALE_TOO_LONG,
  approveArgs,
  approveButtonTone,
  decisionAvailability,
  dismissArgs,
  interpretDecisionResult,
  isApplying,
  isPastDeadline,
  isSettled,
  settledToast,
  stillWaitingMessage,
  validateDecline,
  watchingLabel,
} from "./decision";

const NOW = Date.parse("2026-10-11T12:00:00.000Z");

function proposal(overrides: Partial<ProposalWithMetadata> = {}): ProposalWithMetadata {
  return {
    id: "p1",
    spaceId: "default",
    conversationId: "c1",
    title: "Isolate host-7",
    comment: "",
    actionWorkflowId: "system-alertzero-action-isolate-host",
    actionInput: { endpoint_ids: ["a"] },
    status: "pending",
    impact: "high",
    confidence: "high",
    origin: "alertzero",
    createdAt: "2026-10-11T11:00:00.000Z",
    ...overrides,
  };
}

describe("isApplying / isSettled", () => {
  it.each<[ProposalStatus, "approved" | "dismissed" | undefined, boolean, boolean]>([
    ["pending", undefined, false, false],
    ["pending", "approved", true, false],
    ["executing", "approved", true, false],
    ["succeeded", "approved", false, true],
    ["failed", "approved", false, true],
    ["no_action", "approved", false, true],
    ["pending", "dismissed", false, true],
    ["expired", undefined, false, true],
    ["superseded", undefined, false, true],
  ])("status %s / decision %s → applying %s, settled %s", (status, decision, applying, settled) => {
    expect(isApplying({ status, decision })).toBe(applying);
    expect(isSettled({ status, decision })).toBe(settled);
  });
});

describe("decisionAvailability", () => {
  it("enables deciding on an awaiting proposal the key can decide", () => {
    expect(decisionAvailability({ proposal: proposal({ expiresAt: "2026-10-12T00:00:00Z" }), canDecide: true }, NOW)).toEqual({
      kind: "decide",
    });
  });

  it("explains why deciding is disabled", () => {
    expect(decisionAvailability({ proposal: proposal(), canDecide: false }, NOW)).toEqual({
      kind: "decide",
      disabledReason: NO_PRIVILEGE_REASON,
    });
    expect(decisionAvailability({ proposal: proposal({ expiresAt: "2026-10-11T11:59:00Z" }), canDecide: true }, NOW)).toEqual({
      kind: "decide",
      disabledReason: PAST_DEADLINE_REASON,
    });
  });

  it("reports applying and decided states", () => {
    expect(decisionAvailability({ proposal: proposal({ decision: "approved", status: "executing" }), canDecide: true }, NOW).kind).toBe(
      "applying",
    );
    expect(decisionAvailability({ proposal: proposal({ decision: "approved", status: "succeeded" }), canDecide: true }, NOW).kind).toBe(
      "none",
    );
    expect(decisionAvailability({ proposal: proposal({ decision: "dismissed" }), canDecide: true }, NOW).kind).toBe("none");
    expect(decisionAvailability({ proposal: proposal({ status: "expired" }), canDecide: true }, NOW).kind).toBe("none");
  });

  it("treats an unparseable deadline as not past", () => {
    expect(isPastDeadline("soon", NOW)).toBe(false);
    expect(isPastDeadline(undefined, NOW)).toBe(false);
    expect(isPastDeadline("2026-10-11T12:00:00.000Z", NOW)).toBe(true);
  });
});

describe("approveButtonTone", () => {
  it("is danger for high and critical impact", () => {
    expect(approveButtonTone("critical")).toBe("danger");
    expect(approveButtonTone("high")).toBe("danger");
    expect(approveButtonTone("medium")).toBe("primary");
    expect(approveButtonTone("low")).toBe("primary");
    expect(approveButtonTone(undefined)).toBe("primary");
  });
});

describe("validateDecline", () => {
  it("requires a rationale only for Other", () => {
    expect(validateDecline("other", "   ")).toBe(OTHER_RATIONALE_REQUIRED);
    expect(validateDecline("other", "Handled by IR")).toBeUndefined();
    expect(validateDecline("no_reason", "")).toBeUndefined();
    expect(validateDecline("false_positive", "")).toBeUndefined();
  });

  it("caps the rationale length", () => {
    expect(validateDecline("no_reason", "x".repeat(RATIONALE_MAX))).toBeUndefined();
    expect(validateDecline("no_reason", "x".repeat(RATIONALE_MAX + 1))).toBe(RATIONALE_TOO_LONG);
  });
});

describe("tool arguments", () => {
  it("sends the stored actionInput object and a trimmed rationale", () => {
    const p = proposal();
    const args = approveArgs(p, "  looks right  ", "soc");
    expect(args).toEqual({ proposalId: "p1", actionInput: p.actionInput, rationale: "looks right", spaceId: "soc" });
    expect(args.actionInput).toBe(p.actionInput);
    expect(approveArgs(p, "   ", "soc").rationale).toBeUndefined();
    expect(dismissArgs("p1", "duplicate", "", "soc")).toEqual({
      proposalId: "p1",
      dismissReason: "duplicate",
      rationale: undefined,
      spaceId: "soc",
    });
  });
});

describe("interpretDecisionResult", () => {
  const withAction = proposal();
  const noAction = proposal({ actionWorkflowId: undefined, actionInput: undefined });

  it("watches an approved action that is still running", () => {
    expect(
      interpretDecisionResult("approve", { ok: true, decisionRecorded: true, proposal: proposal({ decision: "approved" }) }, withAction),
    ).toEqual({ type: "recorded", message: "Approved — Alert Zero is applying the action", tone: "success", watch: true });
    expect(interpretDecisionResult("approve", { ok: true, decisionRecorded: true }, withAction)).toMatchObject({ watch: true });
  });

  it("reports an action that already settled instead of watching it", () => {
    const outcome = interpretDecisionResult(
      "approve",
      { ok: true, decisionRecorded: true, proposal: proposal({ decision: "approved", status: "succeeded" }) },
      withAction,
    );
    expect(outcome).toEqual({ type: "recorded", message: 'Applied — "Isolate host-7"', tone: "success", watch: false });
  });

  it("does not watch no-action approvals or declines", () => {
    expect(interpretDecisionResult("approve", { ok: true, decisionRecorded: true }, noAction)).toEqual({
      type: "recorded",
      message: "Approved",
      tone: "success",
      watch: false,
    });
    expect(interpretDecisionResult("dismiss", { ok: true, decisionRecorded: true }, withAction)).toEqual({
      type: "recorded",
      message: "Declined",
      tone: "success",
      watch: false,
    });
  });

  it("distinguishes submitted-but-unrecorded, conflict, forbidden and other errors", () => {
    expect(interpretDecisionResult("approve", { ok: true, decisionRecorded: false }, withAction)).toEqual({
      type: "submitted",
      message: "Decision submitted — Alert Zero is still recording it",
    });
    expect(
      interpretDecisionResult("approve", { ok: false, decisionRecorded: false, httpStatus: 409, error: "conflict" }, withAction),
    ).toEqual({ type: "conflict", message: CONFLICT_MESSAGE });
    expect(
      interpretDecisionResult("dismiss", { ok: false, decisionRecorded: false, httpStatus: 403, error: "Kibana returned 403" }, withAction),
    ).toEqual({ type: "error", message: FORBIDDEN_MESSAGE, detail: "Kibana returned 403" });
    expect(interpretDecisionResult("dismiss", { ok: false, decisionRecorded: false, error: "boom" }, withAction)).toEqual({
      type: "error",
      message: "boom",
    });
    expect(interpretDecisionResult("dismiss", { ok: false, decisionRecorded: false }, withAction).type).toBe("error");
  });
});

describe("labels", () => {
  it("describes what is being waited on", () => {
    expect(watchingLabel(proposal({ decision: "approved" }), "applying")).toBe("Applying… typically takes 3–5 minutes");
    expect(watchingLabel(proposal(), "recording")).toBe("Recording your decision…");
    expect(watchingLabel(proposal({ decision: "approved" }), "recording")).toBe("Applying… typically takes 3–5 minutes");
    expect(watchingLabel(proposal({ decision: "approved", actionWorkflowId: undefined }), "applying")).toBe("Finishing up…");
    expect(stillWaitingMessage(proposal())).toMatch(/hasn't recorded/);
    expect(stillWaitingMessage(proposal({ decision: "approved" }))).toMatch(/^Still applying/);
  });

  it("summarises the settled state", () => {
    expect(settledToast(proposal({ decision: "approved", status: "succeeded" }))).toEqual({
      message: 'Applied — "Isolate host-7"',
      tone: "success",
    });
    expect(
      settledToast(proposal({ decision: "approved", status: "failed", executionError: "Agent offline", supersededBy: "p2" })),
    ).toEqual({
      message: 'Action failed — "Isolate host-7": Agent offline. Alert Zero re-offered it as a new proposal.',
      tone: "danger",
    });
    expect(settledToast(proposal({ decision: "approved", status: "no_action" })).tone).toBe("info");
    expect(settledToast(proposal({ status: "expired" })).message).toMatch(/expired/);
  });
});
