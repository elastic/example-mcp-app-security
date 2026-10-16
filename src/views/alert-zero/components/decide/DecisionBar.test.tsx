/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { ToastProvider } from "../../../../shared/components";
import {
  DISMISS_REASONS,
  DISMISS_REASON_LABELS,
  toProposalCard,
  type AlertZeroDecisionResult,
  type AlertZeroProposalDetail,
} from "../../../../shared/alert-zero-types";
import { ALERT_ZERO_APP_TOOLS, type AlertZeroApi } from "../../api";
import type { LoadedProposalDetail } from "../../types";
import { ProposalDetail } from "../detail/ProposalDetail";
import { FULL_PROPOSAL, makeDetail, makeInvestigation } from "../detail/testFixtures";
import { DecisionBar } from "./DecisionBar";
import {
  APPLY_POLL_INTERVAL_MS,
  APPLY_POLL_MAX_ATTEMPTS,
  CONFLICT_MESSAGE,
  FORBIDDEN_MESSAGE,
  NO_PRIVILEGE_REASON,
  OTHER_RATIONALE_REQUIRED,
  PAST_DEADLINE_REASON,
} from "./decision";

type DetailProposal = AlertZeroProposalDetail["proposal"];
type Handler = (args: Record<string, unknown>) => unknown;

const SPACE = "soc-space";
const TITLE = FULL_PROPOSAL.title;

function awaiting(overrides: Partial<DetailProposal> = {}): DetailProposal {
  return {
    ...FULL_PROPOSAL,
    status: "pending",
    decision: undefined,
    decidedBy: undefined,
    decidedAt: undefined,
    dismissReason: undefined,
    rationale: undefined,
    executionError: undefined,
    supersededBy: undefined,
    ...overrides,
  };
}

function detailFor(proposal: DetailProposal, overrides: Partial<AlertZeroProposalDetail> = {}): AlertZeroProposalDetail {
  return { ...makeDetail(), proposal, ...overrides };
}

function makeApi(handlers: Partial<Record<string, Handler>> = {}) {
  const callTool = vi.fn(async (name: string, args: Record<string, unknown>) => {
    const handler = handlers[name];
    if (!handler) throw new Error(`unexpected tool ${name}`);
    return handler(args);
  });
  const api = { callTool, openLink: vi.fn(), sendMessage: vi.fn(), downloadFile: vi.fn() };
  return api as typeof api & AlertZeroApi;
}

function callsTo(api: ReturnType<typeof makeApi>, name: string): Record<string, unknown>[] {
  return api.callTool.mock.calls.filter(([n]) => n === name).map(([, args]) => args);
}

function renderBar(api: AlertZeroApi, loaded: LoadedProposalDetail) {
  const reload = vi.fn();
  const onDecided = vi.fn();
  const utils = render(
    <ToastProvider>
      <DecisionBar loaded={loaded} reload={reload} api={api} spaceId={SPACE} onDecided={onDecided} />
    </ToastProvider>,
  );
  return { ...utils, reload, onDecided };
}

function openApprove(): HTMLElement {
  fireEvent.click(screen.getByRole("button", { name: "Approve" }));
  return screen.getByRole("dialog", { name: `Approve "${TITLE}"?` });
}

function openDecline(): HTMLElement {
  fireEvent.click(screen.getByRole("button", { name: "Decline" }));
  return screen.getByRole("dialog", { name: `Decline "${TITLE}"?` });
}

const recorded = (proposal?: DetailProposal): AlertZeroDecisionResult => ({ ok: true, decisionRecorded: true, proposal });

describe("DecisionBar — awaiting a decision", () => {
  it("shows Decline and a danger Approve for high-impact proposals", () => {
    renderBar(makeApi(), { detail: detailFor(awaiting()) });
    expect(screen.getByRole("button", { name: "Decline" })).toBeEnabled();
    const approve = screen.getByRole("button", { name: "Approve" });
    expect(approve).toBeEnabled();
    expect(approve).toHaveClass("azdec-btn--danger");
  });

  it("uses the primary tone for low-impact proposals", () => {
    renderBar(makeApi(), { detail: detailFor(awaiting({ impact: "low" })) });
    expect(screen.getByRole("button", { name: "Approve" })).toHaveClass("azdec-btn--primary");
  });

  it("disables both buttons and explains why without the decide privilege", () => {
    renderBar(makeApi(), { detail: detailFor(awaiting(), { canDecide: false }) });
    const note = screen.getByText(NO_PRIVILEGE_REASON);
    for (const name of ["Decline", "Approve"]) {
      const button = screen.getByRole("button", { name });
      expect(button).toBeDisabled();
      expect(button).toHaveAttribute("aria-describedby", note.id);
    }
  });

  it("disables both buttons past the deadline", () => {
    renderBar(makeApi(), { detail: detailFor(awaiting({ expiresAt: "2020-01-01T00:00:00.000Z" })) });
    expect(screen.getByText(PAST_DEADLINE_REASON)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Decline" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled();
  });

  it("renders nothing for a decided proposal", () => {
    const { container } = renderBar(makeApi(), {
      detail: detailFor(awaiting({ decision: "approved", status: "succeeded" })),
    });
    expect(container).toBeEmptyDOMElement();
  });
});

describe("DecisionBar — approve", () => {
  it("confirms, then sends exactly the displayed actionInput with the rationale and space", async () => {
    const proposal = awaiting();
    const api = makeApi({
      [ALERT_ZERO_APP_TOOLS.approve]: () => recorded({ ...proposal, decision: "approved", status: "executing" }),
    });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(proposal) });

    const dialog = openApprove();
    expect(dialog).toHaveAttribute("aria-modal", "true");
    for (const text of [
      "Isolate host",
      "Isolates Elastic Defend endpoints from the network.",
      "High impact",
      "Reversible",
      "Respond",
      "This will run:",
      "2 endpoints",
    ]) {
      expect(dialog.textContent, text).toContain(text);
    }
    const rationale = within(dialog).getByRole("textbox", { name: /Rationale/ });
    expect(rationale).toHaveFocus();

    fireEvent.click(within(dialog).getByRole("button", { name: /Exact action input/ }));
    expect(dialog.querySelector("pre")?.textContent).toBe(JSON.stringify(proposal.actionInput, null, 2));

    fireEvent.change(rationale, { target: { value: "  Confirmed with the IR lead  " } });
    expect(within(dialog).getByText("30 / 4,096")).toBeInTheDocument();
    const confirm = within(dialog).getByRole("button", { name: "Approve and run" });
    expect(confirm).toHaveClass("azdec-btn--danger");
    fireEvent.click(confirm);

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const [args] = callsTo(api, ALERT_ZERO_APP_TOOLS.approve);
    expect(args).toEqual({
      proposalId: proposal.id,
      actionInput: proposal.actionInput,
      rationale: "Confirmed with the IR lead",
      spaceId: SPACE,
    });
    expect(args.actionInput).toBe(proposal.actionInput);
    expect(screen.getByText("Approved — Alert Zero is applying the action")).toBeInTheDocument();
    expect(screen.getByText("Applying… typically takes 3–5 minutes")).toBeInTheDocument();
    expect(reload).toHaveBeenCalledTimes(1);
    expect(onDecided).toHaveBeenCalledTimes(1);
  });

  it("warns about irreversible actions", () => {
    renderBar(makeApi(), { detail: detailFor(awaiting({ action: { ...FULL_PROPOSAL.action!, reversible: false } })) });
    const dialog = openApprove();
    expect(dialog.textContent).toContain("Irreversible");
    expect(dialog.textContent).toContain("This action is irreversible");
  });

  it("explains that approving a no-action proposal only records the decision", async () => {
    const proposal = awaiting({ actionWorkflowId: undefined, actionInput: undefined, action: undefined, impact: "low" });
    const api = makeApi({ [ALERT_ZERO_APP_TOOLS.approve]: () => recorded() });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(proposal) });

    const dialog = openApprove();
    expect(dialog.textContent).toContain("Approving records your decision; no automated action runs.");
    expect(dialog.textContent).not.toContain("This will run:");
    const confirm = within(dialog).getByRole("button", { name: "Approve" });
    expect(confirm).toHaveClass("azdec-btn--primary");
    fireEvent.click(confirm);

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.approve)[0]).toEqual({
      proposalId: proposal.id,
      actionInput: undefined,
      rationale: undefined,
      spaceId: SPACE,
    });
    expect(screen.getByText("Approved")).toBeInTheDocument();
    expect(reload).toHaveBeenCalledTimes(1);
    expect(onDecided).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/Applying…/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("disables the dialog while submitting and ignores Escape", async () => {
    let resolve!: (r: AlertZeroDecisionResult) => void;
    const api = makeApi({
      [ALERT_ZERO_APP_TOOLS.approve]: () => new Promise<AlertZeroDecisionResult>((r) => (resolve = r)),
    });
    renderBar(api, { detail: detailFor(awaiting()) });
    const dialog = openApprove();
    fireEvent.click(within(dialog).getByRole("button", { name: "Approve and run" }));

    expect(within(dialog).getByRole("button", { name: "Approve and run" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeDisabled();
    expect(within(dialog).getByRole("textbox", { name: /Rationale/ })).toBeDisabled();
    expect(dialog).toHaveAttribute("aria-busy", "true");
    fireEvent.keyDown(document, { key: "Escape" });
    fireEvent.mouseDown(screen.getByTestId("azdec-overlay"));
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    await act(async () => resolve(recorded()));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("closes and refreshes on a 409 conflict", async () => {
    const api = makeApi({
      [ALERT_ZERO_APP_TOOLS.approve]: () => ({
        ok: false,
        decisionRecorded: false,
        httpStatus: 409,
        error: "Kibana returned 409: actionInput does not match",
      }),
    });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(awaiting()) });
    fireEvent.click(within(openApprove()).getByRole("button", { name: "Approve and run" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.getByText(CONFLICT_MESSAGE)).toBeInTheDocument();
    expect(reload).toHaveBeenCalledTimes(1);
    expect(onDecided).toHaveBeenCalledTimes(1);
  });

  it("keeps the dialog open with an inline error for 403s and thrown errors", async () => {
    let attempt = 0;
    const api = makeApi({
      [ALERT_ZERO_APP_TOOLS.approve]: () => {
        attempt += 1;
        if (attempt === 1) return { ok: false, decisionRecorded: false, httpStatus: 403, error: "Kibana returned 403: forbidden" };
        throw new Error("Not connected to the MCP host");
      },
    });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(awaiting()) });
    const dialog = openApprove();
    const confirm = within(dialog).getByRole("button", { name: "Approve and run" });

    fireEvent.click(confirm);
    const alert = await within(dialog).findByRole("alert");
    expect(alert.textContent).toContain(FORBIDDEN_MESSAGE);
    expect(alert.textContent).toContain("Kibana returned 403: forbidden");
    expect(confirm).toBeEnabled();

    fireEvent.click(confirm);
    await waitFor(() => expect(within(dialog).getByRole("alert").textContent).toBe("Not connected to the MCP host"));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(reload).not.toHaveBeenCalled();
    expect(onDecided).not.toHaveBeenCalled();
  });
});

describe("DecisionBar — decline", () => {
  it("offers every reason and requires a rationale for Other", async () => {
    const proposal = awaiting();
    const api = makeApi({ [ALERT_ZERO_APP_TOOLS.dismiss]: () => recorded({ ...proposal, decision: "dismissed" }) });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(proposal) });
    const dialog = openDecline();

    const radios = within(dialog).getAllByRole("radio");
    expect(radios.map((r) => (r as HTMLInputElement).value)).toEqual([...DISMISS_REASONS]);
    for (const reason of DISMISS_REASONS) {
      expect(within(dialog).getByRole("radio", { name: DISMISS_REASON_LABELS[reason] })).toBeInTheDocument();
    }
    const noReason = within(dialog).getByRole("radio", { name: "No reason" });
    expect(noReason).toBeChecked();
    expect(noReason).toHaveFocus();

    const confirm = within(dialog).getByRole("button", { name: "Decline" });
    expect(confirm).toBeEnabled();
    fireEvent.click(within(dialog).getByRole("radio", { name: "Other" }));
    expect(within(dialog).getByText(OTHER_RATIONALE_REQUIRED)).toBeInTheDocument();
    const rationale = within(dialog).getByRole("textbox", { name: /Rationale/ });
    expect(rationale).toHaveAttribute("aria-required", "true");
    expect(rationale).toHaveAttribute("aria-invalid", "true");
    expect(confirm).toBeDisabled();

    fireEvent.change(rationale, { target: { value: "  Owned by the network team  " } });
    expect(within(dialog).queryByText(OTHER_RATIONALE_REQUIRED)).toBeNull();
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.dismiss)).toEqual([
      { proposalId: proposal.id, dismissReason: "other", rationale: "Owned by the network team", spaceId: SPACE },
    ]);
    expect(screen.getByText("Declined")).toBeInTheDocument();
    expect(reload).toHaveBeenCalledTimes(1);
    expect(onDecided).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "Decline" })).toBeNull();
  });

  it("sends the chosen reason without a rationale when it is optional", async () => {
    const api = makeApi({ [ALERT_ZERO_APP_TOOLS.dismiss]: () => recorded() });
    renderBar(api, { detail: detailFor(awaiting()) });
    const dialog = openDecline();
    fireEvent.click(within(dialog).getByRole("radio", { name: "False positive" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Decline" }));
    await waitFor(() => expect(callsTo(api, ALERT_ZERO_APP_TOOLS.dismiss)).toHaveLength(1));
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.dismiss)[0]).toEqual({
      proposalId: FULL_PROPOSAL.id,
      dismissReason: "false_positive",
      rationale: undefined,
      spaceId: SPACE,
    });
  });

  it("tells the user when the decision is submitted but not recorded yet", async () => {
    const api = makeApi({ [ALERT_ZERO_APP_TOOLS.dismiss]: () => ({ ok: true, decisionRecorded: false }) });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(awaiting()) });
    fireEvent.click(within(openDecline()).getByRole("button", { name: "Decline" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.getByText("Decision submitted — Alert Zero is still recording it")).toBeInTheDocument();
    expect(screen.getByText("Recording your decision…")).toBeInTheDocument();
    expect(reload).toHaveBeenCalledTimes(1);
    expect(onDecided).toHaveBeenCalledTimes(1);
  });
});

describe("DecisionBar — dialog behaviour", () => {
  it("closes on Escape and outside clicks, restores focus, and traps Tab", () => {
    renderBar(makeApi(), { detail: detailFor(awaiting()) });
    const declineButton = screen.getByRole("button", { name: "Decline" });
    declineButton.focus();
    openDecline();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(declineButton).toHaveFocus();

    let dialog = openApprove();
    fireEvent.mouseDown(dialog);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByTestId("azdec-overlay"));
    expect(screen.queryByRole("dialog")).toBeNull();

    dialog = openApprove();
    const confirm = within(dialog).getByRole("button", { name: "Approve and run" });
    confirm.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.activeElement).not.toBe(confirm);
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("DecisionBar — applying", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const executing = () => awaiting({ decision: "approved", status: "executing" });

  function detailSequence(...proposals: DetailProposal[]): Handler {
    return () => detailFor(proposals.length > 1 ? proposals.shift()! : proposals[0]);
  }

  async function advance(ms: number) {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });
  }

  it("polls every 3s and stops once the action settles", async () => {
    const api = makeApi({
      [ALERT_ZERO_APP_TOOLS.detail]: detailSequence(executing(), executing(), { ...executing(), status: "succeeded" }),
    });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(executing()) });
    expect(screen.getByText("Applying… typically takes 3–5 minutes")).toBeInTheDocument();
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(0);

    await advance(APPLY_POLL_INTERVAL_MS);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toEqual([{ proposalId: FULL_PROPOSAL.id, spaceId: SPACE }]);
    await advance(APPLY_POLL_INTERVAL_MS);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(2);
    expect(reload).not.toHaveBeenCalled();

    await advance(APPLY_POLL_INTERVAL_MS);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(3);
    expect(reload).toHaveBeenCalledTimes(1);
    expect(onDecided).toHaveBeenCalledTimes(1);
    expect(screen.getByText(`Applied — "${TITLE}"`)).toBeInTheDocument();
    expect(screen.queryByText(/Applying…/)).toBeNull();

    await advance(APPLY_POLL_INTERVAL_MS * 10);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(3);
  });

  it("reports a failed action, including the re-offered clone", async () => {
    const api = makeApi({
      [ALERT_ZERO_APP_TOOLS.detail]: detailSequence({
        ...executing(),
        status: "failed",
        executionError: "Endpoint agent offline",
        supersededBy: "prop-next-0003",
      }),
    });
    renderBar(api, { detail: detailFor(executing()) });
    await advance(APPLY_POLL_INTERVAL_MS);
    expect(
      screen.getByText(`Action failed — "${TITLE}": Endpoint agent offline. Alert Zero re-offered it as a new proposal.`),
    ).toBeInTheDocument();
  });

  it("stops when the user stops watching, and can resume", async () => {
    const api = makeApi({ [ALERT_ZERO_APP_TOOLS.detail]: detailSequence(executing()) });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(executing()) });
    await advance(APPLY_POLL_INTERVAL_MS);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(1);

    fireEvent.click(screen.getByRole("button", { name: "Stop watching" }));
    expect(reload).toHaveBeenCalledTimes(1);
    expect(onDecided).not.toHaveBeenCalled();
    await advance(APPLY_POLL_INTERVAL_MS * 5);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(1);
    expect(screen.getByText(/Still applying\. Watch again/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Watch again" }));
    expect(screen.getByText("Applying… typically takes 3–5 minutes")).toBeInTheDocument();
    await advance(APPLY_POLL_INTERVAL_MS);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(2);
  });

  it("stops polling on unmount", async () => {
    const api = makeApi({ [ALERT_ZERO_APP_TOOLS.detail]: detailSequence(executing()) });
    const { unmount, onDecided } = renderBar(api, { detail: detailFor(executing()) });
    unmount();
    await advance(APPLY_POLL_INTERVAL_MS * 5);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(0);
    expect(onDecided).not.toHaveBeenCalled();
  });

  it("gives up after about three minutes", async () => {
    const api = makeApi({ [ALERT_ZERO_APP_TOOLS.detail]: detailSequence(executing()) });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(executing()) });
    await advance(APPLY_POLL_INTERVAL_MS * APPLY_POLL_MAX_ATTEMPTS);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(APPLY_POLL_MAX_ATTEMPTS);
    expect(screen.getByText(/^Still applying — Alert Zero will finish in the background/)).toBeInTheDocument();
    expect(reload).toHaveBeenCalledTimes(1);
    expect(onDecided).toHaveBeenCalledTimes(1);
    await advance(APPLY_POLL_INTERVAL_MS * 5);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(APPLY_POLL_MAX_ATTEMPTS);
  });

  it("after approving, refreshes the list right away and again once the action settles", async () => {
    const proposal = awaiting();
    const api = makeApi({
      [ALERT_ZERO_APP_TOOLS.approve]: () => recorded({ ...proposal, decision: "approved", status: "pending" }),
      [ALERT_ZERO_APP_TOOLS.detail]: detailSequence(executing(), { ...executing(), status: "succeeded" }),
    });
    const { reload, onDecided } = renderBar(api, { detail: detailFor(proposal) });
    fireEvent.click(within(openApprove()).getByRole("button", { name: "Approve and run" }));
    await advance(0);

    expect(screen.queryByRole("dialog")).toBeNull();
    expect(reload).toHaveBeenCalledTimes(1);
    expect(onDecided).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Applying… typically takes 3–5 minutes")).toBeInTheDocument();

    await advance(APPLY_POLL_INTERVAL_MS * 2);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(2);
    expect(reload).toHaveBeenCalledTimes(2);
    expect(onDecided).toHaveBeenCalledTimes(2);
  });

  it("stops polling when the pane closes mid-apply", async () => {
    const api = makeApi({
      [ALERT_ZERO_APP_TOOLS.approve]: () => recorded({ ...awaiting(), decision: "approved", status: "executing" }),
      [ALERT_ZERO_APP_TOOLS.detail]: detailSequence(executing()),
    });
    const { unmount, onDecided } = renderBar(api, { detail: detailFor(awaiting()) });
    fireEvent.click(within(openApprove()).getByRole("button", { name: "Approve and run" }));
    await advance(0);
    expect(onDecided).toHaveBeenCalledTimes(1);
    unmount();
    await advance(APPLY_POLL_INTERVAL_MS * 3);
    expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(0);
    expect(onDecided).toHaveBeenCalledTimes(1);
  });
});

describe("DecisionBar — inside ProposalDetail", () => {
  it("renders in the footer slot and reloads the detail after a decline", async () => {
    let proposal = awaiting();
    const api = makeApi({
      [ALERT_ZERO_APP_TOOLS.detail]: () => detailFor(proposal),
      [ALERT_ZERO_APP_TOOLS.investigation]: () => makeInvestigation(),
      [ALERT_ZERO_APP_TOOLS.dismiss]: () => {
        proposal = { ...proposal, decision: "dismissed", dismissReason: "duplicate" };
        return recorded(proposal);
      },
    });
    const onDecided = vi.fn();
    const { container } = render(
      <ToastProvider>
        <ProposalDetail
          card={toProposalCard(proposal)}
          spaceId={SPACE}
          kibanaUrl="http://kibana.test"
          api={api}
          renderFooterActions={(loaded, reload) => (
            <DecisionBar loaded={loaded} reload={reload} api={api} spaceId={SPACE} onDecided={onDecided} />
          )}
        />
      </ToastProvider>,
    );
    await waitFor(() => expect(container.querySelector(".azd-footer-actions button")).toBeTruthy());
    const footer = container.querySelector(".azd-footer-actions") as HTMLElement;
    expect(within(footer).getByRole("button", { name: "Decline" })).toBeInTheDocument();

    const dialog = openDecline();
    fireEvent.click(within(dialog).getByRole("radio", { name: "Duplicate" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Decline" }));

    await waitFor(() => expect(callsTo(api, ALERT_ZERO_APP_TOOLS.detail)).toHaveLength(2));
    await waitFor(() => expect(container.querySelector('[data-section="Outcome"]')?.textContent).toContain("Duplicate"));
    expect(onDecided).toHaveBeenCalledTimes(1);
    expect(within(footer).queryByRole("button", { name: "Approve" })).toBeNull();
  });
});
