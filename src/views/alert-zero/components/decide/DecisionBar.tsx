/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useEffect, useId, useReducer, useRef, useState } from "react";
import classNames from "classnames";
import { useToast } from "../../../../shared/components";
import type {
  AlertZeroDecisionResult,
  AlertZeroProposalDetail,
  DismissReason,
  ProposalWithMetadata,
} from "../../../../shared/alert-zero-types";
import { ALERT_ZERO_APP_TOOLS, type AlertZeroApi } from "../../api";
import type { LoadedProposalDetail } from "../../types";
import { parseTime } from "../detail/helpers";
import { ApproveDialog, type DialogError } from "./ApproveDialog";
import { DeclineDialog } from "./DeclineDialog";
import { Spinner } from "./DecisionDialog";
import {
  APPLY_POLL_INTERVAL_MS,
  APPLY_POLL_MAX_ATTEMPTS,
  approveArgs,
  approveButtonTone,
  decisionAvailability,
  dismissArgs,
  interpretDecisionResult,
  isApplying,
  isSettled,
  proposalImpact,
  settledToast,
  stillWaitingMessage,
  watchingLabel,
  type DecisionKind,
} from "./decision";
import "./decide.css";

export interface DecisionBarProps {
  readonly loaded: LoadedProposalDetail;
  readonly reload: () => void;
  readonly api: AlertZeroApi;
  readonly spaceId: string;
  /** Refresh the proposal list (and the open detail) after a decision settles. */
  readonly onDecided: () => void;
}

interface Watch {
  readonly mode: "applying" | "recording";
}

type WatchEnd =
  | { readonly type: "settled"; readonly proposal: ProposalWithMetadata }
  | { readonly type: "timeout"; readonly proposal: ProposalWithMetadata };

interface OpenDialog {
  readonly kind: DecisionKind;
  readonly proposal: ProposalWithMetadata;
}

const MAX_TIMER_MS = 2 ** 31 - 1;

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Re-render once the deadline passes so the buttons disable themselves. */
function useDeadlineTick(expiresAt: string | undefined): void {
  const [, tick] = useReducer((n: number) => n + 1, 0);
  useEffect(() => {
    const t = parseTime(expiresAt);
    if (t === undefined) return;
    const delay = t - Date.now();
    if (delay <= 0 || delay >= MAX_TIMER_MS) return;
    const timer = setTimeout(tick, delay + 50);
    return () => clearTimeout(timer);
  }, [expiresAt]);
}

export function DecisionBar({ loaded, reload, api, spaceId, onDecided }: DecisionBarProps) {
  const toast = useToast();
  const p = loaded.detail.proposal;
  useDeadlineTick(p.expiresAt);

  const [dialog, setDialog] = useState<OpenDialog | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<DialogError | undefined>();
  const [decided, setDecided] = useState(false);
  const [watch, setWatchState] = useState<Watch | null>(null);
  const [ended, setEnded] = useState<"settled" | "stopped" | null>(null);
  const [polled, setPolled] = useState<ProposalWithMetadata | undefined>();
  const noteId = useId();

  const watchRef = useRef<Watch | null>(null);
  const mounted = useRef(true);
  const live = useRef({ reload, onDecided, toast });
  live.current = { reload, onDecided, toast };

  const setWatch = useCallback((next: Watch | null) => {
    watchRef.current = next;
    setWatchState(next);
    setPolled(undefined);
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const applying = isApplying(p);
  const watching = watch !== null;
  const proposalId = p.id;
  const proposalRef = useRef(p);
  proposalRef.current = p;

  useEffect(() => {
    if (applying && ended === null && !watchRef.current) setWatch({ mode: "applying" });
  }, [applying, ended, setWatch]);

  const finish = useCallback(
    (end: WatchEnd) => {
      setWatch(null);
      const { toast: t, reload: r, onDecided: done } = live.current;
      if (end.type === "settled") {
        setEnded("settled");
        t.show(settledToast(end.proposal));
      } else {
        setEnded("stopped");
        t.show({ message: stillWaitingMessage(end.proposal), tone: "info" });
      }
      r();
      done();
    },
    [setWatch],
  );

  useEffect(() => {
    if (!watching) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempts = 0;
    let last: ProposalWithMetadata | undefined;
    const tick = async () => {
      attempts += 1;
      try {
        const next = await api.callTool<AlertZeroProposalDetail>(ALERT_ZERO_APP_TOOLS.detail, { proposalId, spaceId });
        if (cancelled) return;
        last = next.proposal;
        setPolled(next.proposal);
      } catch {
        if (cancelled) return;
      }
      if (last && isSettled(last)) {
        finish({ type: "settled", proposal: last });
        return;
      }
      if (attempts >= APPLY_POLL_MAX_ATTEMPTS) {
        finish({ type: "timeout", proposal: last ?? proposalRef.current });
        return;
      }
      timer = setTimeout(() => void tick(), APPLY_POLL_INTERVAL_MS);
    };
    timer = setTimeout(() => void tick(), APPLY_POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [watching, api, proposalId, spaceId, finish]);

  const stopWatching = () => {
    setWatch(null);
    setEnded("stopped");
    reload();
  };

  const openDialog = (kind: DecisionKind) => {
    setError(undefined);
    setDialog({ kind, proposal: p });
  };

  const closeDialog = () => {
    if (!submitting) setDialog(null);
  };

  const submit = async (kind: DecisionKind, snapshot: ProposalWithMetadata, args: Record<string, unknown>) => {
    setSubmitting(true);
    setError(undefined);
    let result: AlertZeroDecisionResult;
    try {
      result = await api.callTool<AlertZeroDecisionResult>(
        kind === "approve" ? ALERT_ZERO_APP_TOOLS.approve : ALERT_ZERO_APP_TOOLS.dismiss,
        args,
      );
    } catch (e) {
      if (mounted.current) {
        setSubmitting(false);
        setError({ message: errorMessage(e) });
      }
      return;
    }
    const outcome = interpretDecisionResult(kind, result, snapshot);
    const { toast: t, reload: r, onDecided: done } = live.current;
    if (!mounted.current) {
      if (outcome.type !== "error") done();
      return;
    }
    setSubmitting(false);
    switch (outcome.type) {
      case "error":
        setError({ message: outcome.message, detail: outcome.detail });
        return;
      case "conflict":
        t.show({ message: outcome.message, tone: "info" });
        setDialog(null);
        r();
        done();
        return;
      case "submitted":
        t.show({ message: outcome.message, tone: "info" });
        setDialog(null);
        setDecided(true);
        setEnded(null);
        setWatch({ mode: "recording" });
        r();
        done();
        return;
      case "recorded":
        t.show({ message: outcome.message, tone: outcome.tone });
        setDialog(null);
        setDecided(true);
        r();
        done();
        if (outcome.watch) {
          setEnded(null);
          setWatch({ mode: "applying" });
        }
        return;
    }
  };

  let content: React.ReactNode = null;
  if (watch || (applying && ended === null)) {
    content = (
      <div className="azdec-status" role="status">
        <Spinner />
        <span className="azdec-status-text">{watchingLabel(polled ?? p, watch?.mode ?? "applying")}</span>
        <button type="button" className="azd-btn azd-btn--sm azd-btn--ghost" onClick={stopWatching}>
          Stop watching
        </button>
      </div>
    );
  } else if (applying) {
    content =
      ended === "stopped" ? (
        <div className="azdec-status azdec-status--idle" role="status">
          <span className="azdec-status-text">Still applying. Watch again or reload the proposal for the result.</span>
          <button type="button" className="azd-btn azd-btn--sm azd-btn--ghost" onClick={() => setEnded(null)}>
            Watch again
          </button>
        </div>
      ) : null;
  } else if (!decided) {
    const availability = decisionAvailability(loaded.detail, Date.now());
    if (availability.kind === "decide") {
      const reason = availability.disabledReason;
      const disabled = Boolean(reason);
      const describedBy = disabled ? noteId : undefined;
      content = (
        <div className="azdec-bar">
          {reason && (
            <p id={noteId} className="azdec-note" role="note">
              {reason}
            </p>
          )}
          <div className="azdec-buttons" title={reason}>
            <button
              type="button"
              className="azd-btn azdec-btn"
              disabled={disabled}
              aria-describedby={describedBy}
              aria-haspopup="dialog"
              onClick={() => openDialog("dismiss")}
            >
              Decline
            </button>
            <button
              type="button"
              className={classNames("azd-btn azdec-btn", `azdec-btn--${approveButtonTone(proposalImpact(p))}`)}
              disabled={disabled}
              aria-describedby={describedBy}
              aria-haspopup="dialog"
              onClick={() => openDialog("approve")}
            >
              Approve
            </button>
          </div>
        </div>
      );
    }
  }

  return (
    <>
      {content}
      {dialog?.kind === "approve" && (
        <ApproveDialog
          proposal={dialog.proposal}
          submitting={submitting}
          error={error}
          onCancel={closeDialog}
          onConfirm={(rationale) =>
            void submit("approve", dialog.proposal, approveArgs(dialog.proposal, rationale, spaceId))
          }
        />
      )}
      {dialog?.kind === "dismiss" && (
        <DeclineDialog
          proposal={dialog.proposal}
          submitting={submitting}
          error={error}
          onCancel={closeDialog}
          onConfirm={(reason: DismissReason, rationale) =>
            void submit("dismiss", dialog.proposal, dismissArgs(dialog.proposal.id, reason, rationale, spaceId))
          }
        />
      )}
    </>
  );
}
