/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from "react";
import classNames from "classnames";
import {
  summarizeActionTargets,
  type ProposalImpact,
  type ProposalWithMetadata,
} from "../../../../shared/alert-zero-types";
import { humanize, sentenceCase, type BadgeTone } from "../detail/helpers";
import { WarningIcon } from "../detail/icons";
import { Badge, Collapsible, JsonBlock } from "../detail/primitives";
import { DecisionDialog, InlineError, RationaleField, Spinner } from "./DecisionDialog";
import {
  RATIONALE_MAX,
  approveButtonTone,
  hasAutomatedAction,
  proposalImpact,
  validateRationale,
} from "./decision";

export interface DialogError {
  readonly message: string;
  readonly detail?: string;
}

export interface ApproveDialogProps {
  /** Snapshot taken when the dialog opened; its `actionInput` is exactly what gets sent. */
  readonly proposal: ProposalWithMetadata;
  readonly submitting: boolean;
  readonly error?: DialogError;
  readonly onCancel: () => void;
  readonly onConfirm: (rationale: string) => void;
}

function impactBadgeTone(impact: ProposalImpact): BadgeTone {
  if (approveButtonTone(impact) === "danger") return "danger";
  return impact === "medium" ? "warning" : "hollow";
}

function actionName(p: ProposalWithMetadata): string {
  if (p.action?.name) return p.action.name;
  if (p.actionWorkflowId) return humanize(p.actionWorkflowId.replace(/^system-alertzero-action-/, ""));
  return "No automated action";
}

export function ApproveDialog({ proposal: p, submitting, error, onCancel, onConfirm }: ApproveDialogProps) {
  const [rationale, setRationale] = useState("");
  const withAction = hasAutomatedAction(p);
  const impact = proposalImpact(p);
  const tone = approveButtonTone(impact);
  const category = p.category ?? p.action?.category;
  const reversible = p.action?.reversible;
  const targets = withAction ? summarizeActionTargets(p.actionWorkflowId, p.actionInput) : [];
  const rationaleError = validateRationale(rationale);

  return (
    <DecisionDialog
      title={`Approve "${p.title}"?`}
      onClose={onCancel}
      busy={submitting}
      className="azdec-dialog--approve"
      footer={
        <>
          <button type="button" className="azd-btn" onClick={onCancel} disabled={submitting}>
            Cancel
          </button>
          <button
            type="button"
            className={classNames("azd-btn azdec-btn", `azdec-btn--${tone}`)}
            onClick={() => onConfirm(rationale)}
            disabled={submitting || Boolean(rationaleError)}
          >
            {submitting && <Spinner />}
            {withAction ? "Approve and run" : "Approve"}
          </button>
        </>
      }
    >
      <section className="azdec-action" aria-label="Action">
        <div className="azdec-action-name">{actionName(p)}</div>
        {p.action?.description && <p className="azdec-action-desc">{p.action.description}</p>}
        <div className="azd-badges">
          {impact && <Badge tone={impactBadgeTone(impact)}>{sentenceCase(impact)} impact</Badge>}
          {reversible !== undefined && (
            <Badge tone={reversible ? "success" : "warning"}>{reversible ? "Reversible" : "Irreversible"}</Badge>
          )}
          {category && <Badge tone="hollow">{sentenceCase(category)}</Badge>}
        </div>
      </section>

      {withAction ? (
        <section className="azdec-run" aria-label="This will run">
          <div className="azdec-run-label">This will run:</div>
          {targets.length > 0 && (
            <div className="azd-chips">
              {targets.map((t, i) => (
                <span key={`${t}-${i}`} className="az-chip azd-chip--sans" title={t}>
                  {t}
                </span>
              ))}
            </div>
          )}
          <Collapsible title="Exact action input (JSON)">
            <JsonBlock value={p.actionInput ?? {}} label="action input JSON" />
          </Collapsible>
        </section>
      ) : (
        <p className="azdec-note azdec-note--block">Approving records your decision; no automated action runs.</p>
      )}

      {withAction && reversible === false && (
        <div className="azdec-warning" role="note">
          <WarningIcon size={13} />
          <span>This action is irreversible — it can't be undone once it runs.</span>
        </div>
      )}

      <RationaleField
        label="Rationale"
        hint="(optional)"
        placeholder="Why are you approving? Saved with the decision."
        value={rationale}
        onChange={setRationale}
        error={rationaleError}
        disabled={submitting}
        autoFocus
        max={RATIONALE_MAX}
      />

      {error && <InlineError message={error.message} detail={error.detail} />}
    </DecisionDialog>
  );
}
