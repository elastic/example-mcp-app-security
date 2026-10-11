/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState } from "react";
import {
  DISMISS_REASONS,
  DISMISS_REASON_LABELS,
  type DismissReason,
  type ProposalWithMetadata,
} from "../../../../shared/alert-zero-types";
import { DecisionDialog, InlineError, RationaleField, Spinner } from "./DecisionDialog";
import type { DialogError } from "./ApproveDialog";
import { RATIONALE_MAX, validateDecline } from "./decision";

export interface DeclineDialogProps {
  readonly proposal: ProposalWithMetadata;
  readonly submitting: boolean;
  readonly error?: DialogError;
  readonly onCancel: () => void;
  readonly onConfirm: (reason: DismissReason, rationale: string) => void;
}

export function DeclineDialog({ proposal, submitting, error, onCancel, onConfirm }: DeclineDialogProps) {
  const [reason, setReason] = useState<DismissReason>("no_reason");
  const [rationale, setRationale] = useState("");
  const validation = validateDecline(reason, rationale);
  const required = reason === "other";

  return (
    <DecisionDialog
      title={`Decline "${proposal.title}"?`}
      onClose={onCancel}
      busy={submitting}
      className="azdec-dialog--decline"
      footer={
        <>
          <button type="button" className="azd-btn" onClick={onCancel} disabled={submitting}>
            Cancel
          </button>
          <button
            type="button"
            className="azd-btn azdec-btn azdec-btn--decline"
            onClick={() => onConfirm(reason, rationale)}
            disabled={submitting || Boolean(validation)}
          >
            {submitting && <Spinner />}
            Decline
          </button>
        </>
      }
    >
      <fieldset className="azdec-fieldset" disabled={submitting}>
        <legend className="azdec-legend">Reason</legend>
        {DISMISS_REASONS.map((r) => (
          <label key={r} className="azdec-radio">
            <input
              type="radio"
              name="azdec-dismiss-reason"
              value={r}
              checked={reason === r}
              data-autofocus={reason === r || undefined}
              onChange={() => setReason(r)}
            />
            <span>{DISMISS_REASON_LABELS[r]}</span>
          </label>
        ))}
      </fieldset>

      <RationaleField
        label="Rationale"
        hint={required ? "(required)" : "(optional)"}
        placeholder={required ? "Describe why (required for Other)" : "Add detail (optional)"}
        value={rationale}
        onChange={setRationale}
        required={required}
        error={validation}
        disabled={submitting}
        max={RATIONALE_MAX}
      />

      {error && <InlineError message={error.message} detail={error.detail} />}
    </DecisionDialog>
  );
}
