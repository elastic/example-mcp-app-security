/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import classNames from "classnames";
import type { AlertZeroProposalCard } from "../../../../shared/alert-zero-types";
import { timeAgo } from "../../../../shared/theme";
import { AssigneeAvatars } from "./AssigneeAvatars";
import {
  categoryBucket,
  confidenceLabel,
  expiryInfo,
  impactLabel,
  impactTone,
  investigationLabel,
} from "./list-model";

const MAX_TARGETS = 3;

export interface ProposalCardProps {
  readonly card: AlertZeroProposalCard;
  readonly selected: boolean;
  readonly onSelect: (card: AlertZeroProposalCard) => void;
  /** Shared clock so every card in a render agrees on what has expired. */
  readonly now?: number;
  /** Off when the card already sits under its investigation's heading. */
  readonly showInvestigation?: boolean;
}

export function ProposalCard({ card, selected, onSelect, now, showInvestigation = true }: ProposalCardProps) {
  const expiry = expiryInfo(card.expiresAt, now);
  const createdAt = new Date(card.createdAt);
  const revision = card.revision ?? 1;
  const targets = card.targets.slice(0, MAX_TARGETS);
  const hiddenTargets = card.targets.slice(MAX_TARGETS);

  return (
    <button
      type="button"
      className={classNames("az-card", `az-card--${categoryBucket(card.category)}`, {
        "az-card--selected": selected,
      })}
      aria-pressed={selected}
      onClick={() => onSelect(card)}
    >
      <span className="az-card-meta">
        <span className="az-card-meta-main">
          <span className="az-card-age" title={Number.isNaN(createdAt.getTime()) ? undefined : createdAt.toLocaleString()}>
            {timeAgo(card.createdAt)}
          </span>
          {expiry &&
            (expiry.tone === "muted" ? (
              <span className="az-card-expiry" title={expiry.title}>{expiry.label}</span>
            ) : (
              <span className={`az-badge az-badge--${expiry.tone}`} title={expiry.title}>{expiry.label}</span>
            ))}
          {revision > 1 && (
            <span className="az-badge az-badge--hollow" title={`Revision ${revision} of this proposal`}>
              Rev {revision}
            </span>
          )}
          {card.hasPreviousExecutionError && (
            <span className="az-badge az-badge--warning" title="A previous attempt to run this action failed">
              Retry
            </span>
          )}
        </span>
        <AssigneeAvatars assignees={card.assignees} />
      </span>

      {showInvestigation && <span className="az-card-investigation">{investigationLabel(card)}</span>}

      <span className={classNames("az-card-title", { "az-card-title--primary": !showInvestigation })}>
        {card.title}
        {card.actionName && <span className="az-card-action"> · {card.actionName}</span>}
      </span>

      <span className="az-card-badges">
        <span className={`az-badge az-badge--${impactTone(card.impact)}`}>{impactLabel(card.impact)}</span>
        <span className="az-badge az-badge--default">{confidenceLabel(card.confidence)}</span>
        {card.reversible !== undefined &&
          (card.reversible ? (
            <span className="az-badge az-badge--hollow">Reversible</span>
          ) : (
            <span className="az-badge az-badge--warning">Irreversible</span>
          ))}
        {targets.map((target, i) => (
          <span key={`${i}-${target}`} className="az-chip" title={target}>
            {target}
          </span>
        ))}
        {hiddenTargets.length > 0 && (
          <span className="az-chip" title={hiddenTargets.join(", ")}>
            +{hiddenTargets.length}
          </span>
        )}
      </span>
    </button>
  );
}
