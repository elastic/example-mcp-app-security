/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from "react";
import type { AlertZeroProposalCard } from "../../../../shared/alert-zero-types";
import { ProposalCard } from "./ProposalCard";
import { groupProposals, impactLabel, impactTone, type GroupBy } from "./list-model";

export interface ProposalListProps {
  readonly cards: readonly AlertZeroProposalCard[];
  readonly groupBy: GroupBy;
  readonly selectedId?: string;
  readonly onSelect: (card: AlertZeroProposalCard) => void;
}

function countLabel(n: number): string {
  return `${n} proposal${n === 1 ? "" : "s"}`;
}

export function ProposalList({ cards, groupBy, selectedId, onSelect }: ProposalListProps) {
  const groups = useMemo(() => groupProposals(cards, groupBy), [cards, groupBy]);
  const now = Date.now();

  return (
    <div className="az-groups">
      {groups.map((group, i) => (
        <section
          key={`${group.kind}-${group.key}`}
          className="az-section animate-in"
          style={{ "--i": i } as React.CSSProperties}
          aria-label={`${group.label}, ${countLabel(group.cards.length)}`}
        >
          <div className="az-section-head">
            {group.kind === "category" ? (
              <span className={`az-badge az-badge--${group.tone}`}>{group.label}</span>
            ) : (
              <h2 className="az-section-title" title={group.label}>{group.label}</h2>
            )}
            <span className="az-section-count">{countLabel(group.cards.length)}</span>
            {group.kind === "investigation" && (
              <span className={`az-badge az-badge--${impactTone(group.topImpact)} az-section-impact`}>
                {impactLabel(group.topImpact)}
              </span>
            )}
          </div>
          <div className="az-section-cards">
            {group.cards.map((card) => (
              <ProposalCard
                key={card.id}
                card={card}
                selected={card.id === selectedId}
                onSelect={onSelect}
                now={now}
                showInvestigation={group.kind !== "investigation"}
              />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}
