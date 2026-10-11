/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo } from "react";
import { KpiStrip, KpiTile } from "../../../../shared/components";
import type { AlertZeroProposalCard } from "../../../../shared/alert-zero-types";
import { computeKpis } from "./list-model";

export interface AlertZeroKpisProps {
  /** Pending proposals in the space before any filter. */
  readonly totalAwaitingDecision: number;
  /** Loaded rows — already narrowed by the scope/category filters. */
  readonly cards: readonly AlertZeroProposalCard[];
  /** True when `cards` is a subset (filtered or truncated), so the per-card tiles get a qualifier. */
  readonly partial: boolean;
}

export function AlertZeroKpis({ totalAwaitingDecision, cards, partial }: AlertZeroKpisProps) {
  const kpis = useMemo(() => computeKpis(cards), [cards]);
  const qualifier = partial ? "in view" : undefined;
  const tileCount = kpis.pastDeadline > 0 ? 6 : 5;

  return (
    <KpiStrip className="az-kpi-strip" tileCount={tileCount}>
      <KpiTile
        label="Awaiting decision"
        value={totalAwaitingDecision}
        meta={partial ? `${cards.length} shown` : undefined}
        accent="accent"
      />
      <KpiTile
        label="High/critical impact"
        value={kpis.highImpact}
        meta={qualifier}
        accent={kpis.highImpact > 0 ? "critical" : undefined}
      />
      <KpiTile
        label="Expiring < 24h"
        value={kpis.expiringSoon}
        meta={qualifier}
        accent={kpis.expiringSoon > 0 ? "medium" : undefined}
      />
      {kpis.pastDeadline > 0 && (
        <KpiTile label="Past deadline" value={kpis.pastDeadline} meta={qualifier} accent="critical" />
      )}
      <KpiTile label="Unassigned" value={kpis.unassigned} meta={qualifier} />
      <KpiTile label="Assigned to me" value={kpis.assignedToMe} meta={qualifier} />
    </KpiStrip>
  );
}
