/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import classNames from "classnames";
import {
  ALERT_ZERO_CATEGORIES,
  PROPOSAL_SCOPES,
  type AlertZeroCategory,
  type AlertZeroCategoryFilter,
  type ProposalScope,
} from "../../../../shared/alert-zero-types";
import { CATEGORY_LABEL, CATEGORY_TONE, type GroupBy } from "./list-model";

const SCOPE_LABEL: Record<ProposalScope, string> = {
  all: "All",
  mine: "Assigned to me",
  unassigned: "Unassigned",
};

const GROUP_OPTIONS: readonly { value: GroupBy; label: string }[] = [
  { value: "category", label: "Category" },
  { value: "investigation", label: "Investigation" },
];

export interface FilterBarProps {
  readonly scope: ProposalScope;
  readonly category: AlertZeroCategoryFilter;
  readonly groupBy: GroupBy;
  readonly countsByCategory: Record<AlertZeroCategory, number>;
  readonly totalAwaitingDecision: number;
  readonly onScopeChange: (scope: ProposalScope) => void;
  readonly onCategoryChange: (category: AlertZeroCategoryFilter) => void;
  readonly onGroupByChange: (groupBy: GroupBy) => void;
}

function Pill({
  active,
  onClick,
  children,
}: {
  readonly active: boolean;
  readonly onClick: () => void;
  readonly children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      className={classNames("az-pill", { "az-pill--active": active })}
      aria-pressed={active}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

export function FilterBar({
  scope,
  category,
  groupBy,
  countsByCategory,
  totalAwaitingDecision,
  onScopeChange,
  onCategoryChange,
  onGroupByChange,
}: FilterBarProps) {
  return (
    <div className="az-filters">
      <div className="az-filter-row">
        <div className="az-pill-group" role="group" aria-label="Assignment">
          {PROPOSAL_SCOPES.map((s) => (
            <Pill key={s} active={scope === s} onClick={() => onScopeChange(s)}>
              {SCOPE_LABEL[s]}
            </Pill>
          ))}
        </div>
        <div className="az-filter-group">
          <span className="az-filter-label" aria-hidden="true">Group by</span>
          <div className="az-pill-group" role="group" aria-label="Group by">
            {GROUP_OPTIONS.map((o) => (
              <Pill key={o.value} active={groupBy === o.value} onClick={() => onGroupByChange(o.value)}>
                {o.label}
              </Pill>
            ))}
          </div>
        </div>
      </div>
      <div className="az-filter-row">
        <div className="az-pill-group" role="group" aria-label="Category">
          <Pill active={category === "all"} onClick={() => onCategoryChange("all")}>
            All <span className="az-pill-count">{totalAwaitingDecision}</span>
          </Pill>
          {ALERT_ZERO_CATEGORIES.map((c) => (
            <Pill key={c} active={category === c} onClick={() => onCategoryChange(c)}>
              <span className={`az-pill-dot az-pill-dot--${CATEGORY_TONE[c]}`} aria-hidden="true" />
              {CATEGORY_LABEL[c]} <span className="az-pill-count">{countsByCategory[c] ?? 0}</span>
            </Pill>
          ))}
        </div>
      </div>
    </div>
  );
}
