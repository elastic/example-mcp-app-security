/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { ChevronRightIcon } from "../icons/icons";
import { SEVERITY_LABEL, SeverityChip, toSeverity } from "../SeverityChip/SeverityChip";
import type { Severity } from "../SeverityChip/SeverityChip";
import "./GroupCard.css";

export interface GroupCardProps {
  /** Bold display name for the group (host name, user, rule name, etc.). */
  name: string;
  /** Optional subtitle below the name (OS, domain, parent process, …). */
  subtitle?: string;
  /** Highest severity in the group — drives the left stripe + chip color. */
  topSeverity: Severity | string;
  /** Number of children inside the group (rendered as "alerts: N"). */
  count: number;
  /** Localised label for the count noun, e.g. "alerts" or "discoveries". */
  countLabel?: string;
  expanded: boolean;
  onToggle: () => void;
  /** Optional accessibility hint, e.g. "Grouped by Host". */
  description?: string;
}

export function GroupCard({
  name,
  subtitle,
  topSeverity,
  count,
  countLabel = "alerts",
  expanded,
  onToggle,
  description,
}: GroupCardProps) {
  const sev = toSeverity(typeof topSeverity === "string" ? topSeverity : topSeverity);
  return (
    <button
      type="button"
      className={`group-card sev-${sev}${expanded ? " expanded" : ""}`}
      onClick={onToggle}
      aria-expanded={expanded}
    >
      <div className="group-card-body">
        <SeverityChip severity={sev} label={SEVERITY_LABEL[sev]} hideDot />
        <div className="group-card-identity">
          <div className="group-card-name">{name}</div>
          {subtitle && <div className="group-card-subtitle">{subtitle}</div>}
        </div>
      </div>
      <div className="group-card-meta">
        <span className="group-card-count">
          {countLabel}: <span className="group-card-count-value">{count}</span>
        </span>
        <span className={`group-card-chevron${expanded ? " open" : ""}`} aria-hidden="true">
          <ChevronRightIcon open={expanded} />
        </span>
      </div>
      {description && <span className="sr-only">{description}</span>}
    </button>
  );
}
