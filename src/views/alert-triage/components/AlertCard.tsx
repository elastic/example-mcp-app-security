/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { timeAgo } from "../../../shared/theme";
import type { SecurityAlert } from "../../../shared/types";

export const EntityIcon = {
  host: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="3" width="12" height="8" rx="1" />
      <path d="M5 13h6M8 11v2" />
      <circle cx="4.5" cy="7" r="0.4" fill="currentColor" stroke="none" />
    </svg>
  ),
  user: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
      <circle cx="8" cy="6" r="2.5" />
      <path d="M3 13c0-2.5 2.2-4 5-4s5 1.5 5 4" />
    </svg>
  ),
  process: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="3" width="12" height="10" rx="1" />
      <path d="M4.5 6.5 6 8 4.5 9.5M7.5 9.5h3" />
    </svg>
  ),
  executable: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 2h7l3 3v9a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z" />
      <path d="M10 2v3h3" />
    </svg>
  ),
};

interface AlertCardProps {
  alert: SecurityAlert;
  compact?: boolean;
  selected?: boolean;
  showDetails?: boolean;
  onClick?: () => void;
  onEntityFilter?: (field: string, value: string) => void;
}

type SeverityKey = "low" | "medium" | "high" | "critical";

export function AlertCard({ alert, compact, selected, showDetails = true, onClick, onEntityFilter }: AlertCardProps) {
  const src = alert._source;
  const sev = ((src["kibana.alert.severity"]?.toLowerCase() || "low") as SeverityKey);
  const score = src["kibana.alert.risk_score"] ?? 0;

  // First tactic + its first technique for the MITRE pill
  const threat = src["kibana.alert.rule.threat"]?.[0];
  const tacticName = threat?.tactic?.name;
  const techniqueId = threat?.technique?.[0]?.id;

  const userDisplay = src.user?.name
    ? (src.user.domain ? `${src.user.domain}\\${src.user.name}` : src.user.name)
    : undefined;

  return (
    <div
      className={`alert-card sev-${sev}${compact ? " compact" : ""}${selected ? " selected" : ""}`}
      onClick={onClick}
    >
      <div className="alert-card-score">
        <AlertScoreRing score={score} severity={sev} />
      </div>

      <div className="alert-card-main">
        <div className="alert-card-head">
          {(tacticName || techniqueId) && (
            <div className="alert-card-mitre">
              {tacticName && <span className="mitre-tag mitre-tag-tactic">{tacticName}</span>}
              {techniqueId && <span className="mitre-tag mitre-tag-technique">{techniqueId}</span>}
            </div>
          )}
          <div className="alert-card-titles">
            <div className="alert-card-title">{src["kibana.alert.rule.name"]}</div>
            {src["kibana.alert.reason"] && (
              <div className="alert-card-reason">{src["kibana.alert.reason"]}</div>
            )}
          </div>
        </div>

        {!compact && showDetails && (src.host?.name || userDisplay || src.process?.name) && (
          <div className="alert-card-facts">
            {src.host?.name && (
              <div className="fact-row">
                <span className="fact-label">
                  <span className="fact-label-icon" aria-hidden="true">{EntityIcon.host}</span>
                  <span>HOST</span>
                </span>
                <FactValue
                  field="host.name"
                  value={src.host.name}
                  onFilter={onEntityFilter}
                />
              </div>
            )}
            {userDisplay && (
              <div className="fact-row">
                <span className="fact-label">
                  <span className="fact-label-icon" aria-hidden="true">{EntityIcon.user}</span>
                  <span>USER</span>
                </span>
                <FactValue
                  field="user.name"
                  value={src.user?.name || userDisplay}
                  displayValue={userDisplay}
                  onFilter={onEntityFilter}
                />
              </div>
            )}
            {src.process?.name && (
              <div className="fact-row">
                <span className="fact-label">
                  <span className="fact-label-icon" aria-hidden="true">{EntityIcon.process}</span>
                  <span>PROCESS</span>
                </span>
                <FactValue
                  field="process.name"
                  value={src.process.name}
                  onFilter={onEntityFilter}
                />
              </div>
            )}
          </div>
        )}
      </div>

      <div className="alert-card-time">{timeAgo(src["@timestamp"])}</div>
    </div>
  );
}

/**
 * Dotted-underline value that filters the alert list when clicked.
 * Renders as a plain span (no filter behavior) if no onFilter callback is provided.
 */
function FactValue({ field, value, displayValue, onFilter }: {
  field: string;
  value: string;
  displayValue?: string;
  onFilter?: (field: string, value: string) => void;
}) {
  const label = displayValue ?? value;
  if (!onFilter) {
    return <span className="fact-value">{label}</span>;
  }
  return (
    <button
      type="button"
      className="fact-value clickable"
      onClick={(e) => { e.stopPropagation(); onFilter(field, value); }}
      title={`Filter by ${field}: ${value}`}
    >
      {label}
    </button>
  );
}

export function AlertScoreRing({ score, severity }: { score: number; severity: SeverityKey }) {
  // 38×38 ring to match Figma. Stroke 2px → r = 17.
  const r = 17;
  const cx = 19;
  const cy = 19;
  const circumference = 2 * Math.PI * r;
  const clamped = Math.max(0, Math.min(100, score));
  const filled = (clamped / 100) * circumference;

  return (
    <svg
      width="38"
      height="38"
      viewBox="0 0 38 38"
      className={`score-ring score-ring-${severity}`}
      aria-label={`Risk score ${Math.round(score)}`}
    >
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#474745" strokeWidth="2" />
      <circle
        cx={cx}
        cy={cy}
        r={r}
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeDasharray={`${filled} ${circumference}`}
        strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}
      />
      <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="middle" className="score-ring-text">
        {Math.round(score)}
      </text>
    </svg>
  );
}
