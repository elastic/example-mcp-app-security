/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import {
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  SEVERITY_STROKE,
  toSeverity,
} from "../SeverityChip/SeverityChip";
import type { Severity } from "../SeverityChip/SeverityChip";
import "./SeverityDonut.css";

export interface SeverityDonutProps {
  /** Severity counts — keys may be capitalised or include unknown extras; we normalise. */
  bySeverity: Record<string, number>;
  /** Donut diameter in pixels. */
  size?: number;
  /** Localised noun for the aria label, e.g. "alerts" or "discoveries". */
  itemLabel?: string;
}

/**
 * Donut chart showing the per-severity breakdown plus a legend.
 * Reused across alert-triage, attack-discovery, case-management, detection-rules.
 */
export function SeverityDonut({ bySeverity, size = 105, itemLabel = "items" }: SeverityDonutProps) {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const [k, v] of Object.entries(bySeverity)) {
    const key = toSeverity(k);
    counts[key] += v;
  }
  const total = SEVERITY_ORDER.reduce((s, k) => s + counts[k], 0);

  // viewBox chosen so circumference = 100, segment lengths are percentages.
  const r = 15.91549430918954;
  const cx = 21;
  const cy = 21;
  const sw = 6;

  let cumulative = 0;
  const arcs = SEVERITY_ORDER.map((key) => {
    const pct = total ? (counts[key] / total) * 100 : 0;
    const arc = { key, count: counts[key], pct, offset: -cumulative };
    cumulative += pct;
    return arc;
  });

  return (
    <div className="severity-donut">
      <svg
        width={size}
        height={size}
        viewBox="0 0 42 42"
        className="severity-donut-svg"
        role="img"
        aria-label={`Severity breakdown: ${total} ${itemLabel} total`}
      >
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--bg-tertiary)" strokeWidth={sw} />
        {arcs.filter((a) => a.pct > 0).map((a) => (
          <circle
            key={a.key}
            cx={cx}
            cy={cy}
            r={r}
            fill="none"
            stroke={SEVERITY_STROKE[a.key]}
            strokeWidth={sw}
            strokeDasharray={`${a.pct} ${100 - a.pct}`}
            strokeDashoffset={a.offset}
            transform={`rotate(-90 ${cx} ${cy})`}
          />
        ))}
      </svg>
      <div className="severity-legend">
        {arcs.map((a) => (
          <div key={a.key} className="severity-legend-row">
            <span className={`severity-legend-dot sev-${a.key}`} />
            <span className="severity-legend-label">{SEVERITY_LABEL[a.key]}</span>
            <span className="severity-legend-value">{a.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
