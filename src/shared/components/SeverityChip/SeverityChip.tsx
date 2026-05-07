/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import "./SeverityChip.css";

export type Severity = "low" | "medium" | "high" | "critical";

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export const SEVERITY_STROKE: Record<Severity, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
};

/** Normalize an arbitrary severity string to a known key, defaulting to "low". */
export function toSeverity(value: string | undefined | null): Severity {
  const k = (value || "").toLowerCase();
  return k === "critical" || k === "high" || k === "medium" || k === "low" ? k : "low";
}

export interface SeverityChipProps {
  severity: Severity | string;
  /** Override the displayed label (defaults to capitalised severity name). */
  label?: string;
  /** Hide the leading dot (used by GroupCard's outlined-pill variant). */
  hideDot?: boolean;
  className?: string;
}

export function SeverityChip({ severity, label, hideDot, className }: SeverityChipProps) {
  const key = toSeverity(typeof severity === "string" ? severity : severity);
  const cls = [
    "sev-chip",
    `sev-chip-${key}`,
    hideDot ? "sev-chip-no-dot" : "",
    className ?? "",
  ].filter(Boolean).join(" ");
  return (
    <span className={cls}>
      <span className="sev-chip-dot" />
      <span className="sev-chip-label">{label ?? SEVERITY_LABEL[key]}</span>
    </span>
  );
}
