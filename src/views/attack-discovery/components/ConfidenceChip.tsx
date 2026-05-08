/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";

export type ConfidenceKey = "high" | "moderate" | "low";

export const CONFIDENCE_LABEL: Record<ConfidenceKey, string> = {
  high: "High",
  moderate: "Moderate",
  low: "Low",
};

export interface ConfidenceChipProps {
  level: ConfidenceKey;
}

/** Pill that renders the AI's confidence in an attack-discovery finding. */
export function ConfidenceChip({ level }: ConfidenceChipProps) {
  return (
    <span className={`conf-chip conf-chip-${level}`} aria-label={`Confidence: ${CONFIDENCE_LABEL[level]}`}>
      <span className="conf-chip-dot" />
      <span className="conf-chip-label">{CONFIDENCE_LABEL[level]}</span>
    </span>
  );
}
