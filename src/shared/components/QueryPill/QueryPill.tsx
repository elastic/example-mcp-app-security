/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { CloseIcon } from "../icons/icons";
import "./QueryPill.css";

export type QueryPillTone = "amber" | "accent" | "low" | "high" | "critical";

export interface QueryPillProps {
  label: React.ReactNode;
  onClear?: () => void;
  tone?: QueryPillTone;
  ariaLabel?: string;
}

/** Filter chip rendered in the header (e.g. active query string). */
export function QueryPill({ label, onClear, tone = "amber", ariaLabel = "Clear filter" }: QueryPillProps) {
  const toneClass = tone === "amber" ? "" : `tone-${tone}`;
  return (
    <span className={`query-pill ${toneClass}`.trim()}>
      {label}
      {onClear && (
        <button type="button" onClick={onClear} aria-label={ariaLabel}>
          <CloseIcon />
        </button>
      )}
    </span>
  );
}
