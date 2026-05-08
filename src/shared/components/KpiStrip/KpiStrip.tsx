/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import "./KpiStrip.css";

export type KpiAccent = "critical" | "high" | "medium" | "low" | "accent";

export interface KpiTileProps {
  label: string;
  value: React.ReactNode;
  /** Optional inline meta text shown beside the value (e.g. "+3 today"). */
  meta?: React.ReactNode;
  /** Adds a coloured left stripe to highlight the tile. */
  accent?: KpiAccent;
}

export function KpiTile({ label, value, meta, accent }: KpiTileProps) {
  const accentClass = accent ? `kpi-tile-accent-${accent}` : "";
  return (
    <div className={`kpi-tile ${accentClass}`.trim()}>
      <div className="kpi-tile-label">{label}</div>
      {meta ? (
        <div className="kpi-tile-value-row">
          <span className="kpi-tile-value">{value}</span>
          <span className="kpi-tile-meta-inline">{meta}</span>
        </div>
      ) : (
        <div className="kpi-tile-value">{value}</div>
      )}
    </div>
  );
}

export interface KpiStripProps {
  /**
   * Optional summary section rendered at the left of the strip.
   * Use it to embed `<SeverityDonut>` or any other summary widget.
   */
  summary?: React.ReactNode;
  children: React.ReactNode;
  /** Number of value tiles — controls the grid template. */
  tileCount: number;
  className?: string;
}

export function KpiStrip({ summary, children, tileCount, className }: KpiStripProps) {
  return (
    <div
      className={className ? `kpi-strip ${className}` : "kpi-strip"}
      style={{ ["--kpi-tiles" as string]: String(tileCount) } as React.CSSProperties}
    >
      {summary && <div className="summary-section">{summary}</div>}
      {children}
    </div>
  );
}
