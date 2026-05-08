/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";

export interface ExpandSectionProps {
  title: string;
  count: number;
  expanded: boolean;
  onToggle: () => void;
  /** Number of rows shown when collapsed; expand control is hidden when count <= previewCount. */
  previewCount: number;
  children: React.ReactNode;
}

/**
 * Collapsible section used by the alert-detail pane (Related, Process tree,
 * Network). Renders a title with count + chevron and a children slot.
 */
export function ExpandSection({ title, count, expanded, onToggle, previewCount, children }: ExpandSectionProps) {
  const canExpand = count > previewCount;
  return (
    <section className="alert-detail-section">
      <div className="alert-detail-section-head">
        <span className="alert-detail-section-title">{title}</span>
        <span className="alert-detail-section-count">{count}</span>
      </div>
      {children}
      {canExpand && (
        <button type="button" className="alert-detail-expand" onClick={onToggle}>
          <span>{expanded ? "Collapse" : "Expand"}</span>
          <svg
            width="12"
            height="12"
            viewBox="0 0 12 12"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
            style={{ transform: expanded ? "rotate(90deg)" : "none", transition: "transform 0.15s" }}
          >
            <path d="M4.5 3l3 3-3 3" />
          </svg>
        </button>
      )}
    </section>
  );
}
