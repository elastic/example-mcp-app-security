/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import "./DetailTabs.css";

export interface DetailTab<V extends string> {
  value: V;
  label: string;
  count?: number;
}

export interface DetailTabsProps<V extends string> {
  tabs: DetailTab<V>[];
  value: V;
  onChange: (value: V) => void;
  ariaLabel?: string;
}

/** Tab strip used in detail panes (attack-discovery, etc.). */
export function DetailTabs<V extends string>({ tabs, value, onChange, ariaLabel }: DetailTabsProps<V>) {
  return (
    <div className="detail-tabs" role="tablist" aria-label={ariaLabel}>
      {tabs.map((tab) => (
        <button
          key={tab.value}
          type="button"
          role="tab"
          aria-selected={tab.value === value}
          className={`detail-tab${tab.value === value ? " active" : ""}`}
          onClick={() => onChange(tab.value)}
        >
          {tab.label}
          {typeof tab.count === "number" && (
            <span className="detail-tab-count">{tab.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}
