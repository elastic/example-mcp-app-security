/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";

export type NoisyRuleRow = { ruleName: string; ruleId: string; alertCount: number };

export interface NoisyRulesViewProps {
  loading: boolean;
  rows: NoisyRuleRow[];
}

/**
 * "Noisy rules" panel — ranks detection rules by alert volume over the last
 * 7 days so SOC analysts can quickly identify rules that need tuning.
 */
export function NoisyRulesView({ loading, rows }: NoisyRulesViewProps) {
  const max = rows[0]?.alertCount || 1;
  return (
    <div className="rule-detail">
      <div className="rule-detail-head">
        <h2 className="rule-detail-title">Noisy rules</h2>
        <div className="rule-detail-subtitle">
          Ranked by alert volume over the last 7 days. Use this to tune or disable high-chatter rules.
        </div>
      </div>
      {loading ? (
        <div className="loading-state"><div className="loading-spinner" />Loading volume data…</div>
      ) : rows.length === 0 ? (
        <div className="empty-state">No noisy-rule data available for this window.</div>
      ) : (
        <div className="noisy-list">
          {rows.map((r, i) => (
            <div
              key={r.ruleId}
              className="noisy-row animate-in"
              style={{ "--i": Math.min(i, 12) } as React.CSSProperties}
            >
              <div className="noisy-row-rank">{i + 1}</div>
              <div className="noisy-row-main">
                <div className="noisy-row-title" title={r.ruleName}>{r.ruleName}</div>
                <div className="summary-bar-track">
                  <div
                    className="summary-bar-fill summary-bar-sev-medium"
                    style={{ width: `${(r.alertCount / max) * 100}%` }}
                  />
                </div>
              </div>
              <div className="noisy-row-count">{r.alertCount.toLocaleString()}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
