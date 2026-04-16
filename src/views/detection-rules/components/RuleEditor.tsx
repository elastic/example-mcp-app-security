/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import React from "react";
import { SeverityBadge, RiskScore } from "../../../shared/severity";
import { MitreTags } from "../../../shared/mitre";
import type { DetectionRule } from "../../../shared/types";

function sevClass(severity: string): string {
  const s = severity.toLowerCase();
  if (s === "low" || s === "medium" || s === "high" || s === "critical") return `sev-${s}`;
  return "sev-low";
}

interface RuleEditorProps {
  rule: DetectionRule;
  onToggle: (enabled: boolean) => void;
}

export function RuleEditor({ rule, onToggle }: RuleEditorProps) {
  return (
    <div className={`detail-header-card ${sevClass(rule.severity)}`}>
      <h1 className="detail-title">{rule.name}</h1>

      <div className="detail-meta-grid">
        <div className="detail-meta-item">
          <span className="label">Type</span>
          <span className="value">
            <span className="rule-type">{rule.type}</span>
          </span>
        </div>
        <div className="detail-meta-item">
          <span className="label">Severity</span>
          <span className="value">
            <SeverityBadge severity={rule.severity} />
          </span>
        </div>
        <div className="detail-meta-item">
          <span className="label">Risk score</span>
          <span className="value">
            <RiskScore score={rule.risk_score} />
          </span>
        </div>
        <div className="detail-meta-item">
          <span className="label">Status</span>
          <span className="value" style={{ color: rule.enabled ? "var(--success)" : "var(--text-muted)" }}>
            {rule.enabled ? "Enabled" : "Disabled"}
          </span>
        </div>
        <div className="detail-meta-item">
          <span className="label">Created</span>
          <span className="value">{new Date(rule.created_at).toLocaleString()}</span>
        </div>
        <div className="detail-meta-item">
          <span className="label">Updated</span>
          <span className="value">{new Date(rule.updated_at).toLocaleString()}</span>
        </div>
      </div>

      {rule.description ? <p className="detail-desc">{rule.description}</p> : null}

      {rule.threat && rule.threat.length > 0 ? (
        <div className="rule-mitre-block">
          <MitreTags threats={rule.threat} />
        </div>
      ) : null}

      {rule.query ? (
        <>
          <div className="query-block-label">Query ({rule.language || "kuery"})</div>
          <pre className="query-block">{rule.query}</pre>
        </>
      ) : null}

      {rule.index && rule.index.length > 0 ? (
        <div>
          <div className="query-block-label">Index patterns</div>
          <div className="rule-index-list">
            {rule.index.map((idx) => (
              <span key={idx} className="rule-index-pill">
                {idx}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      <div className="rule-detail-actions">
        <button
          type="button"
          className={rule.enabled ? "btn btn-danger" : "btn btn-success"}
          onClick={() => onToggle(!rule.enabled)}
        >
          {rule.enabled ? "Disable rule" : "Enable rule"}
        </button>
      </div>
    </div>
  );
}
