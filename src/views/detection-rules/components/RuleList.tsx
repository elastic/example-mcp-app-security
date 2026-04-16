/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { SeverityBadge } from "../../../shared/severity";
import { MitreTags } from "../../../shared/mitre";
import type { DetectionRule } from "../../../shared/types";

function sevClass(severity: string): string {
  const s = severity.toLowerCase();
  if (s === "low" || s === "medium" || s === "high" || s === "critical") return `sev-${s}`;
  return "sev-low";
}

interface RuleListProps {
  rules: DetectionRule[];
  selectedId: string | null;
  onSelect: (r: DetectionRule) => void;
  onToggle: (id: string, enabled: boolean) => void;
}

export function RuleList({ rules, selectedId, onSelect, onToggle }: RuleListProps) {
  return (
    <div>
      {rules.map((rule, i) => {
        const selected = selectedId === rule.id;
        return (
          <div
            key={rule.id}
            role="button"
            tabIndex={0}
            className={`card animate-in ${sevClass(rule.severity)}${selected ? " selected" : ""}`}
            style={{ ["--i" as string]: Math.min(i, 20) }}
            onClick={() => onSelect(rule)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onSelect(rule);
              }
            }}
          >
            <div className="rule-card-row1">
              <span
                className={`rule-enabled ${rule.enabled ? "on" : "off"}`}
                title={rule.enabled ? "Enabled — click to disable" : "Disabled — click to enable"}
                role="presentation"
                onClick={(e) => {
                  e.stopPropagation();
                  onToggle(rule.id, !rule.enabled);
                }}
              />
              <SeverityBadge severity={rule.severity} />
              <span className="rule-card-name" title={rule.name}>
                {rule.name}
              </span>
              <span className="rule-type">{rule.type}</span>
            </div>
            <div className="rule-card-row2">
              <span className="meta-item">
                <span className="meta-label">Risk</span>
                <span className="meta-value">{rule.risk_score}</span>
              </span>
              <span className="meta-item">
                <span className="meta-label">Updated</span>
                <span className="meta-value">{new Date(rule.updated_at).toLocaleString()}</span>
              </span>
              {rule.index && rule.index.length > 0 ? (
                <span className="meta-item">
                  <span className="meta-label">Index</span>
                  <span className="meta-value" title={rule.index.join(", ")}>
                    {rule.index.slice(0, 2).join(", ")}
                    {rule.index.length > 2 ? ` +${rule.index.length - 2}` : ""}
                  </span>
                </span>
              ) : null}
            </div>
            {rule.threat && rule.threat.length > 0 ? (
              <div className="rule-card-mitre">
                <MitreTags threats={rule.threat} />
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
