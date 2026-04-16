/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { SeverityBadge, RiskScore } from "../../../shared/severity";
import { timeAgo } from "../../../shared/theme";
import type { SecurityAlert } from "../../../shared/types";

interface AlertCardProps {
  alert: SecurityAlert;
  compact?: boolean;
  selected?: boolean;
  onClick?: () => void;
}

export function AlertCard({ alert, compact, selected, onClick }: AlertCardProps) {
  const src = alert._source;
  const sev = src["kibana.alert.severity"]?.toLowerCase() || "low";

  return (
    <div
      className={`alert-card sev-${sev} ${compact ? "compact" : ""} ${selected ? "selected" : ""}`}
      onClick={onClick}
    >
      <div className="alert-card-row1">
        <SeverityBadge severity={src["kibana.alert.severity"]} />
        <span className="alert-card-rule">{src["kibana.alert.rule.name"]}</span>
        <RiskScore score={src["kibana.alert.risk_score"]} />
        <span className="alert-card-time">{timeAgo(src["@timestamp"])}</span>
      </div>

      <div className="alert-card-reason">{src["kibana.alert.reason"]}</div>

      <div className="alert-card-meta">
        {src.host?.name && (
          <span className="meta-item">
            <span className="meta-label">Host</span>
            <span className="meta-value">{src.host.name}</span>
          </span>
        )}
        {src.user?.name && (
          <span className="meta-item">
            <span className="meta-label">User</span>
            <span className="meta-value">
              {src.user.domain ? `${src.user.domain}\\` : ""}{src.user.name}
            </span>
          </span>
        )}
        {src.process?.name && (
          <span className="meta-item">
            <span className="meta-label">Process</span>
            <span className="meta-value">{src.process.name}</span>
          </span>
        )}
      </div>

      {!compact && src["kibana.alert.rule.threat"]?.length ? (
        <div className="alert-card-mitre">
          {src["kibana.alert.rule.threat"]!.slice(0, 2).map((t, i) => (
            <React.Fragment key={i}>
              <span className="mitre-tag mitre-tactic">{t.tactic.name}</span>
              {t.technique?.slice(0, 2).map((tech) => (
                <span key={tech.id} className="mitre-tag mitre-technique">{tech.id}</span>
              ))}
            </React.Fragment>
          ))}
        </div>
      ) : null}
    </div>
  );
}
