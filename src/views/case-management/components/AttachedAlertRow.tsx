/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import classNames from "classnames";
import { timeAgo } from "../../../shared/theme";
import { SEVERITY_LABEL } from "../../../shared/components";
import type { Severity } from "../../../shared/components";

export interface AttachedAlertRowProps {
  /** Raw alert as returned by the Kibana attached-alerts response (may have or
   *  lack `_source` depending on the API version, hence `unknown`). */
  alert: unknown;
}

/** Compact row for an alert attached to a case. */
export function AttachedAlertRow({ alert }: AttachedAlertRowProps) {
  const a = (alert || {}) as Record<string, unknown>;
  const src = ((a._source as Record<string, unknown>) || a) as Record<string, unknown>;
  const rule = String(src["kibana.alert.rule.name"] || a.ruleName || a.rule || "Unknown rule");
  const severity = String(src["kibana.alert.severity"] || a.severity || "low").toLowerCase() as Severity;
  const ts = String(src["@timestamp"] || a.timestamp || "");
  return (
    <div className={classNames("case-detail-alert-row", `sev-${severity}`)}>
      <div className="case-detail-alert-row-main">
        <div className="case-detail-alert-row-title">{rule}</div>
        <div className="case-detail-alert-row-meta">{SEVERITY_LABEL[severity] || severity}</div>
      </div>
      {ts && <div className="case-detail-alert-row-time">{timeAgo(ts)}</div>}
    </div>
  );
}
