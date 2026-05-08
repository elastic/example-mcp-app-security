/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import classNames from "classnames";
import type { SecurityAlert } from "../../../shared/types";
import { AlertScoreRing } from "./AlertCard";

export interface RelatedAlertCardProps {
  alert: SecurityAlert;
  selected?: boolean;
  onClick: () => void;
}

/** Compact card used inside the detail pane's "Related" section. */
export function RelatedAlertCard({ alert, selected, onClick }: RelatedAlertCardProps) {
  const src = alert._source;
  const sev = ((src["kibana.alert.severity"]?.toLowerCase() || "low") as "low" | "medium" | "high" | "critical");
  const score = src["kibana.alert.risk_score"] ?? 0;
  return (
    <div className={classNames("related-alert-card", `sev-${sev}`, { selected })} onClick={onClick}>
      <div className="related-alert-card-score">
        <AlertScoreRing score={score} severity={sev} />
      </div>
      <div className="related-alert-card-body">
        <div className="related-alert-card-title">{src["kibana.alert.rule.name"]}</div>
        {src["kibana.alert.reason"] && (
          <div className="related-alert-card-reason">{src["kibana.alert.reason"]}</div>
        )}
      </div>
    </div>
  );
}
