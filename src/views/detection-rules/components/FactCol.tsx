/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";

export interface FactColProps {
  label: string;
  value?: string;
}

/** Single fact column inside the rule-detail header. */
export function FactCol({ label, value }: FactColProps) {
  return (
    <div className="rule-detail-fact">
      <div className="rule-detail-fact-label">{label}</div>
      <div className="rule-detail-fact-value" title={value || undefined}>{value || "—"}</div>
    </div>
  );
}
