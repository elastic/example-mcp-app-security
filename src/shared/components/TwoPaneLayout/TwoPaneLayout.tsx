/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import "./TwoPaneLayout.css";

export interface TwoPaneLayoutProps {
  /** Always-visible master list. */
  list: React.ReactNode;
  /**
   * Detail panel — when truthy, the list pane collapses to its narrow form
   * and the detail pane slides in from the right.
   */
  detail?: React.ReactNode;
  /** Extra class on the body wrapper. */
  className?: string;
}

/**
 * Master/detail layout used by every list-driven view. Replaces the
 * `.{view}-body` + `.{view}-list-pane` + `.detail-pane` triple per view.
 */
export function TwoPaneLayout({ list, detail, className }: TwoPaneLayoutProps) {
  const hasDetail = !!detail;
  return (
    <div className={className ? `app-body ${className}` : "app-body"}>
      <div className={`list-pane${hasDetail ? " narrow" : ""}`}>{list}</div>
      {hasDetail && <div className="detail-pane">{detail}</div>}
    </div>
  );
}
