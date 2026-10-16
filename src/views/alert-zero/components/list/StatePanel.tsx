/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";

export interface StatePanelProps {
  readonly title: string;
  readonly children?: React.ReactNode;
  /** Buttons rendered under the body. */
  readonly actions?: React.ReactNode;
}

/** Full-pane message card used for the unavailable and load-error states. */
export function StatePanel({ title, children, actions }: StatePanelProps) {
  return (
    <div className="az-state-panel">
      <section className="az-state-card" aria-label={title}>
        <h2 className="az-state-title">{title}</h2>
        {children}
        {actions && <div className="az-state-actions">{actions}</div>}
      </section>
    </div>
  );
}
