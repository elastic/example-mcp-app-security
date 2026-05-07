/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import "./States.css";

export interface LoadingStateProps {
  /** Replaces the default "Loading..." message. */
  children?: React.ReactNode;
}

export function LoadingState({ children = "Loading..." }: LoadingStateProps) {
  return (
    <div className="loading-state">
      <div className="loading-spinner" />
      {children}
    </div>
  );
}

export interface EmptyStateProps {
  children: React.ReactNode;
}

export function EmptyState({ children }: EmptyStateProps) {
  return <div className="empty-state">{children}</div>;
}
