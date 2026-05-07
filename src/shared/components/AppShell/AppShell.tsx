/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import "./AppShell.css";

export interface AppShellProps {
  children: React.ReactNode;
  className?: string;
}

/**
 * Root view container — full-viewport flex column with the standard 1px
 * outer stroke. Replaces every `.{view}-app` class.
 */
export function AppShell({ children, className }: AppShellProps) {
  return <div className={className ? `app-shell ${className}` : "app-shell"}>{children}</div>;
}
