/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from "react";
import { EmptyState } from "../States/States";

export interface ErrorBoundaryProps {
  /** Replaces the default fallback message. */
  fallback?: React.ReactNode;
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * Catches render-time exceptions anywhere in `children` and shows a fallback
 * instead of letting React unmount the whole tree to a blank screen.
 *
 * MCP app views render inside a host-provided webview with no dev console
 * visible to the end user — an uncaught render error otherwise looks
 * identical to "nothing loaded," with no indication anything went wrong.
 * Wrap each view's root render in this boundary so an unexpected data shape
 * degrades to a visible message instead of a silent blank panel.
 */
export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo): void {
    console.error("Unhandled render error:", error, info.componentStack);
  }

  render(): React.ReactNode {
    if (this.state.error) {
      return (
        this.props.fallback ?? (
          <EmptyState>
            Something went wrong rendering this view. Try reloading — if it keeps
            happening, the underlying data may be in an unexpected shape.
          </EmptyState>
        )
      );
    }
    return this.props.children;
  }
}
