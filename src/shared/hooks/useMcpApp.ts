/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useContext, useEffect, useMemo, useRef } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import type {
  McpAppBootstrapEnvelope,
  McpAppBootstrapErrorState,
  McpAppBootstrapIdleState,
  ViewBootstrapPayloads,
} from "../mcp-app-bootstrap.js";
import type { ViewId } from "../analytics-events.js";
import {
  McpAppContext,
  type McpAppContextValue,
  type OnToolResult,
} from "./McpAppContext";

export type { OnToolResult } from "./McpAppContext";

export interface UseMcpAppState {
  readonly app: McpApp | null;
  readonly getApp: () => McpApp | null;
  readonly connected: boolean;
  readonly bootstrapState: McpAppContextValue["bootstrapState"];
}

export function useMcpApp(): UseMcpAppState {
  const ctx = useContext(McpAppContext);
  if (!ctx) {
    throw new Error(
      "useMcpApp() must be used inside <McpAppProvider>. Wrap your view's root in <McpAppProvider name=… version=…>.",
    );
  }
  return {
    app: ctx.app,
    getApp: ctx.getApp,
    connected: ctx.connected,
    bootstrapState: ctx.bootstrapState,
  };
}

export interface UseMcpAppEventsOptions {
  /**
   * Called whenever the host pushes a tool result after transport
   * connection. Startup bootstrap payloads are delivered on this same
   * channel, so consumers that rely on `useMcpAppBootstrap()` should
   * ignore the explicit bootstrap envelope here.
   */
  onToolResult?: OnToolResult;
}

export function useMcpAppEvents(options: UseMcpAppEventsOptions): void {
  const ctx = useContext(McpAppContext);
  if (!ctx) {
    throw new Error(
      "useMcpAppEvents() must be used inside <McpAppProvider>.",
    );
  }

  const onToolResultRef = useRef(options.onToolResult);
  onToolResultRef.current = options.onToolResult;

  useEffect(() => {
    const unsubscribeToolResult = ctx.subscribeToToolResult((params, app) => {
      onToolResultRef.current?.(params, app);
    });
    return () => {
      unsubscribeToolResult();
    };
  }, [ctx]);
}

type ViewBootstrapReadyState<V extends ViewId> = {
  readonly status: "ready";
  readonly envelope: McpAppBootstrapEnvelope<V>;
  readonly payload: ViewBootstrapPayloads[V];
};

export type UseMcpAppBootstrapState<V extends ViewId> =
  | McpAppBootstrapIdleState
  | McpAppBootstrapErrorState
  | ViewBootstrapReadyState<V>;

/**
 * Read the host-owned startup payload for a specific view.
 *
 * The provider persists bootstrap state in context, so late subscribers
 * do not need a separate replay subscription: they synchronously read
 * the current state on mount.
 */
export function useMcpAppBootstrap<V extends ViewId>(
  viewId: V,
): UseMcpAppBootstrapState<V> {
  const { bootstrapState } = useMcpApp();
  return useMemo(() => {
    if (bootstrapState.status !== "ready") {
      return bootstrapState;
    }
    if (bootstrapState.envelope.viewId !== viewId) {
      return {
        status: "error",
        reason: `Bootstrap for ${bootstrapState.envelope.viewId} does not match ${viewId}.`,
      };
    }
    return {
      status: "ready",
      // The runtime check above narrows the envelope to the requested view.
      envelope: bootstrapState.envelope as McpAppBootstrapEnvelope<V>,
      payload: bootstrapState.envelope.payload as ViewBootstrapPayloads[V],
    };
  }, [bootstrapState, viewId]);
}
