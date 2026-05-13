/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useContext, useEffect, useRef } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import {
  McpAppContext,
  type OnConnect,
  type OnToolResult,
} from "./McpAppContext";

export type { OnConnect, OnToolResult } from "./McpAppContext";

export interface UseMcpAppState {
  /** The underlying MCP app instance, or null until React mounts. */
  readonly app: McpApp | null;
  /** Stable ref accessor — useful inside `useCallback`s where the value can be null until connect. */
  readonly getApp: () => McpApp | null;
  /** True once `app.connect()` resolves. Views typically gate their UI on this. */
  readonly connected: boolean;
}

/**
 * Read the {@link McpApp} instance owned by the enclosing
 * `<McpAppProvider>`. Must be called inside a provider — throws
 * otherwise rather than silently constructing a second instance.
 */
export function useMcpApp(): UseMcpAppState {
  const ctx = useContext(McpAppContext);
  if (!ctx) {
    throw new Error(
      "useMcpApp() must be used inside <McpAppProvider>. Wrap your view's root in <McpAppProvider name=… version=…>.",
    );
  }
  return { app: ctx.app, getApp: ctx.getApp, connected: ctx.connected };
}

export interface UseMcpAppEventsOptions {
  /**
   * Called when the host pushes a tool result. Fires for **every** push
   * — use to seed view state from `params._meta`, react to LLM-driven
   * filter changes, and so on. Pass a stable identity or an inline
   * function freely; the hook stashes the latest in a ref so the
   * subscription itself isn't churned per-render.
   */
  onToolResult?: OnToolResult;
  /**
   * Called once after `app.connect()` resolves and the 1.5 s grace
   * window elapses. Receives `gotResult: true` if `onToolResult`
   * already fired during the grace window — views use this to decide
   * whether to issue their own initial fetch.
   *
   * If the connect event has already fired by the time this hook
   * subscribes (e.g. a component that mounts late), the listener is
   * invoked synchronously inside the subscribe call, so late
   * subscribers don't miss the event.
   */
  onConnect?: OnConnect;
}

/**
 * Subscribe to the enclosing `<McpAppProvider>`'s lifecycle events.
 *
 * Multiple `useMcpAppEvents` calls in the same tree compose naturally:
 * every subscriber sees every emission, in registration order. The
 * provider holds listeners in a `Set` and fans events out on each
 * push. Compare to `useWatch` in react-hook-form.
 *
 * Each render writes the latest callback identities into local refs
 * — the subscription itself is set up once per mount, so consumers
 * can pass inline functions without churning the provider's listener
 * set on every render.
 */
export function useMcpAppEvents(options: UseMcpAppEventsOptions): void {
  const ctx = useContext(McpAppContext);
  if (!ctx) {
    throw new Error(
      "useMcpAppEvents() must be used inside <McpAppProvider>.",
    );
  }

  const onToolResultRef = useRef(options.onToolResult);
  const onConnectRef = useRef(options.onConnect);
  onToolResultRef.current = options.onToolResult;
  onConnectRef.current = options.onConnect;

  useEffect(() => {
    const unsubscribeToolResult = ctx.subscribeToToolResult((params, app) => {
      onToolResultRef.current?.(params, app);
    });
    const unsubscribeConnect = ctx.subscribeToConnect((app, gotResult) => {
      onConnectRef.current?.(app, gotResult);
    });
    return () => {
      unsubscribeToolResult();
      unsubscribeConnect();
    };
  }, [ctx]);
}
