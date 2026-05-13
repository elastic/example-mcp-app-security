/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createContext } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";

/** Argument shape pushed to `app.ontoolresult`. */
export type ToolResultParams = Parameters<NonNullable<McpApp["ontoolresult"]>>[0];

export type OnToolResult = (params: ToolResultParams, app: McpApp) => void;
export type OnConnect = (app: McpApp, gotResult: boolean) => void;

/** Unsubscribe function returned by every `subscribe*` call. */
export type Unsubscribe = () => void;

/**
 * Internal context value backing `<McpAppProvider>`.
 *
 * Descendants read the connected `McpApp` (and the `connected` flag)
 * via `useMcpApp()`. Components that need to react to lifecycle events
 * register listeners via `useMcpAppEvents()`, which routes through the
 * `subscribeTo*` functions exposed here.
 *
 * The provider's pub/sub registry lives in `Set<Listener>` refs — adding
 * or removing listeners never re-fires the provider's connect effect.
 *
 * **Replay semantics:**
 *  - `subscribeToToolResult` — no replay. New subscribers see events
 *    that arrive after they subscribe, never before.
 *  - `subscribeToConnect` — replays the most recent firing (if any)
 *    synchronously into the new listener. The connect event fires at
 *    most once per provider lifetime, so a late subscriber would
 *    otherwise miss it forever.
 */
export interface McpAppContextValue {
  /** The underlying MCP app instance, or null until React mounts. */
  readonly app: McpApp | null;
  /** Stable ref accessor — null until connect is set up. */
  readonly getApp: () => McpApp | null;
  /** True once `app.connect()` resolves. */
  readonly connected: boolean;
  /**
   * Subscribe to every `ontoolresult` push from the host. Returns an
   * {@link Unsubscribe} that removes the listener.
   */
  readonly subscribeToToolResult: (listener: OnToolResult) => Unsubscribe;
  /**
   * Subscribe to the one-shot post-connect event (1.5 s after
   * `app.connect()` resolves). If the event has already fired by the
   * time `subscribeToConnect` is called, the listener is invoked
   * synchronously with the cached firing — late subscribers don't miss
   * it. Returns an {@link Unsubscribe} that removes the listener.
   */
  readonly subscribeToConnect: (listener: OnConnect) => Unsubscribe;
}

export const McpAppContext = createContext<McpAppContextValue | null>(null);
