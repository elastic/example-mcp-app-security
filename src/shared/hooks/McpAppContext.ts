/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createContext } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import type { McpAppBootstrapState } from "../mcp-app-bootstrap.js";

/** Argument shape pushed to `app.ontoolresult`. */
export type ToolResultParams = Parameters<NonNullable<McpApp["ontoolresult"]>>[0];

export type OnToolResult = (params: ToolResultParams, app: McpApp) => void;

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
 *  - `bootstrapState` — persisted in React state. Late subscribers read
 *    the current bootstrap state synchronously from context, so they
 *    never miss the host-owned initial hydration payload once it has
 *    arrived.
 */
export interface McpAppContextValue {
  /** The underlying MCP app instance, or null until React mounts. */
  readonly app: McpApp | null;
  /** Stable ref accessor — null until connect is set up. */
  readonly getApp: () => McpApp | null;
  /** True once `app.connect()` resolves. */
  readonly connected: boolean;
  /** Host-owned initial hydration state for this app view. */
  readonly bootstrapState: McpAppBootstrapState;
  /**
   * Subscribe to every `ontoolresult` push from the host. Returns an
   * {@link Unsubscribe} that removes the listener.
   */
  readonly subscribeToToolResult: (listener: OnToolResult) => Unsubscribe;
}

export const McpAppContext = createContext<McpAppContextValue | null>(null);
