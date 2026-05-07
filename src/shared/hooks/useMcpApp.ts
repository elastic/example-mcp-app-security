/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useEffect, useRef, useState } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme } from "../theme";

type ToolResultParams = Parameters<NonNullable<McpApp["ontoolresult"]>>[0];

export interface UseMcpAppOptions {
  /** App identification — passed to `new McpApp({ name, version })`. */
  name: string;
  version: string;
  /**
   * Called when the host pushes an initial tool result. Use this to seed
   * params/state from `params._meta` etc. before falling through to the
   * view's own loader.
   */
  onToolResult?: (params: ToolResultParams, app: McpApp) => void;
  /**
   * Called once the connection is up. Receives whether `onToolResult` already
   * fired (via the 1500ms grace timer) so the view can decide to issue its
   * own initial fetch when nothing was pushed.
   */
  onConnect?: (app: McpApp, gotResult: boolean) => void;
}

export interface UseMcpAppState {
  /** The underlying MCP app instance, or null until React mounts. */
  app: McpApp | null;
  /** Stable ref accessor — useful inside `useCallback`s where the value can be null until connect. */
  getApp: () => McpApp | null;
  /** True once `app.connect()` resolves. Views typically gate their UI on this. */
  connected: boolean;
}

/**
 * Standard MCP app bootstrap: instantiate, apply the design-system theme,
 * register the `ontoolresult` handler, connect, and tear down on unmount.
 *
 * Replaces the ~30-line copy-pasted `useEffect` block at the top of every
 * view's `App.tsx`.
 */
export function useMcpApp({ name, version, onToolResult, onConnect }: UseMcpAppOptions): UseMcpAppState {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  // Refs stash the latest callbacks so the connect effect runs once, even
  // when consumers pass new function identities on every render.
  const onToolResultRef = useRef(onToolResult);
  const onConnectRef = useRef(onConnect);
  onToolResultRef.current = onToolResult;
  onConnectRef.current = onConnect;

  useEffect(() => {
    const app = new McpApp({ name, version });
    appRef.current = app;
    applyTheme(app);

    let gotResult = false;
    app.ontoolresult = (params) => {
      gotResult = true;
      try {
        onToolResultRef.current?.(params, app);
      } catch (e) {
        console.error("ontoolresult handler failed:", e);
      }
    };

    app.connect().then(() => {
      setConnected(true);
      // Give the host a 1.5s grace period to push a tool result before
      // falling back to whatever the view's own loader wants to do.
      setTimeout(() => {
        onConnectRef.current?.(app, gotResult);
      }, 1500);
    });

    return () => { app.close(); };
  }, [name, version]);

  return {
    app: appRef.current,
    getApp: () => appRef.current,
    connected,
  };
}
