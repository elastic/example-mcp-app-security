/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme } from "../theme";
import {
  McpAppContext,
  type McpAppContextValue,
  type OnConnect,
  type OnToolResult,
  type Unsubscribe,
} from "./McpAppContext";

export interface McpAppProviderProps {
  /** App identification — passed to `new McpApp({ name, version })`. */
  name: string;
  version: string;
  children: ReactNode;
}

/**
 * Owns the MCP App lifecycle for a single view subtree.
 *
 * Constructs the `McpApp`, applies the design-system theme, wires
 * `ontoolresult`, calls `connect()`, and tears down on unmount. The
 * connected instance plus the `connected` flag are exposed via
 * {@link McpAppContext} so descendants (`useMcpApp`, `useAnalytics`,
 * `useMcpAppEvents`) can share a single instance instead of each
 * constructing their own.
 *
 * Lifecycle events (`ontoolresult` from the host, plus a synthetic
 * `onConnect` 1.5 s after the transport binds) are fanned out to all
 * registered listeners via the `subscribeTo*` functions on the context
 * value. The provider holds listeners in `Set` refs so adding /
 * removing subscribers never re-triggers the connect effect.
 */
export function McpAppProvider({
  name,
  version,
  children,
}: McpAppProviderProps): ReactNode {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);

  // Pub/sub registries. Refs (not state) so adding subscribers never
  // re-runs the connect effect. `Set` semantics make subscribe/
  // unsubscribe O(1) and naturally support multiple subscribers per
  // event.
  const toolResultListeners = useRef<Set<OnToolResult>>(new Set());
  const connectListeners = useRef<Set<OnConnect>>(new Set());

  // Cached last firing of the one-shot `onConnect` event. Used to
  // replay synchronously into late subscribers — without this, a
  // component that mounts after the 1.5 s grace window would miss
  // the event forever.
  const lastConnectFiring = useRef<{ gotResult: boolean } | null>(null);

  useEffect(() => {
    const app = new McpApp({ name, version });
    appRef.current = app;
    applyTheme(app);

    let gotResult = false;
    let cancelled = false;
    let graceTimer: ReturnType<typeof setTimeout> | null = null;

    app.ontoolresult = (params) => {
      gotResult = true;
      // Snapshot the listener set so a subscriber that unsubscribes
      // during its own callback doesn't perturb the iteration order.
      for (const listener of [...toolResultListeners.current]) {
        try {
          listener(params, app);
        } catch (e) {
          console.error("onToolResult listener failed:", e);
        }
      }
    };

    app.connect()
      .then(() => {
        if (cancelled) return;
        setConnected(true);
        // 1.5s grace period before falling back to the view's own
        // initial-load behaviour — preserves the legacy semantics.
        graceTimer = setTimeout(() => {
          graceTimer = null;
          if (cancelled) return;
          // Cache *before* notifying so any subscriber added during
          // the fan-out (rare but possible) sees the firing.
          lastConnectFiring.current = { gotResult };
          for (const listener of [...connectListeners.current]) {
            try {
              listener(app, gotResult);
            } catch (e) {
              console.error("onConnect listener failed:", e);
            }
          }
        }, 1500);
      })
      .catch((err) => {
        if (cancelled) return;
        console.error("MCP app connect() failed:", err);
      });

    return () => {
      cancelled = true;
      if (graceTimer !== null) {
        clearTimeout(graceTimer);
        graceTimer = null;
      }
      app.close();
      appRef.current = null;
      lastConnectFiring.current = null;
    };
  }, [name, version]);

  const subscribeToToolResult = useCallback(
    (listener: OnToolResult): Unsubscribe => {
      toolResultListeners.current.add(listener);
      return () => {
        toolResultListeners.current.delete(listener);
      };
    },
    [],
  );

  const subscribeToConnect = useCallback(
    (listener: OnConnect): Unsubscribe => {
      connectListeners.current.add(listener);
      // Replay the cached firing synchronously so late subscribers
      // (mounted after the grace window) still see it. App is
      // guaranteed to be non-null here because `lastConnectFiring`
      // only flips non-null inside the connect effect, which sets
      // `appRef.current` first.
      const fired = lastConnectFiring.current;
      const app = appRef.current;
      if (fired && app) {
        try {
          listener(app, fired.gotResult);
        } catch (e) {
          console.error("onConnect replay failed:", e);
        }
      }
      return () => {
        connectListeners.current.delete(listener);
      };
    },
    [],
  );

  const value = useMemo<McpAppContextValue>(
    () => ({
      app: appRef.current,
      getApp: () => appRef.current,
      connected,
      subscribeToToolResult,
      subscribeToConnect,
    }),
    [connected, subscribeToToolResult, subscribeToConnect],
  );

  return <McpAppContext.Provider value={value}>{children}</McpAppContext.Provider>;
}
