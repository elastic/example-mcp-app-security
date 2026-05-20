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
  type McpAppBootstrapState,
  inspectMcpAppBootstrapResult,
} from "../mcp-app-bootstrap";
import {
  McpAppContext,
  type McpAppContextValue,
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
 * Lifecycle events (`ontoolresult` from the host) are fanned out to all
 * registered listeners via the `subscribeToToolResult` function on the
 * context value. The provider also persists the host-owned bootstrap
 * state in React state so late subscribers can synchronously read the
 * initial hydration payload after it arrives. Listener registries live
 * in `Set` refs so adding / removing subscribers never re-triggers the
 * connect effect.
 */
export function McpAppProvider({
  name,
  version,
  children,
}: McpAppProviderProps): ReactNode {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  const [bootstrapState, setBootstrapState] = useState<McpAppBootstrapState>({
    status: "idle",
  });

  // Pub/sub registries. Refs (not state) so adding subscribers never
  // re-runs the connect effect. `Set` semantics make subscribe/
  // unsubscribe O(1) and naturally support multiple subscribers per
  // event.
  const toolResultListeners = useRef<Set<OnToolResult>>(new Set());

  useEffect(() => {
    const app = new McpApp({ name, version });
    appRef.current = app;
    setConnected(false);
    setBootstrapState({ status: "idle" });
    applyTheme(app);

    let cancelled = false;

    app.ontoolresult = (params) => {
      // Snapshot the listener set so a subscriber that unsubscribes
      // during its own callback doesn't perturb the iteration order.
      for (const listener of [...toolResultListeners.current]) {
        try {
          listener(params, app);
        } catch (e) {
          console.error("onToolResult listener failed:", e);
        }
      }

      const bootstrapResult = inspectMcpAppBootstrapResult(params);
      if (bootstrapResult.status === "not_bootstrap") {
        return;
      }
      if (bootstrapResult.status === "error") {
        setBootstrapState((current) =>
          current.status === "ready" ? current : bootstrapResult,
        );
        return;
      }
      setBootstrapState((current) => {
        if (current.status === "ready") {
          return current;
        }
        if (bootstrapResult.envelope.viewId !== name) {
          return {
            status: "error",
            reason: `Received bootstrap for ${bootstrapResult.envelope.viewId} inside ${name}.`,
          };
        }
        return bootstrapResult;
      });
    };

    app.connect()
      .then(() => {
        if (cancelled) return;
        setConnected(true);
      })
      .catch((err) => {
        if (cancelled) return;
        console.error("MCP app connect() failed:", err);
      });

    return () => {
      cancelled = true;
      app.close();
      appRef.current = null;
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

  const value = useMemo<McpAppContextValue>(
    () => ({
      app: appRef.current,
      getApp: () => appRef.current,
      connected,
      bootstrapState,
      subscribeToToolResult,
    }),
    [bootstrapState, connected, subscribeToToolResult],
  );

  return <McpAppContext.Provider value={value}>{children}</McpAppContext.Provider>;
}
