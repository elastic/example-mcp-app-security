/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  Fragment,
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
import { LIST_SPACES_TOOL, SPACE_ARG, isValidSpaceId, type ListSpacesResult } from "../spaces";
import { parseListSpacesResult, spaceDisplayName, withSpaceArg } from "../space-calls";
import {
  McpAppContext,
  type McpAppContextValue,
  type OnToolResult,
  type Unsubscribe,
} from "./McpAppContext";
import { McpSpaceContext, type McpSpaceContextValue } from "./McpSpaceContext";

/** Bounds how long a space switch waits for the host to ack the model context update. */
const MODEL_CONTEXT_TIMEOUT_MS = 2000;

function spaceSwitchText(id: string, name: string, configured: string): string {
  if (id === configured) {
    return `The analyst switched the Elastic Security view back to their configured Kibana space "${name}" (id: ${id}). Use the configured space for follow-up questions again (omit the \`space\` argument).`;
  }
  return `The analyst switched the Elastic Security view to the Kibana space "${name}" (id: ${id}) for this session. Use this space for follow-up questions about alerts, cases, rules and attack discoveries (pass \`space: "${id}"\` to Elastic Security tools) until they switch back.`;
}

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
 *
 * Kibana spaces: after connecting, the provider loads `list-spaces` and
 * exposes the result via {@link McpSpaceContext} (`useSpaces()`). Every
 * `callServerTool` on the instance is routed through {@link withSpaceArg},
 * so once the analyst picks another space for the session, view calls carry
 * `space` without each call site knowing about it.
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

  const [spaceList, setSpaceList] = useState<ListSpacesResult | null>(null);
  const [activeSpace, setActiveSpaceState] = useState("");
  // Read by the wrapped `callServerTool`, which outlives any single render.
  const activeSpaceRef = useRef("");
  const configuredSpaceRef = useRef("");
  const switchSeqRef = useRef(0);
  // Space the model passed on the tool call that rendered this view.
  const renderedSpaceRef = useRef("");
  const [viewKey, setViewKey] = useState(0);

  useEffect(() => {
    const app = new McpApp({ name, version });
    const callServerTool = app.callServerTool.bind(app);
    app.callServerTool = (params, options) =>
      callServerTool(
        withSpaceArg(params, activeSpaceRef.current, configuredSpaceRef.current),
        options,
      );
    appRef.current = app;
    setConnected(false);
    setBootstrapState({ status: "idle" });
    activeSpaceRef.current = "";
    configuredSpaceRef.current = "";
    switchSeqRef.current = 0;
    renderedSpaceRef.current = "";
    setSpaceList(null);
    setActiveSpaceState("");
    applyTheme(app);

    let cancelled = false;

    // The model chose this space, so it isn't told again. The remount drops any
    // load the view started in the configured space; a ready bootstrap from the
    // same call is kept, so the remounted view hydrates from it.
    const adoptRenderedSpace = (space: string) => {
      if (switchSeqRef.current > 0 || space === activeSpaceRef.current) return;
      activeSpaceRef.current = space;
      setActiveSpaceState(space);
      setViewKey((k) => k + 1);
    };

    app.ontoolinput = (params) => {
      const requested = params.arguments?.[SPACE_ARG];
      if (typeof requested !== "string" || !isValidSpaceId(requested)) return;
      renderedSpaceRef.current = requested;
      if (configuredSpaceRef.current) adoptRenderedSpace(requested);
    };

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
      // A bootstrap that arrives after a space switch describes the previous space.
      if (switchSeqRef.current > 0) {
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
      .then(async () => {
        if (cancelled) return;
        setConnected(true);
        try {
          const list = parseListSpacesResult(
            await app.callServerTool({ name: LIST_SPACES_TOOL, arguments: {} }),
          );
          if (cancelled || !list) return;
          configuredSpaceRef.current = list.configured;
          activeSpaceRef.current = list.configured;
          setSpaceList(list);
          setActiveSpaceState(list.configured);
          if (renderedSpaceRef.current) adoptRenderedSpace(renderedSpaceRef.current);
        } catch {
          // Older servers have no `list-spaces`; the space UI stays hidden.
        }
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

  const setActiveSpace = useCallback(
    async (id: string): Promise<void> => {
      const app = appRef.current;
      if (!app || !spaceList || id === activeSpaceRef.current) return;
      const seq = ++switchSeqRef.current;
      try {
        await app.updateModelContext(
          {
            content: [
              {
                type: "text",
                text: spaceSwitchText(id, spaceDisplayName(spaceList.spaces, id), spaceList.configured),
              },
            ],
          },
          { timeout: MODEL_CONTEXT_TIMEOUT_MS },
        );
      } catch {
        // Hosts without model context support still get the view switch.
      }
      if (seq !== switchSeqRef.current || appRef.current !== app) return;
      activeSpaceRef.current = id;
      setActiveSpaceState(id);
      setBootstrapState({ status: "idle" });
      setViewKey((k) => k + 1);
    },
    [spaceList],
  );

  const spaceValue = useMemo<McpSpaceContextValue>(
    () => ({
      configured: spaceList?.configured ?? "",
      active: activeSpace,
      spaces: spaceList?.spaces ?? [],
      setActiveSpace,
    }),
    [activeSpace, setActiveSpace, spaceList],
  );

  return (
    <McpAppContext.Provider value={value}>
      <McpSpaceContext.Provider value={spaceValue}>
        <Fragment key={viewKey}>{children}</Fragment>
      </McpSpaceContext.Provider>
    </McpAppContext.Provider>
  );
}
