/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useCallback, useEffect, useRef } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { useMcpApp } from "./useMcpApp";
import type { ViewId } from "../analytics-events";

export type { ViewId };

export interface UseAnalytics {
  /**
   * Forward one `view_rendered` event to the MCP server.
   *
   * The hook does **not** dedupe — every call produces one event. The
   * consumer owns the firing decision and is responsible for calling
   * this the correct number of times (typically once per view mount,
   * from inside a `useEffect`).
   *
   * Calls made before `app.connect()` resolves are buffered in-memory
   * and flushed automatically the moment `connected` flips to `true`,
   * so consumers can call this from a mount effect without having to
   * gate on the connect state themselves.
   *
   * Errors from `app.callServerTool()` are swallowed: telemetry is
   * fire-and-forget and must never break the view.
   */
  trackViewRendered: (viewId: ViewId) => void;
}

function dispatch(app: McpApp, viewId: ViewId): void {
  void app
    .callServerTool({
      name: "report-analytics-event",
      arguments: { eventType: "view_rendered", viewId },
    })
    .catch(() => {
      // Telemetry is fire-and-forget; swallow.
    });
}

/**
 * Hook for emitting client-side analytics from a React view.
 *
 * Returns a `trackViewRendered` function — the hook itself has no
 * side effects on render. Firing an event is the consumer's call:
 *
 * ```ts
 * const { trackViewRendered } = useAnalytics();
 * useEffect(() => {
 *   trackViewRendered("alert-triage");
 * }, [trackViewRendered]);
 * ```
 *
 * `trackViewRendered` has a **stable identity** for the lifetime of
 * the enclosing `<McpAppProvider>`: the underlying `connected` /
 * `getApp` values are read through refs so a consumer's effect isn't
 * re-run just because the provider rebuilt its context value when
 * connect resolved.
 *
 * Events are reported via the app-only `report-analytics-event` MCP
 * tool; the server-side handler forwards them to the
 * {@link AnalyticsClient}, which in turn ships them via EBT (subject
 * to the user's Kibana opt-in).
 */
export function useAnalytics(): UseAnalytics {
  const { getApp, connected } = useMcpApp();

  // Buffer view IDs requested before the connection is ready; flushed
  // on the first render after `connected` flips. This is transport
  // resilience, not consumer-call deduplication — repeated calls to
  // `trackViewRendered(viewId)` pre-connect produce repeated buffer
  // entries and repeated post-connect emissions.
  const pending = useRef<ViewId[]>([]);

  // Read the latest provider state via refs so `trackViewRendered`
  // can be memoised with no deps. Consumers wire it into a useEffect
  // dep list and shouldn't see those effects re-fire just because
  // the provider's context value churned (e.g. on the connect flip).
  const getAppRef = useRef(getApp);
  getAppRef.current = getApp;
  const connectedRef = useRef(connected);
  connectedRef.current = connected;

  const trackViewRendered = useCallback((viewId: ViewId): void => {
    if (!connectedRef.current) {
      pending.current.push(viewId);
      return;
    }
    const app = getAppRef.current();
    if (app) dispatch(app, viewId);
  }, []);

  // One-shot flush on the connect transition. Reads `getApp` from
  // the effect's own closure rather than the ref so the flush sees
  // the same provider state that triggered the rerun.
  useEffect(() => {
    if (!connected || pending.current.length === 0) return;
    const app = getApp();
    if (!app) return;
    const buffered = pending.current.splice(0, pending.current.length);
    for (const viewId of buffered) dispatch(app, viewId);
  }, [connected, getApp]);

  return { trackViewRendered };
}
