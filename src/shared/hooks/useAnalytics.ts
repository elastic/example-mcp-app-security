/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useCallback, useEffect, useRef } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { useMcpApp } from "./useMcpApp";
import type { AnalyticsEvent, ViewId } from "../analytics-events";

export type { AnalyticsEvent, ViewId };

export interface UseAnalytics {
  trackEvent: (event: AnalyticsEvent) => void;
}

function dispatch(app: McpApp, event: AnalyticsEvent): void {
  void app
    .callServerTool({
      name: "report-analytics-event",
      arguments: event,
    })
    .catch(() => {});
}

export function useAnalytics(): UseAnalytics {
  const { getApp, connected } = useMcpApp();

  const pending = useRef<AnalyticsEvent[]>([]);

  const getAppRef = useRef(getApp);
  getAppRef.current = getApp;
  const connectedRef = useRef(connected);
  connectedRef.current = connected;

  const trackEvent = useCallback((event: AnalyticsEvent): void => {
    if (!connectedRef.current) {
      pending.current.push(event);
      return;
    }
    const app = getAppRef.current();
    if (app) dispatch(app, event);
  }, []);

  useEffect(() => {
    if (!connected || pending.current.length === 0) return;
    const app = getApp();
    if (!app) return;
    const buffered = pending.current.splice(0, pending.current.length);
    for (const event of buffered) dispatch(app, event);
  }, [connected, getApp]);

  return { trackEvent };
}
