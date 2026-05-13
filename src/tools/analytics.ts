/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAppTool } from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import {
  VIEW_IDS,
  type AnalyticsClient,
} from "../elastic/analytics/index.js";

/** Services the analytics bridge tool depends on. */
export interface AnalyticsToolDeps {
  readonly analytics: Pick<AnalyticsClient, "trackViewRendered">;
}

/**
 * Register the app-only `report-analytics-event` MCP tool used by the
 * frontend `useAnalytics()` hook.
 *
 * The tool's input schema is intentionally restrictive — `eventType` is
 * a single literal and `viewId` is a closed enum — so a malicious or
 * buggy view can't smuggle free-form text into the telemetry pipeline.
 * Adding a future event type means adding a literal to the union and
 * a new `track*` method on the analytics client; both ends remain
 * fully typed.
 *
 * The handler is intentionally not wrapped with `registerTrackedAppTool`:
 * tracking the report-event call itself would produce noisy
 * `mcp_tool_called` events that just mirror the report-event traffic.
 */
export function registerAnalyticsTools(
  server: McpServer,
  deps: AnalyticsToolDeps,
): void {
  const { analytics } = deps;

  registerAppTool(
    server,
    "report-analytics-event",
    {
      title: "Report Analytics Event",
      description: "Internal: report a UI analytics event",
      inputSchema: {
        eventType: z.literal("view_rendered"),
        viewId: z.enum(VIEW_IDS),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ viewId }) => {
      try {
        analytics.trackViewRendered({ view_id: viewId });
      } catch {
        // Telemetry must never break the view; swallow.
      }
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ ok: true }) }],
      };
    },
  );
}
