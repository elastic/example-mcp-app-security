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
import { createStderrLogger, type Logger } from "../shared/logger.js";

export interface AnalyticsToolDeps {
  readonly analytics: Pick<AnalyticsClient, "trackViewRendered">;
  readonly logger?: Pick<Logger, "warn">;
}

/**
 * Wire schema for the app-only `report-analytics-event` MCP tool.
 *
 * Mirrors the {@link AnalyticsEvent} TypeScript discriminated union on
 * the React side — both ends must stay aligned. Adding an event type
 * means adding a `z.object` here, a variant to `AnalyticsEvent`, and a
 * case to the handler's `switch (eventType)` below.
 *
 * Kept as a closed discriminated union (not `z.object({...}).passthrough()`
 * or similar) so a malicious or buggy view can't smuggle free-form text
 * into the telemetry pipeline.
 */
const analyticsEventSchema = z.discriminatedUnion("eventType", [
  z.object({
    eventType: z.literal("view_rendered"),
    viewId: z.enum(VIEW_IDS),
  }),
]);

/**
 * Register the app-only `report-analytics-event` MCP tool used by the
 * frontend `useAnalytics()` hook.
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
  const logger = deps.logger ?? createStderrLogger(["analytics-tool"]);

  registerAppTool(
    server,
    "report-analytics-event",
    {
      title: "Report Analytics Event",
      description: "Internal: report a UI analytics event",
      inputSchema: analyticsEventSchema,
      _meta: { ui: { visibility: ["app"] } },
    },
    async (event) => {
      try {
        switch (event.eventType) {
          case "view_rendered":
            analytics.trackViewRendered({ view_id: event.viewId });
            break;
          default: {
            const _exhaustive: never = event.eventType;
            void _exhaustive;
          }
        }
      } catch (err) {
        logger.warn(
          `report-analytics-event: trackViewRendered failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ ok: true }) }],
      };
    },
  );
}
