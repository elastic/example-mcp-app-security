/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EventTypeOpts } from "@elastic/ebt/client/index.js";
import type { ViewId } from "../../shared/analytics-events.js";

export { VIEW_IDS, type ViewId } from "../../shared/analytics-events.js";

/**
 * Stable event type identifiers used both when the EBT shipper registers
 * the event types at startup and when callers report events. Kept as a
 * `const` object so a typo on either end fails to compile.
 */
export const EVENT_TYPES = {
  mcpToolCalled: "mcp_tool_called",
  viewRendered: "view_rendered",
} as const;

/**
 * EBT payload reported when a model-facing or app-only MCP tool returns.
 *
 * Server-side shape used by the EBT shipper — distinct from the
 * client→server wire format types in `src/shared/analytics-events.ts`.
 * Field names are snake_case to match the Kibana telemetry schema.
 */
export interface McpToolCalledEbtPayload {
  readonly tool_id: string;
  readonly duration_ms: number;
  readonly success: boolean;
}

/**
 * EBT payload reported when a React view mounts.
 *
 * Distinct from the wire-format {@link ViewRenderedEvent} in
 * `src/shared/analytics-events.ts`: that one is what the React hook
 * sends through the MCP tool (camelCase + `eventType` discriminator),
 * this one is what the server ships onward to EBT.
 */
export interface ViewRenderedEbtPayload {
  readonly view_id: ViewId;
}

/**
 * EBT schema for `mcp_tool_called`. Kept alongside the TS type so adding
 * a field can't drift the two apart.
 */
export const mcpToolCalledEventDef: EventTypeOpts<McpToolCalledEbtPayload> = {
  eventType: EVENT_TYPES.mcpToolCalled,
  schema: {
    tool_id: {
      type: "keyword",
      _meta: { description: "MCP tool that was invoked" },
    },
    duration_ms: {
      type: "long",
      _meta: { description: "Wall-clock duration of the tool handler in ms" },
    },
    success: {
      type: "boolean",
      _meta: {
        description: "Whether the handler resolved (true) or threw (false)",
      },
    },
  },
};

export const viewRenderedEventDef: EventTypeOpts<ViewRenderedEbtPayload> = {
  eventType: EVENT_TYPES.viewRendered,
  schema: {
    view_id: {
      type: "keyword",
      _meta: { description: "Identifier of the React view that mounted" },
    },
  },
};
