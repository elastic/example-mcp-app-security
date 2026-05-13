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

/** Payload reported when a model-facing or app-only MCP tool returns. */
export interface McpToolCalledEvent {
  readonly tool_id: string;
  readonly duration_ms: number;
  readonly success: boolean;
}

/** Payload reported when a React view mounts. */
export interface ViewRenderedEvent {
  readonly view_id: ViewId;
}

/**
 * EBT schema for `mcp_tool_called`. Kept alongside the TS type so adding
 * a field can't drift the two apart.
 */
export const mcpToolCalledEventDef: EventTypeOpts<McpToolCalledEvent> = {
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

/** EBT schema for `view_rendered`. */
export const viewRenderedEventDef: EventTypeOpts<ViewRenderedEvent> = {
  eventType: EVENT_TYPES.viewRendered,
  schema: {
    view_id: {
      type: "keyword",
      _meta: { description: "Identifier of the React view that mounted" },
    },
  },
};
