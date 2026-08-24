/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  registerAppTool,
  type McpUiAppToolConfig,
  type ToolConfig,
} from "@modelcontextprotocol/ext-apps/server";
import type {
  McpServer,
  RegisteredTool,
  ToolCallback,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import type {
  AnySchema,
  ZodRawShapeCompat,
} from "@modelcontextprotocol/sdk/server/zod-compat.js";
import type { AnalyticsClient } from "../elastic/analytics/index.js";

type OpaqueCb = (...args: unknown[]) => unknown;

function wrapTrackedCallback(
  analytics: Pick<AnalyticsClient, "trackToolCalled">,
  name: string,
  cb: OpaqueCb
): OpaqueCb {
  return (...args) => {
    const start = performance.now();

    const emit = (success: boolean): void => {
      try {
        analytics.trackToolCalled({
          tool_id: name,
          duration_ms: Math.round(performance.now() - start),
          success,
        });
      } catch {
        // Telemetry must never mutate handler behaviour; swallow.
      }
    };

    return Promise.resolve(cb(...args)).then(
      (value) => {
        emit(true);
        return value;
      },
      (err: unknown) => {
        emit(false);
        throw err;
      }
    );
  };
}

/**
 * Drop-in replacement for `registerAppTool` that emits a typed
 * `mcp_tool_called` telemetry event for every invocation.
 *
 * The wrapper:
 *   - Measures wall-clock duration with `performance.now()`.
 *   - Reports `success: true` on resolve, `success: false` on reject.
 *   - **Never** lets a telemetry failure mutate the handler's return
 *     value or thrown error. The analytics path is wrapped in a
 *     try/catch and any throw from `trackToolCalled` is swallowed.
 *
 * The generic signature mirrors `registerAppTool`'s exactly so the
 * handler's argument types are still inferred from the `inputSchema`.
 * Call sites pass `analytics` first, then the same args as before:
 *
 * ```ts
 * registerTrackedAppTool(analytics, server, "triage-alerts", config, handler);
 * ```
 */
export function registerTrackedAppTool<
  OutputArgs extends ZodRawShapeCompat | AnySchema,
  InputArgs extends undefined | ZodRawShapeCompat | AnySchema = undefined,
>(
  analytics: Pick<AnalyticsClient, "trackToolCalled">,
  server: Pick<McpServer, "registerTool">,
  name: string,
  config: McpUiAppToolConfig & {
    inputSchema?: InputArgs;
    outputSchema?: OutputArgs;
  },
  cb: ToolCallback<InputArgs>
): RegisteredTool {
  return registerAppTool<OutputArgs, InputArgs>(
    server,
    name,
    config,
    wrapTrackedCallback(analytics, name, cb as unknown as OpaqueCb) as unknown as ToolCallback<InputArgs>
  );
}

/**
 * Same telemetry wrap as {@link registerTrackedAppTool}, but registers a
 * JSON-only tool via `server.registerTool`. Use this when there is no MCP
 * App UI (`registerAppTool` requires `_meta.ui`).
 */
export function registerTrackedTool<
  OutputArgs extends ZodRawShapeCompat | AnySchema,
  InputArgs extends undefined | ZodRawShapeCompat | AnySchema = undefined,
>(
  analytics: Pick<AnalyticsClient, "trackToolCalled">,
  server: Pick<McpServer, "registerTool">,
  name: string,
  config: ToolConfig & {
    inputSchema?: InputArgs;
    outputSchema?: OutputArgs;
  },
  cb: ToolCallback<InputArgs>
): RegisteredTool {
  return server.registerTool(
    name,
    config,
    wrapTrackedCallback(analytics, name, cb as unknown as OpaqueCb) as unknown as ToolCallback<InputArgs>
  );
}
