/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  registerAppTool,
  type McpUiAppToolConfig,
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
  cb: ToolCallback<InputArgs>,
): RegisteredTool {
  // Treat the callback as an opaque (...args) => result function so we
  // don't have to reproduce the exact `args / extra` arity of
  // ToolCallback<InputArgs> (which differs by whether InputArgs is
  // undefined). The runtime contract is "forward whatever you got" —
  // the static types are re-applied via the `as unknown as` bridge
  // when handing back to `registerAppTool`.
  type OpaqueCb = (...args: unknown[]) => unknown;
  const original = cb as unknown as OpaqueCb;

  const wrapped: OpaqueCb = (...args) => {
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

    return Promise.resolve(original(...args)).then(
      (value) => {
        emit(true);
        return value;
      },
      (err: unknown) => {
        emit(false);
        throw err;
      },
    );
  };

  return registerAppTool<OutputArgs, InputArgs>(
    server,
    name,
    config,
    wrapped as unknown as ToolCallback<InputArgs>,
  );
}
