/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { registerTrackedAppTool } from "./tracked-app-tool.js";
import { createMockMcpServer } from "../test/helpers/mockMcpServer.js";
import { createMockAnalyticsClient } from "../test/helpers/mockAnalytics.js";

const baseConfig = {
  title: "Probe",
  description: "test tool",
  inputSchema: { value: z.string() },
  _meta: { ui: { resourceUri: "ui://probe/view.html" } },
} as const;

function makeOkResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

describe("registerTrackedAppTool", () => {
  beforeEach(() => {
    vi.spyOn(performance, "now")
      .mockReturnValueOnce(1000)
      .mockReturnValueOnce(1042);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("emits mcp_tool_called with the recorded duration on a successful resolve", async () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();
    const handler = vi.fn(async () => makeOkResult("ok"));

    registerTrackedAppTool(
      analytics,
      server as unknown as McpServer,
      "probe",
      baseConfig,
      handler,
    );

    const tool = server.tool("probe");
    const out = await tool.callback({ value: "x" });

    expect(out).toEqual(makeOkResult("ok"));
    expect(handler).toHaveBeenCalledOnce();
    expect(analytics.trackToolCalled).toHaveBeenCalledExactlyOnceWith({
      tool_id: "probe",
      duration_ms: 42,
      success: true,
    });
  });

  it("emits success: false and rethrows when the handler rejects", async () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();
    const boom = new Error("handler failed");
    const handler = vi.fn(async () => {
      throw boom;
    });

    registerTrackedAppTool(
      analytics,
      server as unknown as McpServer,
      "probe",
      baseConfig,
      handler,
    );

    const tool = server.tool("probe");
    await expect(tool.callback({ value: "x" })).rejects.toBe(boom);

    expect(analytics.trackToolCalled).toHaveBeenCalledExactlyOnceWith({
      tool_id: "probe",
      duration_ms: 42,
      success: false,
    });
  });

  it("never mutates the handler's behaviour when telemetry throws (resolve path)", async () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();
    (analytics.trackToolCalled as ReturnType<typeof vi.fn>).mockImplementation(() => {
      throw new Error("telemetry exploded");
    });
    const handler = vi.fn(async () => makeOkResult("payload"));

    registerTrackedAppTool(
      analytics,
      server as unknown as McpServer,
      "probe",
      baseConfig,
      handler,
    );

    const tool = server.tool("probe");
    const out = await tool.callback({ value: "x" });

    expect(out).toEqual(makeOkResult("payload"));
  });

  it("never mutates the handler's behaviour when telemetry throws (reject path)", async () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();
    (analytics.trackToolCalled as ReturnType<typeof vi.fn>).mockImplementation(() => {
      throw new Error("telemetry exploded");
    });
    const handlerErr = new Error("handler failed");
    const handler = vi.fn(async () => {
      throw handlerErr;
    });

    registerTrackedAppTool(
      analytics,
      server as unknown as McpServer,
      "probe",
      baseConfig,
      handler,
    );

    const tool = server.tool("probe");
    await expect(tool.callback({ value: "x" })).rejects.toBe(handlerErr);
  });
});
