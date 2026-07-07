/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { registerAnalyticsTools } from "./analytics.js";
import { createMockMcpServer } from "../test/helpers/mockMcpServer.js";
import { createMockAnalyticsClient } from "../test/helpers/mockAnalytics.js";
import { VIEW_IDS } from "../shared/analytics-events.js";

describe("registerAnalyticsTools", () => {
  it("registers a single app-only tool named report-analytics-event", () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();

    registerAnalyticsTools(server as unknown as McpServer, { analytics });

    expect([...server.tools.keys()]).toEqual(["report-analytics-event"]);
    const tool = server.tool("report-analytics-event");
    expect(tool.config._meta).toMatchObject({ ui: { visibility: ["app"] } });
  });

  it("dispatches view_rendered events to trackViewRendered", async () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();

    registerAnalyticsTools(server as unknown as McpServer, { analytics });
    const tool = server.tool("report-analytics-event");

    await tool.callback({ eventType: "view_rendered", viewId: "alert-triage" });

    expect(analytics.trackViewRendered).toHaveBeenCalledExactlyOnceWith({
      view_id: "alert-triage",
    });
  });

  it("input schema rejects unknown eventType / viewId values (forward-compat)", () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();

    registerAnalyticsTools(server as unknown as McpServer, { analytics });
    const tool = server.tool("report-analytics-event");

    const inputSchema = tool.config.inputSchema as z.ZodTypeAny;

    expect(
      inputSchema.safeParse({ eventType: "view_action", viewId: "alert-triage" })
        .success,
    ).toBe(false);
    expect(
      inputSchema.safeParse({ eventType: "view_rendered", viewId: "nope" }).success,
    ).toBe(false);
    expect(
      inputSchema.safeParse({
        eventType: "view_rendered",
        viewId: "alert-triage",
      }).success,
    ).toBe(true);
    expect(
      inputSchema.safeParse({ viewId: "alert-triage" }).success,
    ).toBe(false);
  });

  it("never throws if trackViewRendered itself throws", async () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();
    (analytics.trackViewRendered as ReturnType<typeof import("vitest").vi.fn>).mockImplementation(() => {
      throw new Error("telemetry exploded");
    });

    registerAnalyticsTools(server as unknown as McpServer, { analytics });
    const tool = server.tool("report-analytics-event");

    await expect(
      tool.callback({ eventType: "view_rendered", viewId: "alert-triage" }),
    ).resolves.toEqual(
      expect.objectContaining({
        content: [
          expect.objectContaining({ text: JSON.stringify({ ok: true }) }),
        ],
      }),
    );
  });

  it("warns via the injected logger when trackViewRendered throws", async () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();
    const warn = vi.fn();
    (analytics.trackViewRendered as ReturnType<typeof vi.fn>).mockImplementation(() => {
      throw new Error("shipper offline");
    });

    registerAnalyticsTools(server as unknown as McpServer, { analytics, logger: { warn } });
    const tool = server.tool("report-analytics-event");

    await tool.callback({ eventType: "view_rendered", viewId: "alert-triage" });

    expect(warn).toHaveBeenCalledOnce();
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("shipper offline"),
    );
  });

  it("covers every value in VIEW_IDS without a runtime mismatch", async () => {
    const server = createMockMcpServer();
    const analytics = createMockAnalyticsClient();

    registerAnalyticsTools(server as unknown as McpServer, { analytics });
    const tool = server.tool("report-analytics-event");

    for (const viewId of VIEW_IDS) {
      await tool.callback({ eventType: "view_rendered", viewId });
    }

    expect(analytics.trackViewRendered).toHaveBeenCalledTimes(VIEW_IDS.length);
  });
});
