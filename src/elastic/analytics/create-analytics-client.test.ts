/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { createAnalyticsClient } from "./create-analytics-client.js";
import type { Logger } from "../../shared/logger.js";

describe("createAnalyticsClient", () => {
  function createMockLogger(): Pick<Logger, "debug" | "info" | "warn" | "error"> {
    return {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    };
  }

  beforeEach(() => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("exposes the typed AnalyticsClient surface", () => {
    const client = createAnalyticsClient({ mcpAppVersion: "1.2.3" });

    expect(typeof client.trackToolCalled).toBe("function");
    expect(typeof client.trackViewRendered).toBe("function");
    expect(typeof client.setOptIn).toBe("function");
    expect(typeof client.setClusterContext).toBe("function");
    expect(typeof client.setLicenseContext).toBe("function");
    expect(typeof client.shutdown).toBe("function");
  });

  it("does not throw on track* calls before opt-in (events are queued)", () => {
    const client = createAnalyticsClient({
      mcpAppVersion: "1.2.3",
      logger: createMockLogger(),
    });

    expect(() => {
      client.trackToolCalled({
        tool_id: "triage-alerts",
        duration_ms: 12,
        success: true,
      });
      client.trackViewRendered({ view_id: "alert-triage" });
    }).not.toThrow();
  });

  it("does not write EBT debug output to stdout with the default logger", () => {
    const debug = vi.spyOn(console, "debug").mockImplementation(() => undefined);
    const info = vi.spyOn(console, "info").mockImplementation(() => undefined);
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const client = createAnalyticsClient({ mcpAppVersion: "1.2.3" });

    client.trackViewRendered({ view_id: "alert-triage" });

    expect(debug).not.toHaveBeenCalled();
    expect(info).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });

  it("logs each tracked telemetry event through the injected logger", () => {
    const logger = createMockLogger();
    const client = createAnalyticsClient({ mcpAppVersion: "1.2.3", logger });

    client.trackToolCalled({
      tool_id: "triage-alerts",
      duration_ms: 12,
      success: true,
    });
    client.trackViewRendered({ view_id: "alert-triage" });

    expect(logger.info).toHaveBeenCalledWith(
      'reported event: send_to=production type=mcp_tool_called payload={"tool_id":"triage-alerts","duration_ms":12,"success":true}',
    );
    expect(logger.info).toHaveBeenCalledWith(
      'reported event: send_to=production type=view_rendered payload={"view_id":"alert-triage"}',
    );
  });

  it("logs the configured telemetry destination with tracked events", () => {
    const logger = createMockLogger();
    const client = createAnalyticsClient({
      mcpAppVersion: "1.2.3",
      sendTo: "staging",
      logger,
    });

    client.trackViewRendered({ view_id: "alert-triage" });

    expect(logger.info).toHaveBeenCalledWith(
      'reported event: send_to=staging type=view_rendered payload={"view_id":"alert-triage"}',
    );
  });

  it("setOptIn / setClusterContext / setLicenseContext are side-effect-only and return void", () => {
    const client = createAnalyticsClient({ mcpAppVersion: "1.2.3" });

    expect(client.setOptIn(true)).toBeUndefined();
    expect(
      client.setClusterContext({
        cluster_uuid: "uuid-1",
        cluster_version: "8.99.0",
      }),
    ).toBeUndefined();
    expect(
      client.setLicenseContext({
        license_id: "lic-1",
        license_status: "active",
        license_type: "platinum",
      }),
    ).toBeUndefined();
  });

  it("shutdown() resolves to a Promise<void>", async () => {
    const client = createAnalyticsClient({ mcpAppVersion: "1.2.3" });
    await expect(client.shutdown()).resolves.toBeUndefined();
  });
});
