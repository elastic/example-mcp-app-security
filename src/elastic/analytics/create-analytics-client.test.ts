/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { createAnalyticsClient } from "./create-analytics-client.js";

/**
 * The analytics client wraps `@elastic/ebt`, which is non-trivial to
 * mock at runtime. These tests treat the factory as a black box and
 * just verify the public surface — construction, opt-in toggling,
 * context setters, and graceful shutdown — works without throwing.
 *
 * Behavioural coverage of the EBT shipper (opt-in semantics, header
 * generation, retry/back-off) belongs to `@elastic/ebt`'s own suite.
 */
describe("createAnalyticsClient", () => {
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
    const client = createAnalyticsClient({ mcpAppVersion: "1.2.3" });

    expect(() => {
      client.trackToolCalled({
        tool_id: "triage-alerts",
        duration_ms: 12,
        success: true,
      });
      client.trackViewRendered({ view_id: "alert-triage" });
    }).not.toThrow();
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
