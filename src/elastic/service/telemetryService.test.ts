/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { TelemetryService } from "./telemetryService.js";
import { createMockAnalyticsClient } from "../../test/helpers/mockAnalytics.js";
import type {
  TelemetryConfig,
  TelemetryConfigClient,
} from "../client/telemetryConfigClient.js";

function fakeConfigClient(
  fetchConfig: () => Promise<TelemetryConfig>,
): TelemetryConfigClient {
  return { fetchConfig: vi.fn(fetchConfig) } as unknown as TelemetryConfigClient;
}

function buildConfig(overrides: Partial<TelemetryConfig> = {}): TelemetryConfig {
  return {
    allowChangingOptInStatus: true,
    optIn: true,
    sendUsageFrom: "server",
    telemetryNotifyUserAboutOptInDefault: false,
    labels: {},
    ...overrides,
  };
}

describe("TelemetryService.applyOptIn", () => {
  it("enables shipping when Kibana reports optIn === true", async () => {
    const analytics = createMockAnalyticsClient();
    const service = new TelemetryService({
      telemetryConfigClient: fakeConfigClient(async () => buildConfig({ optIn: true })),
      analytics,
    });

    await service.applyOptIn();

    expect(analytics.setOptIn).toHaveBeenCalledWith(true);
  });

  it("disables shipping when Kibana reports optIn === false", async () => {
    const analytics = createMockAnalyticsClient();
    const service = new TelemetryService({
      telemetryConfigClient: fakeConfigClient(async () => buildConfig({ optIn: false })),
      analytics,
    });

    await service.applyOptIn();

    expect(analytics.setOptIn).toHaveBeenCalledWith(false);
  });

  it("treats optIn === null as opted-out (user not prompted yet)", async () => {
    const analytics = createMockAnalyticsClient();
    const service = new TelemetryService({
      telemetryConfigClient: fakeConfigClient(async () => buildConfig({ optIn: null })),
      analytics,
    });

    await service.applyOptIn();

    expect(analytics.setOptIn).toHaveBeenCalledWith(false);
  });

  it("falls back to opted-out and logs when the config fetch throws", async () => {
    const analytics = createMockAnalyticsClient();
    const warn = vi.fn();
    const service = new TelemetryService({
      telemetryConfigClient: fakeConfigClient(async () => {
        throw new Error("network down");
      }),
      analytics,
      logger: { warn },
    });

    await service.applyOptIn();

    expect(analytics.setOptIn).toHaveBeenCalledWith(false);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("network down"),
    );
  });
});
