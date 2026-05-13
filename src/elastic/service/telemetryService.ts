/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AnalyticsClient } from "../analytics/index.js";
import type { TelemetryConfigClient } from "../client/telemetryConfigClient.js";

interface TelemetryServiceOptions {
  readonly telemetryConfigClient: TelemetryConfigClient;
  readonly analytics: Pick<AnalyticsClient, "setOptIn">;
  readonly logger?: Pick<Console, "warn">;
}

/**
 * Mirrors the user's Kibana telemetry opt-in onto the local
 * {@link AnalyticsClient}. The MCP App never holds its own opt-in
 * state — Kibana is the single source of truth.
 *
 * **Fail-closed semantics.** Only `optIn === true` enables shipping.
 * Every other outcome (`false`, `null`, fetch error, malformed body)
 * resolves to `setOptIn(false)`. The analytics client also starts
 * opted-out at construction, so the gap between server start and the
 * first `applyOptIn()` call is safe.
 *
 * Currently a one-shot call on MCP server start; polling can be added
 * later without changing this surface.
 */
export class TelemetryService {
  constructor(private readonly options: TelemetryServiceOptions) {}

  async applyOptIn(): Promise<void> {
    const { telemetryConfigClient, analytics, logger = console } = this.options;

    try {
      const config = await telemetryConfigClient.fetchConfig();
      analytics.setOptIn(config.optIn === true);
    } catch (err) {
      logger.warn(
        `[telemetry] failed to read Kibana telemetry config; staying opted-out: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
      analytics.setOptIn(false);
    }
  }
}
