/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AnalyticsClient, TelemetrySendTo } from "../analytics/index.js";
import { resolveTelemetrySendTo } from "../analytics/index.js";
import type { TelemetryConfigClient } from "../client/telemetryConfigClient.js";
import { createStderrLogger, type Logger } from "../../shared/logger.js";

interface TelemetryServiceOptions {
  readonly telemetryConfigClient: TelemetryConfigClient;
  readonly analytics: Pick<AnalyticsClient, "setOptIn">;
  readonly sendTo?: TelemetrySendTo;
  readonly logger?: Pick<Logger, "info" | "warn">;
}

export class TelemetryService {
  constructor(private readonly options: TelemetryServiceOptions) {}

  async applyOptIn(): Promise<void> {
    const {
      telemetryConfigClient,
      analytics,
      sendTo = resolveTelemetrySendTo(process.env.MCP_APP_TELEMETRY_ENV),
      logger = createStderrLogger(["telemetry"]),
    } = this.options;

    try {
      const config = await telemetryConfigClient.fetchConfig();
      const enabled = config.optIn === true;
      analytics.setOptIn(enabled);
      logger.info(
        `Kibana telemetry opt-in resolved: enabled=${enabled} raw=${String(
          config.optIn,
        )} send_to=${sendTo}`,
      );
    } catch (err) {
      logger.warn(
        `failed to read Kibana telemetry config; staying opted-out: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
      analytics.setOptIn(false);
      logger.info(
        `Kibana telemetry opt-in resolved: enabled=false raw=unavailable send_to=${sendTo}`,
      );
    }
  }
}
