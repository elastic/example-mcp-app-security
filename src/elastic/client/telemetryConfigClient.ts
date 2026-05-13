/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaClient } from "../kibana-client/index.js";

const TELEMETRY_CONFIG_PATH = "/api/telemetry/v2/config";
const KIBANA_API_VERSION = "2023-10-31";

/** Headers required on every Kibana telemetry config call. */
const KIBANA_HEADERS = {
  "elastic-api-version": KIBANA_API_VERSION,
} as const;

/**
 * Response shape for `GET /api/telemetry/v2/config`.
 *
 * Mirrors `v2.FetchTelemetryConfigResponse` in Kibana
 * (`src/platform/plugins/shared/telemetry/common/types`). Only `optIn`
 * is consumed by the MCP App today, but the full shape is typed so a
 * Kibana-side schema change is caught at the boundary.
 *
 * The semantics of `optIn` are critical:
 *   - `true`  — user has explicitly opted in
 *   - `false` — user has explicitly opted out
 *   - `null`  — user has not been prompted yet; treat as opt-out
 */
export interface TelemetryConfig {
  readonly allowChangingOptInStatus: boolean;
  readonly optIn: boolean | null;
  readonly sendUsageFrom: "server" | "browser";
  readonly telemetryNotifyUserAboutOptInDefault: boolean;
  readonly labels: Record<string, string>;
}

interface TelemetryConfigClientOptions {
  readonly kibanaClient: KibanaClient;
}

/**
 * Typed transport for Kibana's public telemetry config endpoint.
 *
 * Kibana exposes `GET /api/telemetry/v2/config` as a
 * `access: 'public'`, `authz.enabled: false` route specifically so
 * other Elastic products can poll opt-in status; this client is a 1:1
 * wrapper around it.
 *
 * `x-elastic-internal-origin` is intentionally NOT overridden — the
 * route does not consult `createRestrictInternalRoutesPostAuthHandler`
 * for public routes, so the default header value carried by the
 * existing {@link KibanaClient} is fine.
 */
export class TelemetryConfigClient {
  constructor(private readonly options: TelemetryConfigClientOptions) {}

  /** GET `/api/telemetry/v2/config`. */
  async fetchConfig(): Promise<TelemetryConfig> {
    const { data } = await this.options.kibanaClient.get<TelemetryConfig>(
      TELEMETRY_CONFIG_PATH,
      { headers: KIBANA_HEADERS },
    );
    return data;
  }
}
