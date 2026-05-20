/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaClient } from "../kibana-client/index.js";

const TELEMETRY_CONFIG_PATH = "/api/telemetry/v2/config";
const KIBANA_API_VERSION = "2023-10-31";

const KIBANA_HEADERS = {
  "elastic-api-version": KIBANA_API_VERSION,
} as const;

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

export class TelemetryConfigClient {
  constructor(private readonly options: TelemetryConfigClientOptions) {}

  async fetchConfig(): Promise<TelemetryConfig> {
    const { data } = await this.options.kibanaClient.get<TelemetryConfig>(
      TELEMETRY_CONFIG_PATH,
      { headers: KIBANA_HEADERS },
    );
    return data;
  }
}
