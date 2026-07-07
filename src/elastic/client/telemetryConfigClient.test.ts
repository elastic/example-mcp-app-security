/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import {
  TelemetryConfigClient,
  type TelemetryConfig,
} from "./telemetryConfigClient.js";
import {
  createMockKibanaClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

const CONFIG_PATH = "/api/telemetry/v2/config";

const sampleConfig: TelemetryConfig = {
  allowChangingOptInStatus: true,
  optIn: true,
  sendUsageFrom: "server",
  telemetryNotifyUserAboutOptInDefault: false,
  labels: {},
};

describe("TelemetryConfigClient", () => {
  it("GETs /api/telemetry/v2/config with the elastic-api-version header", async () => {
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope(sampleConfig));

    const client = new TelemetryConfigClient({ kibanaClient });
    const out = await client.fetchConfig();

    expect(kibanaClient.get).toHaveBeenCalledWith(CONFIG_PATH, {
      headers: { "elastic-api-version": "2023-10-31" },
    });
    expect(out).toEqual(sampleConfig);
  });

  it("propagates errors verbatim — failures must surface to the service", async () => {
    const kibanaClient = createMockKibanaClient();
    const boom = new Error("kibana 503");
    kibanaClient.get.mockRejectedValueOnce(boom);

    const client = new TelemetryConfigClient({ kibanaClient });
    await expect(client.fetchConfig()).rejects.toBe(boom);
  });
});
