/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { createContextLoader } from "./context-loader.js";
import { createMockAnalyticsClient } from "../../test/helpers/mockAnalytics.js";
import {
  createMockEsClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

describe("createContextLoader().loadAndApply", () => {
  it("publishes cluster + license context from GET / and GET /_license", async () => {
    const esClient = createMockEsClient();
    esClient.get.mockImplementation(async (path: string) => {
      if (path === "/") {
        return dataEnvelope({
          cluster_uuid: "uuid-1",
          // `cluster_name` is deliberately present in the ES response
          // but must NOT be forwarded to the analytics client — it's
          // user-controlled and excluded from the anonymised feed.
          cluster_name: "primary",
          version: { number: "8.99.0" },
        });
      }
      if (path === "/_license") {
        return dataEnvelope({
          license: { uid: "lic-1", status: "active", type: "platinum" },
        });
      }
      throw new Error(`unexpected GET ${path}`);
    });
    const analytics = createMockAnalyticsClient();

    const loader = createContextLoader({ esClient, analytics });
    await loader.loadAndApply();

    expect(analytics.setClusterContext).toHaveBeenCalledWith({
      cluster_uuid: "uuid-1",
      cluster_version: "8.99.0",
    });
    expect(analytics.setLicenseContext).toHaveBeenCalledWith({
      license_id: "lic-1",
      license_status: "active",
      license_type: "platinum",
    });
  });

  it("skips cluster context when required fields are missing", async () => {
    const esClient = createMockEsClient();
    esClient.get.mockImplementation(async (path: string) => {
      if (path === "/") return dataEnvelope({ cluster_uuid: "uuid-1" });
      if (path === "/_license") return dataEnvelope({});
      throw new Error(`unexpected GET ${path}`);
    });
    const analytics = createMockAnalyticsClient();
    const warn = vi.fn();

    const loader = createContextLoader({ esClient, analytics, logger: { warn } });
    await loader.loadAndApply();

    expect(analytics.setClusterContext).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("missing required cluster fields"),
    );
  });

  it("swallows cluster fetch errors and still attempts the license fetch", async () => {
    const esClient = createMockEsClient();
    esClient.get.mockImplementation(async (path: string) => {
      if (path === "/") throw new Error("cluster down");
      if (path === "/_license") {
        return dataEnvelope({
          license: { uid: "lic-1", status: "active", type: "gold" },
        });
      }
      throw new Error(`unexpected GET ${path}`);
    });
    const analytics = createMockAnalyticsClient();
    const warn = vi.fn();

    const loader = createContextLoader({ esClient, analytics, logger: { warn } });
    await loader.loadAndApply();

    expect(analytics.setClusterContext).not.toHaveBeenCalled();
    expect(analytics.setLicenseContext).toHaveBeenCalledWith({
      license_id: "lic-1",
      license_status: "active",
      license_type: "gold",
    });
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("cluster down"),
    );
  });
});
