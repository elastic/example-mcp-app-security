/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createKibanaClient } from "./create-kibana-client.js";
import type { ClusterCredentials } from "../credential-client/index.js";
import { runInSpace } from "../shared/space-context.js";
import { MockAxios } from "../../test/helpers/mockAxios.js";

const creds: ClusterCredentials = {
  name: "primary",
  elasticsearchUrl: "https://es.example.com",
  kibanaUrl: "https://kb.example.com",
  elasticsearchApiKey: "secret-key",
  sslVerify: true,
  spaceId: "default",
};

describe("createKibanaClient", () => {
  const mockAxios = new MockAxios();
  let restore: () => void;

  beforeEach(() => {
    restore = mockAxios.install();
    mockAxios
      .onGet(/\/api\/cases\/_find$/, { data: { cases: [] } })
      .onGet("https://other.example.com/api/status", { data: {} });
  });

  afterEach(() => {
    mockAxios.reset();
    restore();
  });

  describe("space request interceptor", () => {
    it("leaves paths unchanged in the default space", async () => {
      const client = createKibanaClient(creds);

      await client.get("/api/cases/_find");

      expect(mockAxios.history().map((r) => r.url)).toEqual([
        "/api/cases/_find",
      ]);
    });

    it("prefixes paths with /s/<space> inside runInSpace", async () => {
      const client = createKibanaClient(creds);

      await runInSpace("soc", () => client.get("/api/cases/_find"));

      expect(mockAxios.history().map((r) => r.url)).toEqual([
        "/s/soc/api/cases/_find",
      ]);
    });

    it("reads the space per request, not per client", async () => {
      const client = createKibanaClient(creds);

      await runInSpace("soc", () => client.get("/api/cases/_find"));
      await client.get("/api/cases/_find");
      await runInSpace("default", () => client.get("/api/cases/_find"));

      expect(mockAxios.history().map((r) => r.url)).toEqual([
        "/s/soc/api/cases/_find",
        "/api/cases/_find",
        "/api/cases/_find",
      ]);
    });

    it("does not rewrite absolute URLs", async () => {
      const client = createKibanaClient(creds);

      await runInSpace("soc", () =>
        client.get("https://other.example.com/api/status")
      );

      expect(mockAxios.history().map((r) => r.url)).toEqual([
        "https://other.example.com/api/status",
      ]);
    });
  });
});
