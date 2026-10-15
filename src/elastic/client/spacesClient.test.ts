/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { SpacesClient } from "./spacesClient.js";
import {
  createMockEsClient,
  createMockKibanaClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

function makeClient() {
  const esClient = createMockEsClient();
  const kibanaClient = createMockKibanaClient();
  return { esClient, kibanaClient, client: new SpacesClient({ esClient, kibanaClient }) };
}

describe("SpacesClient", () => {
  describe("listSpaces", () => {
    it("GETs /api/spaces/space and keeps only id, name, color and initials", async () => {
      const { kibanaClient, client } = makeClient();
      kibanaClient.get.mockResolvedValueOnce(
        dataEnvelope([
          {
            id: "default",
            name: "Default",
            description: "This is your default space!",
            color: "#00bfb3",
            initials: "D",
            disabledFeatures: [],
            _reserved: true,
          },
          { id: "soc", name: "SOC", disabledFeatures: ["ml"], imageUrl: "data:..." },
        ])
      );

      const out = await client.listSpaces();

      expect(kibanaClient.get).toHaveBeenCalledWith("/api/spaces/space", {
        headers: { "elastic-api-version": "2023-10-31" },
      });
      expect(out).toEqual([
        { id: "default", name: "Default", color: "#00bfb3", initials: "D" },
        { id: "soc", name: "SOC" },
      ]);
      for (const field of ["description", "disabledFeatures", "_reserved", "imageUrl"]) {
        expect(out[0]).not.toHaveProperty(field);
        expect(out[1]).not.toHaveProperty(field);
      }
    });

    it("propagates Kibana errors", async () => {
      const { kibanaClient, client } = makeClient();
      const boom = new Error("kibana 403");
      kibanaClient.get.mockRejectedValueOnce(boom);
      await expect(client.listSpaces()).rejects.toBe(boom);
    });
  });

  describe("countBySpace", () => {
    it("POSTs the body to /{pattern}/_search, tolerating missing indices", async () => {
      const { esClient, client } = makeClient();
      const response = {
        aggregations: { by_space: { buckets: [{ key: "default", doc_count: 3 }] } },
      };
      esClient.post.mockResolvedValueOnce(dataEnvelope(response));
      const body = { size: 0 };

      const out = await client.countBySpace(".alerts-security.alerts-*", body);

      expect(esClient.post).toHaveBeenCalledWith("/.alerts-security.alerts-*/_search", body, {
        params: { ignore_unavailable: "true", allow_no_indices: "true" },
      });
      expect(out).toBe(response);
    });

    it("keeps commas between the indices of a multi-index pattern", async () => {
      const { esClient, client } = makeClient();
      esClient.post.mockResolvedValueOnce(dataEnvelope({}));

      await client.countBySpace("a-*,b-*", {});

      expect(esClient.post.mock.calls[0][0]).toBe("/a-*,b-*/_search");
    });
  });
});
