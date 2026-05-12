/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import {
  IndicesClient,
  type CatIndicesRow,
  type RawMappingResponse,
} from "./indicesClient.js";
import {
  createMockEsClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

describe("IndicesClient", () => {
  describe("catIndices", () => {
    it("GETs /_cat/indices/{target} with the supplied params", async () => {
      const esClient = createMockEsClient();
      const rows: CatIndicesRow[] = [
        {
          index: "logs-1",
          health: "green",
          status: "open",
          "docs.count": "10",
          "store.size": "1kb",
        },
      ];
      esClient.get.mockResolvedValueOnce(dataEnvelope(rows));

      const client = new IndicesClient({ esClient });
      const out = await client.catIndices("logs-*", {
        format: "json",
        h: "index",
      });

      expect(esClient.get).toHaveBeenCalledWith("/_cat/indices/logs-*", {
        params: { format: "json", h: "index" },
      });
      expect(out).toEqual(rows);
    });
  });

  describe("getRawMapping", () => {
    it("GETs /{index}/_mapping and returns the envelope", async () => {
      const esClient = createMockEsClient();
      const mapping: RawMappingResponse = {
        "logs-default": { mappings: { properties: {} } },
      };
      esClient.get.mockResolvedValueOnce(dataEnvelope(mapping));

      const client = new IndicesClient({ esClient });
      const out = await client.getRawMapping("logs-*");

      expect(esClient.get).toHaveBeenCalledWith("/logs-*/_mapping");
      expect(out).toBe(mapping);
    });
  });
});
