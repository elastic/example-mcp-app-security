/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { EsqlClient } from "./esqlClient.js";
import {
  createMockEsClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";
import type { EsqlResult } from "../../shared/types.js";

describe("EsqlClient", () => {
  describe("executeEsql", () => {
    it("POSTs to /_query with the query body and format=json param", async () => {
      const esClient = createMockEsClient();
      const result: EsqlResult = { columns: [{ name: "x", type: "long" }], values: [[1]] };
      esClient.post.mockResolvedValueOnce(dataEnvelope(result));

      const client = new EsqlClient({ esClient });
      const out = await client.executeEsql("FROM logs-* | LIMIT 1");

      expect(esClient.post).toHaveBeenCalledTimes(1);
      expect(esClient.post).toHaveBeenCalledWith(
        "/_query",
        { query: "FROM logs-* | LIMIT 1" },
        { params: { format: "json" } }
      );
      expect(out).toEqual(result);
    });

    it("propagates transport errors", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockRejectedValueOnce(new Error("boom"));

      const client = new EsqlClient({ esClient });

      await expect(client.executeEsql("FROM x")).rejects.toThrow("boom");
    });
  });
});
