/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { InvestigateClient, type EsqlEnvelope } from "./investigateClient.js";
import {
  createMockEsClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

describe("InvestigateClient", () => {
  describe("runEsql", () => {
    it("POSTs to /_query with the query body and format=json param", async () => {
      const esClient = createMockEsClient();
      const envelope: EsqlEnvelope = {
        columns: [{ name: "host.name" }],
        values: [["server-1"]],
      };
      esClient.post.mockResolvedValueOnce(dataEnvelope(envelope));

      const client = new InvestigateClient({ esClient });
      const out = await client.runEsql("FROM logs-*");

      expect(esClient.post).toHaveBeenCalledWith(
        "/_query",
        { query: "FROM logs-*" },
        { params: { format: "json" } }
      );
      expect(out).toEqual(envelope);
    });
  });
});
