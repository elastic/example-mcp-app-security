/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { EntityDetailClient } from "./entityDetailClient.js";
import {
  createMockEsClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

describe("EntityDetailClient", () => {
  describe("searchByTerms", () => {
    it("POSTs to /{index}/_search with the supplied body and returns the envelope", async () => {
      const esClient = createMockEsClient();
      const response = { hits: { hits: [{ _source: { foo: "bar" } }] } };
      esClient.post.mockResolvedValueOnce(dataEnvelope(response));

      const client = new EntityDetailClient({ esClient });
      const body = { query: { term: { "host.name": "h1" } } };
      const out = await client.searchByTerms<{ _source: { foo: string } }>(
        "logs-endpoint.events.process-*",
        body
      );

      expect(esClient.post).toHaveBeenCalledWith(
        "/logs-endpoint.events.process-*/_search",
        body
      );
      expect(out).toEqual(response);
    });
  });
});
