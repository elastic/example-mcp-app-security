/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { SampleDataClient } from "./sampleDataClient.js";
import {
  createMockEsClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

describe("SampleDataClient", () => {
  describe("bulkIndex", () => {
    it("POSTs raw NDJSON to /_bulk with the right headers and a 120s timeout", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(
        dataEnvelope({ items: [], errors: false })
      );

      const client = new SampleDataClient({ esClient });
      const ndjson =
        '{"create":{"_index":"x"}}\n{"foo":"bar"}\n';
      await client.bulkIndex(ndjson);

      const [path, body, opts] = esClient.post.mock.calls[0];
      expect(path).toBe("/_bulk");
      expect(body).toBe(ndjson);
      expect(opts).toMatchObject({
        headers: { "Content-Type": "application/x-ndjson" },
        timeout: 120_000,
      });
      // Identity transformRequest preserves the NDJSON payload as a string.
      expect(typeof opts.transformRequest[0]).toBe("function");
      expect(opts.transformRequest[0](ndjson)).toBe(ndjson);
    });
  });

  it("deleteByQuery POSTs the body to /{index}/_delete_by_query", async () => {
    const esClient = createMockEsClient();
    esClient.post.mockResolvedValueOnce(dataEnvelope({ deleted: 2 }));

    const client = new SampleDataClient({ esClient });
    const body = { query: { term: { tags: "x" } } };
    const out = await client.deleteByQuery("logs-x-default", body);

    expect(esClient.post).toHaveBeenCalledWith(
      "/logs-x-default/_delete_by_query",
      body
    );
    expect(out).toEqual({ deleted: 2 });
  });

  it("count POSTs the body to /{index}/_count", async () => {
    const esClient = createMockEsClient();
    esClient.post.mockResolvedValueOnce(dataEnvelope({ count: 17 }));

    const client = new SampleDataClient({ esClient });
    const out = await client.count("logs-x-default", {
      query: { match_all: {} },
    });

    expect(esClient.post).toHaveBeenCalledWith("/logs-x-default/_count", {
      query: { match_all: {} },
    });
    expect(out).toEqual({ count: 17 });
  });

  it("searchAlertsAggregation POSTs to the default alerts index when no namespace is given", async () => {
    const esClient = createMockEsClient();
    const response = {
      hits: { total: { value: 0 } },
      aggregations: { by_rule: { buckets: [] } },
    };
    esClient.post.mockResolvedValueOnce(dataEnvelope(response));

    const client = new SampleDataClient({ esClient });
    const out = await client.searchAlertsAggregation({ size: 0 });

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-default/_search",
      { size: 0 }
    );
    expect(out).toEqual(response);
  });

  it("searchAlertsAggregation substitutes the namespace into the alerts index name", async () => {
    const esClient = createMockEsClient();
    esClient.post.mockResolvedValueOnce(
      dataEnvelope({
        hits: { total: { value: 0 } },
        aggregations: { by_rule: { buckets: [] } },
      })
    );
    const client = new SampleDataClient({ esClient });

    await client.searchAlertsAggregation({ size: 0 }, "soc");

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-soc/_search",
      { size: 0 }
    );
  });
});
