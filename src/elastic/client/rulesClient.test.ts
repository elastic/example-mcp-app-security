/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { RulesClient } from "./rulesClient.js";
import {
  createMockEsClient,
  createMockKibanaClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

const RULES_API = "/api/detection_engine/rules";
const KIBANA_HEADERS = { "elastic-api-version": "2023-10-31" };

describe("RulesClient", () => {
  describe("findRules", () => {
    it("GETs /_find with params + Kibana API version header", async () => {
      const esClient = createMockEsClient();
      const kibanaClient = createMockKibanaClient();
      const envelope = { data: [], total: 0, page: 1, perPage: 20 };
      kibanaClient.get.mockResolvedValueOnce(dataEnvelope(envelope));

      const client = new RulesClient({ esClient, kibanaClient });
      const out = await client.findRules({ page: "1" });

      expect(kibanaClient.get).toHaveBeenCalledWith(`${RULES_API}/_find`, {
        params: { page: "1" },
        headers: KIBANA_HEADERS,
      });
      expect(out).toEqual(envelope);
    });
  });

  it("getRule GETs the base path with id param", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ id: "r1" }));

    const client = new RulesClient({ esClient, kibanaClient });
    await client.getRule("r1");

    expect(kibanaClient.get).toHaveBeenCalledWith(RULES_API, {
      params: { id: "r1" },
      headers: KIBANA_HEADERS,
    });
  });

  it("createRule POSTs the body with Kibana API version header", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ id: "new" }));

    const client = new RulesClient({ esClient, kibanaClient });
    await client.createRule({ name: "n" });

    expect(kibanaClient.post).toHaveBeenCalledWith(
      RULES_API,
      { name: "n" },
      { headers: KIBANA_HEADERS }
    );
  });

  it("patchRule PATCHes the base path with the body", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.patch.mockResolvedValueOnce(dataEnvelope({ id: "r1" }));

    const client = new RulesClient({ esClient, kibanaClient });
    await client.patchRule({ id: "r1", enabled: true });

    expect(kibanaClient.patch).toHaveBeenCalledWith(
      RULES_API,
      { id: "r1", enabled: true },
      { headers: KIBANA_HEADERS }
    );
  });

  it("deleteRule DELETEs with id param", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.delete.mockResolvedValueOnce(dataEnvelope(undefined));

    const client = new RulesClient({ esClient, kibanaClient });
    await client.deleteRule("r1");

    expect(kibanaClient.delete).toHaveBeenCalledWith(RULES_API, {
      params: { id: "r1" },
      headers: KIBANA_HEADERS,
    });
  });

  it("bulkAction POSTs to /_bulk_action", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ ok: true }));

    const client = new RulesClient({ esClient, kibanaClient });
    await client.bulkAction({ action: "enable", ids: ["a"] });

    expect(kibanaClient.post).toHaveBeenCalledWith(
      `${RULES_API}/_bulk_action`,
      { action: "enable", ids: ["a"] },
      { headers: KIBANA_HEADERS }
    );
  });

  it("addException POSTs to /{ruleId}/exceptions", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ ok: true }));

    const client = new RulesClient({ esClient, kibanaClient });
    await client.addException("r1", { items: [] });

    expect(kibanaClient.post).toHaveBeenCalledWith(
      `${RULES_API}/r1/exceptions`,
      { items: [] },
      { headers: KIBANA_HEADERS }
    );
  });

  it("listExceptions GETs the exception lists API", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(
      dataEnvelope({ data: [], total: 0, page: 1, perPage: 20 })
    );

    const client = new RulesClient({ esClient, kibanaClient });
    await client.listExceptions({ list_id: "L" });

    expect(kibanaClient.get).toHaveBeenCalledWith(
      "/api/exception_lists/items/_find",
      { params: { list_id: "L" }, headers: KIBANA_HEADERS }
    );
  });

  it("validateEsql POSTs the query to /_query on esClient", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    esClient.post.mockResolvedValueOnce(dataEnvelope({}));

    const client = new RulesClient({ esClient, kibanaClient });
    await client.validateEsql("FROM x");

    expect(esClient.post).toHaveBeenCalledWith("/_query", {
      query: "FROM x",
      fetch_size: 0,
    });
  });

  it("validateKqlOrEql POSTs the body to the alerts _validate/query endpoint", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    esClient.post.mockResolvedValueOnce(dataEnvelope({ valid: true }));

    const client = new RulesClient({ esClient, kibanaClient });
    await client.validateKqlOrEql({ query: { eql: { query: "x" } } });

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-default/_validate/query",
      { query: { eql: { query: "x" } } }
    );
  });

  it("searchAlertsAggregation POSTs the noisy-rules body to the alerts _search endpoint", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    const response = { aggregations: { by_rule: { buckets: [] } } };
    esClient.post.mockResolvedValueOnce(dataEnvelope(response));

    const client = new RulesClient({ esClient, kibanaClient });
    const out = await client.searchAlertsAggregation({ size: 0 });

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-default/_search",
      { size: 0 }
    );
    expect(out).toEqual(response);
  });
});
