/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { CasesClient } from "./casesClient.js";
import {
  createMockEsClient,
  createMockKibanaClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

const CASES_API = "/api/cases";
const KIBANA_HEADERS = { "elastic-api-version": "2023-10-31" };

describe("CasesClient", () => {
  it("findCases GETs /_find with params + Kibana API version header", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(
      dataEnvelope({ cases: [], total: 0, page: 1, perPage: 20 })
    );

    const client = new CasesClient({ esClient, kibanaClient });
    await client.findCases({ status: "open" });

    expect(kibanaClient.get).toHaveBeenCalledWith(`${CASES_API}/_find`, {
      params: { status: "open" },
      headers: KIBANA_HEADERS,
    });
  });

  it("getCase GETs /api/cases/{id}", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ id: "c1" }));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.getCase("c1");

    expect(kibanaClient.get).toHaveBeenCalledWith(`${CASES_API}/c1`, {
      headers: KIBANA_HEADERS,
    });
  });

  it("createCase POSTs the body to /api/cases", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ id: "new" }));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.createCase({ title: "t" });

    expect(kibanaClient.post).toHaveBeenCalledWith(
      CASES_API,
      { title: "t" },
      { headers: KIBANA_HEADERS }
    );
  });

  it("updateCases PATCHes the bulk envelope to /api/cases", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.patch.mockResolvedValueOnce(dataEnvelope([]));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.updateCases({ cases: [{ id: "c1", version: "v" }] });

    expect(kibanaClient.patch).toHaveBeenCalledWith(
      CASES_API,
      { cases: [{ id: "c1", version: "v" }] },
      { headers: KIBANA_HEADERS }
    );
  });

  it("addComment POSTs to /api/cases/{id}/comments", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ ok: true }));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.addComment("c1", { type: "user", comment: "hi" });

    expect(kibanaClient.post).toHaveBeenCalledWith(
      `${CASES_API}/c1/comments`,
      { type: "user", comment: "hi" },
      { headers: KIBANA_HEADERS }
    );
  });

  it("getCaseAlerts GETs /api/cases/{id}/alerts", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope([]));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.getCaseAlerts("c1");

    expect(kibanaClient.get).toHaveBeenCalledWith(`${CASES_API}/c1/alerts`, {
      headers: KIBANA_HEADERS,
    });
  });

  it("getCommentsFind GETs /api/cases/{id}/comments/_find with params", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(
      dataEnvelope({ comments: [], total: 0 })
    );

    const client = new CasesClient({ esClient, kibanaClient });
    await client.getCommentsFind("c1", { perPage: "100" });

    expect(kibanaClient.get).toHaveBeenCalledWith(
      `${CASES_API}/c1/comments/_find`,
      { params: { perPage: "100" }, headers: KIBANA_HEADERS }
    );
  });

  it("getCasesForAlert GETs /api/cases/alerts/{alertId}", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope([]));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.getCasesForAlert("a1");

    expect(kibanaClient.get).toHaveBeenCalledWith(`${CASES_API}/alerts/a1`, {
      headers: KIBANA_HEADERS,
    });
  });

  it("getUserProfile GETs the security user profile WITHOUT Kibana API version header", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(
      dataEnvelope({ user: { username: "k" } })
    );

    const client = new CasesClient({ esClient, kibanaClient });
    await client.getUserProfile({ dataPath: "avatar" });

    expect(kibanaClient.get).toHaveBeenCalledWith(
      "/internal/security/user_profile",
      { params: { dataPath: "avatar" } }
    );
  });

  it("searchAlertsByIds POSTs an `ids` query to a multi-index _search", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    esClient.post.mockResolvedValueOnce(
      dataEnvelope({ hits: { hits: [{ _id: "a", _index: "i", _source: {} }] } })
    );

    const client = new CasesClient({ esClient, kibanaClient });
    const hits = await client.searchAlertsByIds(
      [".alerts-security.alerts-default", ".internal.alerts-security.alerts-default-000001"],
      ["a", "b"]
    );

    // A search (not `_doc`/`_mget`) so the lookup survives an alerts alias
    // with multiple backing indices (post-rollover clusters).
    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-default,.internal.alerts-security.alerts-default-000001/_search",
      { query: { ids: { values: ["a", "b"] } }, size: 2 },
      { params: { ignore_unavailable: "true", allow_no_indices: "true" } }
    );
    expect(hits).toEqual([{ _id: "a", _index: "i", _source: {} }]);
  });
});
