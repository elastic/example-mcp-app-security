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

  it("findCases / getCase / updateCases / getCaseAlerts / getCommentsFind / getCasesForAlert all prefix the path with /s/<namespace>", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValue(dataEnvelope({}));
    kibanaClient.patch.mockResolvedValue(dataEnvelope([]));

    const client = new CasesClient({ esClient, kibanaClient });

    await client.findCases({ status: "open" }, "soc");
    expect(kibanaClient.get).toHaveBeenLastCalledWith(
      `/s/soc${CASES_API}/_find`,
      { params: { status: "open" }, headers: KIBANA_HEADERS }
    );

    await client.getCase("c1", "soc");
    expect(kibanaClient.get).toHaveBeenLastCalledWith(
      `/s/soc${CASES_API}/c1`,
      { headers: KIBANA_HEADERS }
    );

    await client.updateCases({ cases: [] }, "soc");
    expect(kibanaClient.patch).toHaveBeenLastCalledWith(
      `/s/soc${CASES_API}`,
      { cases: [] },
      { headers: KIBANA_HEADERS }
    );

    await client.getCaseAlerts("c1", "soc");
    expect(kibanaClient.get).toHaveBeenLastCalledWith(
      `/s/soc${CASES_API}/c1/alerts`,
      { headers: KIBANA_HEADERS }
    );

    await client.getCommentsFind("c1", { perPage: "100" }, "soc");
    expect(kibanaClient.get).toHaveBeenLastCalledWith(
      `/s/soc${CASES_API}/c1/comments/_find`,
      { params: { perPage: "100" }, headers: KIBANA_HEADERS }
    );

    await client.getCasesForAlert("a1", "soc");
    expect(kibanaClient.get).toHaveBeenLastCalledWith(
      `/s/soc${CASES_API}/alerts/a1`,
      { headers: KIBANA_HEADERS }
    );
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

  it("createCase prefixes the path with /s/<namespace> for a non-default space", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ id: "new" }));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.createCase({ title: "t" }, "soc");

    expect(kibanaClient.post).toHaveBeenCalledWith(
      `/s/soc${CASES_API}`,
      { title: "t" },
      { headers: KIBANA_HEADERS }
    );
  });

  it("createCase treats 'default' as the un-prefixed path", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ id: "new" }));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.createCase({ title: "t" }, "default");

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

  it("addComment prefixes the path with /s/<namespace> for a non-default space", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.post.mockResolvedValueOnce(dataEnvelope({ ok: true }));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.addComment("c1", { type: "user", comment: "hi" }, "soc");

    expect(kibanaClient.post).toHaveBeenCalledWith(
      `/s/soc${CASES_API}/c1/comments`,
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

  it("getAlertDocument GETs /{index}/_doc/{id} on esClient", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    esClient.get.mockResolvedValueOnce(dataEnvelope({ _source: {} }));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.getAlertDocument(".alerts-security.alerts-default", "a1");

    expect(esClient.get).toHaveBeenCalledWith(
      "/.alerts-security.alerts-default/_doc/a1"
    );
  });

  it("mgetAlerts POSTs an `ids` body to the alerts _mget endpoint", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    esClient.post.mockResolvedValueOnce(dataEnvelope({ docs: [] }));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.mgetAlerts(["a", "b"]);

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-default/_mget",
      { ids: ["a", "b"] }
    );
  });

  it("mgetAlerts substitutes the namespace into the alerts index name", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    esClient.post.mockResolvedValueOnce(dataEnvelope({ docs: [] }));

    const client = new CasesClient({ esClient, kibanaClient });
    await client.mgetAlerts(["a"], "soc");

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-soc/_mget",
      { ids: ["a"] }
    );
  });
});
