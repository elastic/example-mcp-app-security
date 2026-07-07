/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { AttackDiscoveryClient } from "./attackDiscoveryClient.js";
import {
  createMockEsClient,
  createMockKibanaClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

const KIBANA_HEADERS = { "elastic-api-version": "2023-10-31" };

describe("AttackDiscoveryClient", () => {
  it("runEsql POSTs to /_query with format=json", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    const result = { columns: [{ name: "x", type: "text" }], values: [["v"]] };
    esClient.post.mockResolvedValueOnce(dataEnvelope(result));

    const client = new AttackDiscoveryClient({ esClient, kibanaClient });
    const out = await client.runEsql("FROM .alerts-*");

    expect(esClient.post).toHaveBeenCalledWith(
      "/_query",
      { query: "FROM .alerts-*" },
      { params: { format: "json" } }
    );
    expect(out).toEqual(result);
  });

  it("acknowledgeOnIndex POSTs the body to /{index}/_update_by_query", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    esClient.post.mockResolvedValueOnce(dataEnvelope({ updated: 3 }));

    const client = new AttackDiscoveryClient({ esClient, kibanaClient });
    await client.acknowledgeOnIndex(".some-index", { query: { ids: { values: [] } } });

    expect(esClient.post).toHaveBeenCalledWith(
      "/.some-index/_update_by_query",
      { query: { ids: { values: [] } } }
    );
  });

  it("generate POSTs to the Kibana attack_discovery generate endpoint", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.post.mockResolvedValueOnce(
      dataEnvelope({ execution_uuid: "exec-1" })
    );

    const client = new AttackDiscoveryClient({ esClient, kibanaClient });
    const out = await client.generate({ size: 10 });

    expect(kibanaClient.post).toHaveBeenCalledWith(
      "/api/attack_discovery/_generate",
      { size: 10 },
      { headers: KIBANA_HEADERS }
    );
    expect(out).toEqual({ execution_uuid: "exec-1" });
  });

  it("listConnectors GETs /api/actions/connectors", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope([]));

    const client = new AttackDiscoveryClient({ esClient, kibanaClient });
    await client.listConnectors();

    expect(kibanaClient.get).toHaveBeenCalledWith(
      "/api/actions/connectors",
      { headers: KIBANA_HEADERS }
    );
  });

  it("findAnonymizationFields GETs the anonymization fields _find endpoint with per_page=1000", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ data: [] }));

    const client = new AttackDiscoveryClient({ esClient, kibanaClient });
    await client.findAnonymizationFields();

    // The route's query schema only accepts snake_case `per_page` (Zod
    // silently drops unrecognized keys like `perPage` and defaults to 20),
    // so this must be snake_case or the field list gets truncated.
    expect(kibanaClient.get).toHaveBeenCalledWith(
      "/api/security_ai_assistant/anonymization_fields/_find",
      { params: { per_page: "1000" }, headers: KIBANA_HEADERS }
    );
  });

  it("getGenerations GETs the generations endpoint with the supplied params", async () => {
    const esClient = createMockEsClient();
    const kibanaClient = createMockKibanaClient();
    kibanaClient.get.mockResolvedValueOnce(dataEnvelope({ generations: [] }));

    const client = new AttackDiscoveryClient({ esClient, kibanaClient });
    await client.getGenerations({ size: "5" });

    expect(kibanaClient.get).toHaveBeenCalledWith(
      "/api/attack_discovery/generations",
      { params: { size: "5" }, headers: KIBANA_HEADERS }
    );
  });
});
