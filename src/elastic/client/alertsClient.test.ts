/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { AlertsClient } from "./alertsClient.js";
import {
  createMockEsClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";

const DEFAULT_ALERTS_PATH = "/.alerts-security.alerts-default/_search";

describe("AlertsClient", () => {
  it("searchAlerts POSTs to the default namespace's alerts index when no namespace is given", async () => {
    const esClient = createMockEsClient();
    const response = {
      hits: { total: { value: 0 }, hits: [] },
    };
    esClient.post.mockResolvedValueOnce(dataEnvelope(response));

    const client = new AlertsClient({ esClient });
    const body = { query: { match_all: {} } };
    const out = await client.searchAlerts(body);

    expect(esClient.post).toHaveBeenCalledWith(DEFAULT_ALERTS_PATH, body);
    expect(out).toEqual(response);
  });

  it("searchAlerts substitutes the namespace into the alerts index name", async () => {
    const esClient = createMockEsClient();
    esClient.post.mockResolvedValueOnce(
      dataEnvelope({ hits: { total: { value: 0 }, hits: [] } })
    );
    const client = new AlertsClient({ esClient });

    await client.searchAlerts({ query: { match_all: {} } }, "soc");

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-soc/_search",
      { query: { match_all: {} } }
    );
  });

  it("searchProcessEvents POSTs to the endpoint process events index", async () => {
    const esClient = createMockEsClient();
    esClient.post.mockResolvedValueOnce(
      dataEnvelope({ hits: { total: { value: 0 }, hits: [] } })
    );
    const client = new AlertsClient({ esClient });

    await client.searchProcessEvents({ size: 10 });

    expect(esClient.post).toHaveBeenCalledWith(
      "/logs-endpoint.events.process-*/_search",
      { size: 10 }
    );
  });

  it("searchNetworkEvents POSTs to the endpoint network events index", async () => {
    const esClient = createMockEsClient();
    esClient.post.mockResolvedValueOnce(
      dataEnvelope({ hits: { total: { value: 0 }, hits: [] } })
    );
    const client = new AlertsClient({ esClient });

    await client.searchNetworkEvents({ size: 5 });

    expect(esClient.post).toHaveBeenCalledWith(
      "/logs-endpoint.events.network-*/_search",
      { size: 5 }
    );
  });

  describe("updateAlert", () => {
    it("wraps the partial doc in a `{ doc }` envelope and POSTs to /_update/{id}", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(dataEnvelope(undefined));

      const client = new AlertsClient({ esClient });
      await client.updateAlert("abc-123", {
        "kibana.alert.workflow_status": "acknowledged",
      });

      expect(esClient.post).toHaveBeenCalledWith(
        "/.alerts-security.alerts-default/_update/abc-123",
        { doc: { "kibana.alert.workflow_status": "acknowledged" } }
      );
    });

    it("substitutes the namespace into the alerts index name", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(dataEnvelope(undefined));

      const client = new AlertsClient({ esClient });
      await client.updateAlert("abc-123", { foo: 1 }, "soc");

      expect(esClient.post).toHaveBeenCalledWith(
        "/.alerts-security.alerts-soc/_update/abc-123",
        { doc: { foo: 1 } }
      );
    });

    it("resolves to void on success", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(dataEnvelope({ result: "updated" }));

      const client = new AlertsClient({ esClient });
      await expect(
        client.updateAlert("id", { foo: 1 })
      ).resolves.toBeUndefined();
    });
  });

  it("updateAlertsByQuery POSTs to /_update_by_query with the supplied body", async () => {
    const esClient = createMockEsClient();
    esClient.post.mockResolvedValueOnce(dataEnvelope({ updated: 7 }));

    const client = new AlertsClient({ esClient });
    const body = { query: { ids: { values: ["a", "b"] } } };
    const out = await client.updateAlertsByQuery(body);

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-default/_update_by_query",
      body
    );
    expect(out).toEqual({ updated: 7 });
  });

  it("updateAlertsByQuery substitutes the namespace into the alerts index name", async () => {
    const esClient = createMockEsClient();
    esClient.post.mockResolvedValueOnce(dataEnvelope({ updated: 1 }));

    const client = new AlertsClient({ esClient });
    await client.updateAlertsByQuery({ query: { match_all: {} } }, "soc");

    expect(esClient.post).toHaveBeenCalledWith(
      "/.alerts-security.alerts-soc/_update_by_query",
      { query: { match_all: {} } }
    );
  });
});
