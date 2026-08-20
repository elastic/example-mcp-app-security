/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import {
  EsqlClient,
  ESQL_ASYNC_HTTP_TIMEOUT_MS,
  ESQL_ASYNC_MAX_POLLS,
  ESQL_ASYNC_MAX_WAIT_MS,
  ESQL_ASYNC_KEEP_ALIVE,
  ESQL_ASYNC_POLL_WAIT,
  ESQL_ASYNC_SUBMIT_WAIT,
} from "./esqlClient.js";
import {
  createMockEsClient,
  dataEnvelope,
} from "../../test/helpers/mockHttpClient.js";
import type { EsqlResult } from "../../shared/types.js";

const QUERY = "FROM logs-* | LIMIT 1";
const RESULT: EsqlResult = { columns: [{ name: "x", type: "long" }], values: [[1]] };

describe("EsqlClient", () => {
  describe("executeEsql", () => {
    it("POSTs to /_query/async with wait_for_completion_timeout and format=json", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(dataEnvelope(RESULT));

      const client = new EsqlClient({ esClient });
      await client.executeEsql(QUERY);

      expect(esClient.post).toHaveBeenCalledWith(
        "/_query/async",
        {
          query: QUERY,
          wait_for_completion_timeout: ESQL_ASYNC_SUBMIT_WAIT,
          keep_alive: ESQL_ASYNC_KEEP_ALIVE,
        },
        {
          params: { format: "json" },
          timeout: ESQL_ASYNC_HTTP_TIMEOUT_MS,
        }
      );
    });

    it("returns results when the async query completes on submit", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(
        dataEnvelope({ ...RESULT, is_running: false })
      );

      const client = new EsqlClient({ esClient });
      const out = await client.executeEsql(QUERY);

      expect(out).toEqual(RESULT);
    });

    it("does not poll when submit already returned columns and values", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(dataEnvelope(RESULT));

      const client = new EsqlClient({ esClient });
      await client.executeEsql(QUERY);

      expect(esClient.get).not.toHaveBeenCalled();
    });

    it("polls GET /_query/async/{id} until the query completes", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(
        dataEnvelope({ id: "abc+", is_running: true })
      );
      esClient.get
        .mockResolvedValueOnce(dataEnvelope({ id: "abc+", is_running: true }))
        .mockResolvedValueOnce(dataEnvelope({ ...RESULT, is_running: false }));

      const client = new EsqlClient({ esClient });
      const out = await client.executeEsql(QUERY);

      expect(out).toEqual(RESULT);
    });

    it("encodes the async query id in the poll path", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(
        dataEnvelope({ id: "abc+", is_running: true })
      );
      esClient.get.mockResolvedValueOnce(
        dataEnvelope({ ...RESULT, is_running: false })
      );

      const client = new EsqlClient({ esClient });
      await client.executeEsql(QUERY);

      expect(esClient.get).toHaveBeenCalledWith(
        "/_query/async/abc%2B",
        {
          params: {
            format: "json",
            wait_for_completion_timeout: ESQL_ASYNC_POLL_WAIT,
            keep_alive: ESQL_ASYNC_KEEP_ALIVE,
          },
          timeout: ESQL_ASYNC_HTTP_TIMEOUT_MS,
        }
      );
    });

    it("throws when a running query has no id", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(dataEnvelope({ is_running: true }));

      const client = new EsqlClient({ esClient });

      await expect(client.executeEsql(QUERY)).rejects.toThrow(
        "did not return an id"
      );
    });

    it("deletes the async query and throws when polling does not finish in time", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(
        dataEnvelope({ id: "slow-1", is_running: true })
      );
      esClient.get.mockResolvedValue(
        dataEnvelope({ id: "slow-1", is_running: true })
      );

      const client = new EsqlClient({ esClient });

      await expect(client.executeEsql(QUERY)).rejects.toThrow(
        `did not complete within ${ESQL_ASYNC_MAX_WAIT_MS / 1000}s`
      );
      expect(esClient.get).toHaveBeenCalledTimes(ESQL_ASYNC_MAX_POLLS);
      expect(esClient.delete).toHaveBeenCalledWith("/_query/async/slow-1");
    });

    it("deletes the async query when a poll request fails", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(
        dataEnvelope({ id: "fail-1", is_running: true })
      );
      esClient.get.mockRejectedValueOnce(new Error("poll failed"));

      const client = new EsqlClient({ esClient });

      await expect(client.executeEsql(QUERY)).rejects.toThrow("poll failed");
      expect(esClient.delete).toHaveBeenCalledWith("/_query/async/fail-1");
    });

    it("still throws the timeout error when delete fails", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockResolvedValueOnce(
        dataEnvelope({ id: "gone-1", is_running: true })
      );
      esClient.get.mockResolvedValue(
        dataEnvelope({ id: "gone-1", is_running: true })
      );
      esClient.delete.mockRejectedValueOnce(new Error("already gone"));

      const client = new EsqlClient({ esClient });

      await expect(client.executeEsql(QUERY)).rejects.toThrow(
        `did not complete within ${ESQL_ASYNC_MAX_WAIT_MS / 1000}s`
      );
    });

    it("propagates transport errors from submit", async () => {
      const esClient = createMockEsClient();
      esClient.post.mockRejectedValueOnce(new Error("boom"));

      const client = new EsqlClient({ esClient });

      await expect(client.executeEsql("FROM x")).rejects.toThrow("boom");
    });
  });
});
