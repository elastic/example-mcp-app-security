/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsqlResult } from "../../shared/types.js";
import type { EsClient } from "../es-client/index.js";

/** How long the submit call waits before returning a query id. */
export const ESQL_ASYNC_SUBMIT_WAIT = "5s";

/** How long each poll waits for the query to finish. */
export const ESQL_ASYNC_POLL_WAIT = "10s";

const POLL_WAIT_MS = 10_000;

/** Axios timeout per submit/poll request. Must exceed {@link ESQL_ASYNC_POLL_WAIT}. */
export const ESQL_ASYNC_HTTP_TIMEOUT_MS = 20_000;

/** Give up (and cancel) if the query is still running after this long. */
export const ESQL_ASYNC_MAX_WAIT_MS = 300_000;

export const ESQL_ASYNC_MAX_POLLS = Math.ceil(ESQL_ASYNC_MAX_WAIT_MS / POLL_WAIT_MS);

/** ES `keep_alive`, derived from {@link ESQL_ASYNC_MAX_WAIT_MS} so the two cannot drift. */
export const ESQL_ASYNC_KEEP_ALIVE = `${Math.ceil(ESQL_ASYNC_MAX_WAIT_MS / 60_000)}m`;

interface EsqlClientOptions {
  readonly esClient: EsClient;
}

interface EsqlAsyncResponse {
  readonly id?: string;
  readonly is_running?: boolean;
  readonly columns?: EsqlResult["columns"];
  readonly values?: EsqlResult["values"];
}

function completedResult(response: EsqlAsyncResponse): EsqlResult | undefined {
  if (response.is_running === true) return undefined;
  if (!response.columns || !response.values) return undefined;
  return { columns: response.columns, values: response.values };
}

function asyncQueryPath(id: string): string {
  return `/_query/async/${encodeURIComponent(id)}`;
}

/**
 * Typed transport for Elasticsearch ES|QL.
 *
 * Bound to a single cluster via the injected {@link EsClient}. Submits via
 * `POST /_query/async` and polls `GET /_query/async/{id}` so frozen-tier and
 * other long-running queries can complete past the default 30s HTTP timeout.
 * Query construction is the caller's responsibility; this client is transport.
 */
export class EsqlClient {
  constructor(private readonly options: EsqlClientOptions) {}

  /** Submit `query` on `/_query/async` and poll until it finishes. */
  async executeEsql(query: string): Promise<EsqlResult> {
    const { data } = await this.options.esClient.post<EsqlAsyncResponse>(
      "/_query/async",
      {
        query,
        wait_for_completion_timeout: ESQL_ASYNC_SUBMIT_WAIT,
        keep_alive: ESQL_ASYNC_KEEP_ALIVE,
      },
      {
        params: { format: "json" },
        timeout: ESQL_ASYNC_HTTP_TIMEOUT_MS,
      }
    );

    const immediate = completedResult(data);
    if (immediate) return immediate;

    const id = data.id;
    if (!id) {
      throw new Error("ES|QL async query is still running but Elasticsearch did not return an id");
    }

    try {
      for (let i = 0; i < ESQL_ASYNC_MAX_POLLS; i++) {
        const { data: poll } = await this.options.esClient.get<EsqlAsyncResponse>(
          asyncQueryPath(id),
          {
            params: {
              format: "json",
              wait_for_completion_timeout: ESQL_ASYNC_POLL_WAIT,
              keep_alive: ESQL_ASYNC_KEEP_ALIVE,
            },
            timeout: ESQL_ASYNC_HTTP_TIMEOUT_MS,
          }
        );
        const done = completedResult(poll);
        if (done) return done;
      }
    } catch (err) {
      await this.deleteAsyncQuery(id);
      throw err;
    }

    await this.deleteAsyncQuery(id);
    throw new Error(
      `ES|QL query did not complete within ${ESQL_ASYNC_MAX_WAIT_MS / 1000}s. Async query id: ${id}`
    );
  }

  private async deleteAsyncQuery(id: string): Promise<void> {
    try {
      await this.options.esClient.delete(asyncQueryPath(id));
    } catch {
      // Query may already have expired or completed.
    }
  }
}
