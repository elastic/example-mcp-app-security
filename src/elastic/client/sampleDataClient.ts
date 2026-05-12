/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsClient } from "../es-client/index.js";

/** Per-call timeout for `_bulk` requests — bulk indexing is slow. */
const BULK_TIMEOUT_MS = 120_000;

/** Opaque body — shaped by the service. */
export type EsRequestBody = Record<string, unknown>;

/** Single item envelope returned by `_bulk` for each emitted operation. */
export interface BulkItemEnvelope {
  readonly create: {
    readonly _index: string;
    readonly status: number;
    readonly error?: unknown;
  };
}

/** Response returned by `POST /_bulk`. */
export interface BulkResponse {
  readonly items: BulkItemEnvelope[];
  readonly errors: boolean;
}

/** Response returned by `POST /<index>/_delete_by_query`. */
export interface DeleteByQueryResponse {
  readonly deleted?: number;
}

/** Response returned by `POST /<index>/_count`. */
export interface CountResponse {
  readonly count: number;
}

/**
 * Bucket shape returned by the alert-by-rule aggregation in
 * {@link SampleDataService.checkExistingData}.
 */
export interface AlertsByRuleBucket {
  readonly key: string;
  readonly doc_count: number;
}

/** Typed envelope for the alert search used by `checkExistingData`. */
export interface AlertCheckResponse {
  readonly hits: { readonly total: { readonly value: number } };
  readonly aggregations: {
    readonly by_rule: { readonly buckets: AlertsByRuleBucket[] };
  };
}

interface SampleDataClientOptions {
  readonly esClient: EsClient;
}

/**
 * Typed transport for the Elasticsearch endpoints used to seed and clean
 * up the sample-data scenarios.
 *
 * Bound to a single cluster via the injected {@link EsClient}. Bulk
 * indexing uses an extended timeout (120s); the other endpoints use the
 * client default.
 */
export class SampleDataClient {
  constructor(private readonly options: SampleDataClientOptions) {}

  /**
   * POST `/_bulk`.
   *
   * The body must be pre-serialised to NDJSON (one JSON document per line,
   * terminated by `\n`); the legacy implementation builds it line-by-line
   * to match Elasticsearch's exact NDJSON requirements.
   */
  async bulkIndex(ndjson: string): Promise<BulkResponse> {
    const { data } = await this.options.esClient.post<BulkResponse>(
      "/_bulk",
      ndjson,
      {
        headers: { "Content-Type": "application/x-ndjson" },
        timeout: BULK_TIMEOUT_MS,
        transformRequest: [(d: unknown) => d as string],
      }
    );
    return data;
  }

  /** POST `/{index}/_delete_by_query`. */
  async deleteByQuery(
    index: string,
    body: EsRequestBody
  ): Promise<DeleteByQueryResponse> {
    const { data } = await this.options.esClient.post<DeleteByQueryResponse>(
      `/${index}/_delete_by_query`,
      body
    );
    return data;
  }

  /** POST `/{index}/_count`. */
  async count(index: string, body: EsRequestBody): Promise<CountResponse> {
    const { data } = await this.options.esClient.post<CountResponse>(
      `/${index}/_count`,
      body
    );
    return data;
  }

  /**
   * POST `/.alerts-security.alerts-*\/_search` — used by `checkExistingData`
   * to count tag-matching alerts and bucket them by rule name.
   */
  async searchAlertsAggregation(
    body: EsRequestBody
  ): Promise<AlertCheckResponse> {
    const { data } = await this.options.esClient.post<AlertCheckResponse>(
      "/.alerts-security.alerts-*/_search",
      body
    );
    return data;
  }
}
