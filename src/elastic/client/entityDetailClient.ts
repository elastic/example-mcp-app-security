/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsClient } from "../es-client/index.js";

/** Domain type for an entity-detail card surfaced in views and tools. */
export interface EntityDetail {
  type: string;
  value: string;
  fields: { label: string; value: string; mono?: boolean }[];
  events?: { timestamp: string; action: string; detail: string }[];
}

/** Opaque ES `_search` body — shaped by the service. */
export type EsRequestBody = Record<string, unknown>;

/** Generic `_search` envelope, parametric on the hit document shape. */
export interface SearchResponse<H> {
  readonly hits: { readonly hits: H[] };
}

interface EntityDetailClientOptions {
  readonly esClient: EsClient;
}

/**
 * Typed transport for the searches that back entity-detail lookups.
 *
 * Exposes a single generic `searchByTerms` method (`POST /<index>/_search`).
 * The service is responsible for crafting the request body — this client
 * stays purely a transport.
 */
export class EntityDetailClient {
  constructor(private readonly options: EntityDetailClientOptions) {}

  /**
   * POST `/{index}/_search`.
   *
   * The hit document type `H` is supplied by the caller so callers can
   * narrow `_source` (or other hit fields) to the shape they need without
   * forcing the client to know about every possible search.
   */
  async searchByTerms<H>(
    index: string,
    body: EsRequestBody
  ): Promise<SearchResponse<H>> {
    const { data } = await this.options.esClient.post<SearchResponse<H>>(
      `/${index}/_search`,
      body
    );
    return data;
  }
}
