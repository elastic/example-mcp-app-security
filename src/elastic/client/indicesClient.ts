/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FieldMapping } from "../../shared/types.js";
import type { EsClient } from "../es-client/index.js";

/** A single row returned by `_cat/indices?format=json`. */
export interface CatIndicesRow {
  readonly index: string;
  readonly health: string;
  readonly status: string;
  readonly "docs.count": string;
  readonly "store.size": string;
}

/** Raw `_mapping` envelope keyed by concrete index name. */
export type RawMappingResponse = Record<
  string,
  { mappings: { properties: FieldMapping } }
>;

interface IndicesClientOptions {
  readonly esClient: EsClient;
}

/**
 * Typed transport for the Elasticsearch `_cat/indices` and `_mapping`
 * endpoints used by index discovery.
 *
 * Bound to a single cluster via the injected {@link EsClient}. Each method
 * maps 1:1 to an ES API call and unwraps `axios .data`. Pattern resolution
 * and mapping-tree flattening live in {@link IndicesService}.
 */
export class IndicesClient {
  constructor(private readonly options: IndicesClientOptions) {}

  /** GET `/_cat/indices/{target}` with caller-supplied query params. */
  async catIndices(
    target: string,
    params: Record<string, string>
  ): Promise<CatIndicesRow[]> {
    const { data } = await this.options.esClient.get<CatIndicesRow[]>(
      `/_cat/indices/${target}`,
      { params }
    );
    return data;
  }

  /** GET `/{index}/_mapping`. */
  async getRawMapping(index: string): Promise<RawMappingResponse> {
    const { data } = await this.options.esClient.get<RawMappingResponse>(
      `/${index}/_mapping`
    );
    return data;
  }
}
