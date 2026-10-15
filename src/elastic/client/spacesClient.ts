/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { SpaceSummary } from "../../shared/spaces.js";
import type { EsClient } from "../es-client/index.js";
import type { KibanaClient } from "../kibana-client/index.js";
import { pathSegment } from "../shared/path-segment.js";
import type { EsRequestBody, TermBucket } from "./alertsClient.js";

const KIBANA_API_VERSION = "2023-10-31";

const KIBANA_HEADERS = {
  "elastic-api-version": KIBANA_API_VERSION,
} as const;

/** Raw space record from `GET /api/spaces/space`. */
interface RawSpace {
  readonly id: string;
  readonly name: string;
  readonly color?: string;
  readonly initials?: string;
}

/** Typed shape of the per-space count `_search` response. */
export interface SpaceCountsAggResponse {
  readonly aggregations?: {
    readonly by_space?: { readonly buckets: TermBucket[] };
  };
}

interface SpacesClientOptions {
  readonly esClient: EsClient;
  readonly kibanaClient: KibanaClient;
}

/**
 * Typed transport for Kibana space discovery and cross-space counts.
 *
 * Bound to a single cluster via the injected {@link EsClient} and
 * {@link KibanaClient}.
 */
export class SpacesClient {
  constructor(private readonly options: SpacesClientOptions) {}

  /** GET `/api/spaces/space` on `kibanaClient`: the spaces the API key can access. */
  async listSpaces(): Promise<SpaceSummary[]> {
    const { data } = await this.options.kibanaClient.get<RawSpace[]>(
      "/api/spaces/space",
      { headers: KIBANA_HEADERS }
    );
    return data.map(({ id, name, color, initials }) => ({
      id,
      name,
      color,
      initials,
    }));
  }

  /**
   * POST `/{indexPattern}/_search` on `esClient`. The body must aggregate
   * into `by_space`; missing indices count as zero rather than failing.
   */
  async countBySpace(
    indexPattern: string,
    body: EsRequestBody
  ): Promise<SpaceCountsAggResponse> {
    const { data } = await this.options.esClient.post<SpaceCountsAggResponse>(
      `/${indexPattern.split(",").map(pathSegment).join(",")}/_search`,
      body,
      { params: { ignore_unavailable: "true", allow_no_indices: "true" } }
    );
    return data;
  }
}
