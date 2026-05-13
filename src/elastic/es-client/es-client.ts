/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AxiosInstance } from "axios";

/**
 * HTTP client for a single Elasticsearch cluster.
 *
 * Implemented as a pre-configured Axios instance with:
 *   - `baseURL` set to the cluster's Elasticsearch URL
 *   - `Authorization: ApiKey ...` header derived from the cluster's API key
 *   - default `Content-Type: application/json`
 *     (override per-call to `application/x-ndjson` for `_bulk` requests)
 *   - default 30s timeout
 *     (override per-call for long-running operations such as `_bulk`)
 *   - response interceptor that rewrites errors to include {@link clusterName}
 *
 * The cluster identity is bound to the instance — there is intentionally no
 * way to retarget a different cluster through this client. Acquire a
 * different cluster's client via the factory.
 */
export type EsClient = AxiosInstance & {
  /** The cluster this client is bound to. */
  readonly clusterName: string;
};
