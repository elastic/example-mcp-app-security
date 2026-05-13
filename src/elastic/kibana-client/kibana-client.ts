/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AxiosInstance } from "axios";

/**
 * HTTP client for a single Kibana instance.
 *
 * Implemented as a pre-configured Axios instance with:
 *   - `baseURL` set to the cluster's Kibana URL
 *   - `Authorization: ApiKey ...` header derived from the cluster's API key
 *   - default `Content-Type: application/json`
 *   - `kbn-xsrf: true` and `x-elastic-internal-origin: Kibana` headers
 *   - default 30s timeout
 *   - response interceptor that rewrites errors to include {@link clusterName}
 *
 * Per-call header overrides are used for things like `elastic-api-version`.
 * The cluster identity is bound to the instance — acquire a different
 * cluster's client via the factory.
 */
export type KibanaClient = AxiosInstance & {
  /** The cluster this client is bound to. */
  readonly clusterName: string;
};
