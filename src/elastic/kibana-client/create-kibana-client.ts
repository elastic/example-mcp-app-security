/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import axios, { AxiosError } from "axios";
import type { ClusterCredentials } from "../credential-client/index.js";
import { createHttpsAgent } from "../shared/https-agent.js";
import type { KibanaClient } from "./kibana-client.js";

const USER_AGENT = "elastic-security-mcp-app";
const DEFAULT_TIMEOUT_MS = 30_000;

function describeError(err: AxiosError, clusterName: string): Error {
  const status = err.response?.status ?? "network";
  const body = err.response?.data;
  const detail =
    typeof body === "string" ? body : JSON.stringify(body ?? err.message ?? {});
  return new Error(`Kibana [${clusterName}] ${status}: ${detail}`);
}

/**
 * Build a {@link KibanaClient} bound to the given cluster.
 *
 * Returns a pre-configured Axios instance — callers use the standard Axios
 * API (`get`, `post`, `put`, `delete`, `request`, …) directly. The required
 * Kibana headers (`kbn-xsrf`, `x-elastic-internal-origin`) are set as
 * defaults; per-call `headers` overrides handle endpoint-specific concerns
 * such as `elastic-api-version`.
 */
export function createKibanaClient(creds: ClusterCredentials): KibanaClient {
  const instance = axios.create({
    baseURL: creds.kibanaUrl,
    timeout: DEFAULT_TIMEOUT_MS,
    httpsAgent: createHttpsAgent(creds),
    headers: {
      "User-Agent": USER_AGENT,
      Authorization: `ApiKey ${creds.elasticsearchApiKey}`,
      "Content-Type": "application/json",
      "kbn-xsrf": "true",
      "x-elastic-internal-origin": "Kibana",
    },
  });

  instance.interceptors.response.use(
    (response) => response,
    (err: unknown) => {
      if (err instanceof AxiosError) {
        return Promise.reject(describeError(err, creds.name));
      }
      return Promise.reject(err);
    }
  );

  return Object.assign(instance, { clusterName: creds.name });
}
