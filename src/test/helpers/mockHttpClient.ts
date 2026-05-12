/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { vi, type Mock } from "vitest";
import type { EsClient } from "../../elastic/es-client/es-client.js";
import type { KibanaClient } from "../../elastic/kibana-client/kibana-client.js";

/**
 * Minimal axios-shaped HTTP surface our clients actually use. We mock only
 * the verb methods (`get` / `post` / `patch` / `delete`) — the rest of the
 * `AxiosInstance` API is intentionally not faked.
 */
export interface MockHttpClient {
  get: Mock;
  post: Mock;
  patch: Mock;
  delete: Mock;
  clusterName: string;
}

/**
 * Build a fresh mock `EsClient` for a single test. Every verb method is a
 * `vi.fn()` resolving with `{ data: undefined }` by default — override via
 * `mockResolvedValueOnce({ data: ... })` or `mockRejectedValueOnce(err)`.
 */
export function createMockEsClient(
  clusterName = "test-cluster"
): EsClient & MockHttpClient {
  return makeMock(clusterName) as EsClient & MockHttpClient;
}

/**
 * Build a fresh mock `KibanaClient` for a single test. Same shape as
 * {@link createMockEsClient} — separate factory only for type clarity at
 * call sites.
 */
export function createMockKibanaClient(
  clusterName = "test-cluster"
): KibanaClient & MockHttpClient {
  return makeMock(clusterName) as KibanaClient & MockHttpClient;
}

function makeMock(clusterName: string): MockHttpClient {
  return {
    get: vi.fn().mockResolvedValue({ data: undefined }),
    post: vi.fn().mockResolvedValue({ data: undefined }),
    patch: vi.fn().mockResolvedValue({ data: undefined }),
    delete: vi.fn().mockResolvedValue({ data: undefined }),
    clusterName,
  };
}

/** Tiny convenience for the common `{ data }` axios envelope. */
export function dataEnvelope<T>(data: T): { data: T } {
  return { data };
}
