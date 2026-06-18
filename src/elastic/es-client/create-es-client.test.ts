/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { AxiosError, type AxiosResponse } from "axios";
import { createEsClient } from "./create-es-client.js";
import type { ClusterCredentials } from "../credential-client/index.js";

const creds: ClusterCredentials = {
  name: "primary",
  elasticsearchUrl: "https://es.example.com",
  kibanaUrl: "https://kb.example.com",
  elasticsearchApiKey: "secret-key",
  sslVerify: true,
};

/**
 * Pull the response interceptor's `rejected` handler so we can drive the
 * error-transform path without making a real HTTP request.
 */
function getRejectedHandler(client: ReturnType<typeof createEsClient>) {
  const handlers = (
    client.interceptors.response as unknown as {
      handlers: { rejected?: (err: unknown) => unknown }[];
    }
  ).handlers;
  const handler = handlers[handlers.length - 1].rejected;
  if (!handler) throw new Error("expected a rejected handler");
  return handler;
}

describe("createEsClient", () => {
  describe("axios configuration", () => {
    it("sets baseURL, timeout, and the standard auth/content-type headers", () => {
      const client = createEsClient(creds);

      expect(client.defaults.baseURL).toBe("https://es.example.com");
      expect(client.defaults.timeout).toBe(30_000);
      expect(client.defaults.headers["User-Agent"]).toBe(
        "elastic-security-mcp-app"
      );
      expect(client.defaults.headers["Authorization"]).toBe(
        "ApiKey secret-key"
      );
      expect(client.defaults.headers["Content-Type"]).toBe(
        "application/json"
      );
    });

    it("attaches the cluster name to the returned client", () => {
      const client = createEsClient(creds);
      expect(client.clusterName).toBe("primary");
    });
  });

  describe("response success interceptor", () => {
    it("passes successful responses through unchanged", () => {
      const client = createEsClient(creds);
      const handlers = (
        client.interceptors.response as unknown as {
          handlers: { fulfilled?: (r: unknown) => unknown }[];
        }
      ).handlers;
      const fulfilled = handlers[handlers.length - 1].fulfilled;
      if (!fulfilled) throw new Error("expected a fulfilled handler");

      const response = { status: 200, data: { ok: true } };
      expect(fulfilled(response)).toBe(response);
    });
  });

  describe("response error interceptor", () => {
    it("rewrites Axios HTTP errors with the cluster name and the response status / body", async () => {
      const client = createEsClient(creds);
      const reject = getRejectedHandler(client);

      const response = {
        status: 502,
        data: "bad gateway",
      } as unknown as AxiosResponse;
      const axiosError = new AxiosError("Bad Gateway");
      axiosError.response = response;

      await expect(reject(axiosError) as Promise<unknown>).rejects.toThrow(
        /Elasticsearch \[primary\] 502: bad gateway/
      );
    });

    it("serialises non-string response bodies as JSON", async () => {
      const client = createEsClient(creds);
      const reject = getRejectedHandler(client);

      const axiosError = new AxiosError("Bad Request");
      axiosError.response = {
        status: 400,
        data: { error: { type: "illegal_argument_exception" } },
      } as unknown as AxiosResponse;

      await expect(reject(axiosError) as Promise<unknown>).rejects.toThrow(
        /Elasticsearch \[primary\] 400: \{"error":\{"type":"illegal_argument_exception"\}\}/
      );
    });

    it("uses 'network' as the status placeholder when there is no response", async () => {
      const client = createEsClient(creds);
      const reject = getRejectedHandler(client);

      const axiosError = new AxiosError("getaddrinfo ENOTFOUND es.example.com");

      await expect(reject(axiosError) as Promise<unknown>).rejects.toThrow(
        /Elasticsearch \[primary\] network: .+ENOTFOUND/
      );
    });

    it("forwards non-Axios rejections unchanged", async () => {
      const client = createEsClient(creds);
      const reject = getRejectedHandler(client);

      const original = new Error("not from axios");
      await expect(reject(original) as Promise<unknown>).rejects.toBe(original);
    });
  });
});
