/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import axios, {
  type AxiosAdapter,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
  AxiosHeaders,
} from "axios";
import { vi } from "vitest";

type Method = "get" | "post" | "put" | "patch" | "delete";

/** What a route handler can return (or shape it can be defined as). */
export interface RouteResponse {
  readonly status?: number;
  readonly data?: unknown;
  readonly headers?: Record<string, string>;
}

export type RouteHandler = (
  config: InternalAxiosRequestConfig
) => RouteResponse | Promise<RouteResponse>;

interface Route {
  readonly method: Method;
  readonly url: string | RegExp;
  readonly handler: RouteHandler;
}

/**
 * In-memory axios mock — installs a custom adapter on every instance built
 * with `axios.create`. Routes are matched against the path passed to the
 * client (`config.url`); supply a `RegExp` when the path needs disambiguation
 * by host (e.g. Elasticsearch vs. Kibana).
 *
 * Usage:
 * ```ts
 * const mockAxios = new MockAxios();
 * const restore = mockAxios.install();
 * mockAxios.onPost("/.alerts-security.alerts-*\/_search", { data: {...} });
 * // ...run code under test...
 * restore();
 * ```
 */
export class MockAxios {
  private readonly routes: Route[] = [];
  private readonly requests: InternalAxiosRequestConfig[] = [];

  /** Register a handler. The first registered match wins per request. */
  on(
    method: Method,
    url: string | RegExp,
    response: RouteResponse | RouteHandler
  ): this {
    const handler: RouteHandler =
      typeof response === "function" ? response : () => response;
    this.routes.push({ method, url, handler });
    return this;
  }

  onGet(url: string | RegExp, response: RouteResponse | RouteHandler): this {
    return this.on("get", url, response);
  }

  onPost(url: string | RegExp, response: RouteResponse | RouteHandler): this {
    return this.on("post", url, response);
  }

  onPatch(url: string | RegExp, response: RouteResponse | RouteHandler): this {
    return this.on("patch", url, response);
  }

  onDelete(url: string | RegExp, response: RouteResponse | RouteHandler): this {
    return this.on("delete", url, response);
  }

  /** All requests intercepted since the last `reset()`. */
  history(): readonly InternalAxiosRequestConfig[] {
    return this.requests;
  }

  /** Clear registered routes and request history. */
  reset(): void {
    this.routes.length = 0;
    this.requests.length = 0;
  }

  /**
   * Patch `axios.create` so every instance is built with our adapter.
   * Returns a `restore()` callback that puts axios back to normal.
   */
  install(): () => void {
    const adapter = this.createAdapter();
    const originalCreate = axios.create.bind(axios);
    const spy = vi.spyOn(axios, "create").mockImplementation((config = {}) =>
      originalCreate({ ...config, adapter })
    );
    return () => spy.mockRestore();
  }

  private createAdapter(): AxiosAdapter {
    return async (config) => {
      this.requests.push(config);
      const url = config.url ?? "";
      const method = (config.method ?? "get").toLowerCase() as Method;
      const route = this.routes.find(
        (r) =>
          r.method === method &&
          (typeof r.url === "string" ? r.url === url : r.url.test(url))
      );
      if (!route) {
        throw new Error(
          `MockAxios: no handler for ${method.toUpperCase()} ${
            config.baseURL ?? ""
          }${url}\nRegistered routes:\n${this.routes
            .map((r) => `  - ${r.method.toUpperCase()} ${r.url}`)
            .join("\n")}`
        );
      }

      const result = await route.handler(config);
      const status = result.status ?? 200;
      const response: AxiosResponse = {
        data: result.data,
        status,
        statusText: status === 200 ? "OK" : `HTTP ${status}`,
        headers: new AxiosHeaders(result.headers),
        config,
        request: undefined,
      };
      if (status >= 400) {
        const err = new axios.AxiosError(
          `Request failed with status code ${status}`,
          String(status),
          config,
          undefined,
          response
        );
        return Promise.reject(err);
      }
      return response;
    };
  }
}
