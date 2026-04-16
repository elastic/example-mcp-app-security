/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticConfig } from "../shared/types.js";

let _config: ElasticConfig | null = null;

export function setConfig(config: ElasticConfig) {
  _config = {
    elasticsearchUrl: config.elasticsearchUrl.replace(/\/$/, ""),
    elasticsearchApiKey: config.elasticsearchApiKey,
    kibanaUrl: (config.kibanaUrl || config.elasticsearchUrl).replace(/\/$/, ""),
    kibanaApiKey: config.kibanaApiKey || config.elasticsearchApiKey,
  };
}

export function getConfig(): ElasticConfig {
  if (!_config) {
    const elasticsearchUrl = process.env.ELASTICSEARCH_URL;
    const elasticsearchApiKey = process.env.ELASTICSEARCH_API_KEY;
    const kibanaUrl = process.env.KIBANA_URL;
    const kibanaApiKey = process.env.KIBANA_API_KEY;

    if (!elasticsearchUrl || !elasticsearchApiKey) {
      throw new Error(
        "ELASTICSEARCH_URL and ELASTICSEARCH_API_KEY environment variables are required"
      );
    }

    _config = {
      elasticsearchUrl: elasticsearchUrl.replace(/\/$/, ""),
      elasticsearchApiKey,
      kibanaUrl: (kibanaUrl || elasticsearchUrl).replace(/\/$/, ""),
      kibanaApiKey: kibanaApiKey || elasticsearchApiKey,
    };
  }
  return _config;
}

export async function esRequest<T = unknown>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    params?: Record<string, string>;
  } = {}
): Promise<T> {
  const config = getConfig();
  const url = new URL(path, config.elasticsearchUrl);
  if (options.params) {
    for (const [k, v] of Object.entries(options.params)) {
      url.searchParams.set(k, v);
    }
  }

  const isRawBody = typeof options.body === "string";
  const contentType = isRawBody && path.includes("_bulk")
    ? "application/x-ndjson"
    : "application/json";

  const timeoutMs = path.includes("_bulk") ? 120_000 : 30_000;
  const res = await fetch(url.toString(), {
    method: options.method || (options.body ? "POST" : "GET"),
    headers: {
      Authorization: `ApiKey ${config.elasticsearchApiKey}`,
      "Content-Type": contentType,
    },
    body: options.body
      ? isRawBody ? (options.body as string) : JSON.stringify(options.body)
      : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Elasticsearch ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}

export async function kibanaRequest<T = unknown>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    params?: Record<string, string>;
    apiVersion?: string;
  } = {}
): Promise<T> {
  const config = getConfig();
  const url = new URL(config.kibanaUrl + path);
  if (options.params) {
    for (const [k, v] of Object.entries(options.params)) {
      url.searchParams.set(k, v);
    }
  }

  const headers: Record<string, string> = {
    Authorization: `ApiKey ${config.kibanaApiKey}`,
    "Content-Type": "application/json",
    "kbn-xsrf": "true",
    "x-elastic-internal-origin": "Kibana",
  };

  if (options.apiVersion) {
    headers["elastic-api-version"] = options.apiVersion;
  }

  const res = await fetch(url.toString(), {
    method: options.method || (options.body ? "POST" : "GET"),
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Kibana ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}
