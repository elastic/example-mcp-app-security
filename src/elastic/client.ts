import type { ElasticConfig } from "../shared/types.js";

let _config: ElasticConfig | null = null;

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

  const res = await fetch(url.toString(), {
    method: options.method || (options.body ? "POST" : "GET"),
    headers: {
      Authorization: `ApiKey ${config.elasticsearchApiKey}`,
      "Content-Type": "application/json",
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
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
  const url = new URL(path, config.kibanaUrl);
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
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Kibana ${res.status}: ${text}`);
  }

  return res.json() as Promise<T>;
}
