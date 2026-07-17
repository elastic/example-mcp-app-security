/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsqlResult } from "../../shared/types.js";
import type { EsClient } from "../es-client/index.js";
import type { KibanaClient } from "../kibana-client/index.js";

const FLEET_HEADERS = { "elastic-api-version": "2023-10-31" } as const;

/** One entry from `GET /_data_stream`. */
export interface RawDataStream {
  readonly name: string;
  readonly template?: string;
  readonly _meta?: {
    readonly managed_by?: string;
    readonly description?: string;
    readonly package?: { readonly name?: string };
  };
  readonly ilm_policy?: string;
}

/** One entry from `GET /_data_stream/_stats`. */
export interface RawDataStreamStat {
  readonly data_stream: string;
  readonly backing_indices: number;
  readonly store_size_bytes: number;
  readonly maximum_timestamp: number;
}

/** One row from `GET /_cat/indices?format=json&h=index,docs.count`. */
export interface CatDocCountRow {
  readonly index: string;
  readonly "docs.count": string;
}

/** One row from `GET /_cat/indices?format=json&h=index,docs.count,store.size&bytes=b`. */
export interface CatIndexRow {
  readonly index: string;
  readonly "docs.count": string;
  readonly "store.size": string;
}

/** One entry from `GET /api/fleet/epm/packages/installed`. */
export interface InstalledPackage {
  readonly name: string;
  readonly version?: string;
}

/** A Fleet package policy (endpoint or otherwise). Shape is intentionally loose. */
export interface RawPackagePolicy {
  readonly id: string;
  readonly name: string;
  readonly package?: { readonly name?: string };
  readonly inputs?: unknown[];
}

/** One entry from `GET /api/actions/connectors`. */
export interface RawActionConnector {
  readonly id: string;
  readonly connector_type_id: string;
  readonly name: string;
  readonly is_preconfigured?: boolean;
  readonly is_deprecated?: boolean;
}

interface EnvironmentClientOptions {
  readonly esClient: EsClient;
  readonly kibanaClient: KibanaClient;
}

/**
 * Typed transport for the discovery endpoints the environment profiler reads.
 *
 * Bound to a single cluster via the injected {@link EsClient} /
 * {@link KibanaClient}. Each method maps 1:1 to an HTTP endpoint and returns
 * the parsed body. All interpretation (parsing data-stream names, mapping
 * connector types to capability domains, extracting Defend protection modes)
 * lives in the service, not here.
 */
export class EnvironmentClient {
  constructor(private readonly options: EnvironmentClientOptions) {}

  /** The cluster this client is bound to — used to seed the profile scope. */
  get clusterName(): string {
    return this.options.esClient.clusterName;
  }

  /** GET `/_data_stream`. */
  async getDataStreams(): Promise<RawDataStream[]> {
    const { data } = await this.options.esClient.get<{
      data_streams: RawDataStream[];
    }>("/_data_stream");
    return data.data_streams ?? [];
  }

  /** GET `/_data_stream/_stats?human=true`. */
  async getDataStreamStats(): Promise<RawDataStreamStat[]> {
    const { data } = await this.options.esClient.get<{
      data_streams: RawDataStreamStat[];
    }>("/_data_stream/_stats", { params: { human: "true" } });
    return data.data_streams ?? [];
  }

  /** GET `/_cat/indices/{pattern}?format=json&h=index,docs.count`. */
  async catDocCounts(pattern: string): Promise<CatDocCountRow[]> {
    const { data } = await this.options.esClient.get<CatDocCountRow[]>(
      `/_cat/indices/${pattern}`,
      { params: { format: "json", h: "index,docs.count" } }
    );
    return data;
  }

  /**
   * GET `/_cat/indices?format=json&h=index,docs.count,store.size&bytes=b` —
   * concrete indices with byte-accurate sizes. Used to discover standalone
   * indices (not backed by a data stream) that hold huntable data.
   */
  async catIndices(): Promise<CatIndexRow[]> {
    const { data } = await this.options.esClient.get<CatIndexRow[]>(
      "/_cat/indices",
      { params: { format: "json", h: "index,docs.count,store.size", bytes: "b" } }
    );
    return data;
  }

  /** POST `/_query?format=json`. */
  async runEsql(query: string): Promise<EsqlResult> {
    const { data } = await this.options.esClient.post<EsqlResult>(
      "/_query",
      { query },
      { params: { format: "json" } }
    );
    return data;
  }

  /** POST `/{pattern}/_count` — tolerant of missing indices. */
  async count(pattern: string, body?: Record<string, unknown>): Promise<number> {
    const { data } = await this.options.esClient.post<{ count: number }>(
      `/${encodeURIComponent(pattern)}/_count`,
      body ?? {},
      { params: { ignore_unavailable: "true", allow_no_indices: "true" } }
    );
    return data.count ?? 0;
  }

  /** GET `/{pattern}/_field_caps?fields=...` — tolerant of missing indices. */
  async getFieldCaps(
    pattern: string,
    fields: string[]
  ): Promise<Record<string, Record<string, unknown>>> {
    const { data } = await this.options.esClient.get<{
      fields: Record<string, Record<string, unknown>>;
    }>(`/${encodeURIComponent(pattern)}/_field_caps`, {
      params: {
        fields: fields.join(","),
        ignore_unavailable: "true",
        allow_no_indices: "true",
      },
    });
    return data.fields ?? {};
  }

  /**
   * GET `/{pattern}/_mapping?filter_path=*.mappings._meta` — harvest per-index
   * `_meta` (Fleet/package indices stamp `description`/`managed_by`/`package`
   * here). A cheap deterministic purpose hint for role/affordance classification.
   * Tolerant of missing indices; returns a per-index `_meta` map.
   */
  async getMappingsMeta(
    pattern: string
  ): Promise<Record<string, Record<string, unknown>>> {
    const { data } = await this.options.esClient.get<
      Record<string, { mappings?: { _meta?: Record<string, unknown> } }>
    >(`/${encodeURIComponent(pattern)}/_mapping`, {
      params: {
        filter_path: "*.mappings._meta",
        ignore_unavailable: "true",
        allow_no_indices: "true",
      },
    });
    const out: Record<string, Record<string, unknown>> = {};
    for (const [index, body] of Object.entries(data ?? {})) {
      const meta = body?.mappings?._meta;
      if (meta && typeof meta === "object") out[index] = meta;
    }
    return out;
  }

  /** GET `/api/cases/_find` — returns just the total. */
  async countCases(): Promise<number> {
    const { data } = await this.options.kibanaClient.get<{ total: number }>(
      "/api/cases/_find",
      { params: { perPage: "1", page: "1" }, headers: FLEET_HEADERS }
    );
    return data.total ?? 0;
  }

  /** GET `/api/attack_discovery/generations` — raw envelope. */
  async getAttackDiscoveryGenerations(): Promise<unknown> {
    const { data } = await this.options.kibanaClient.get(
      "/api/attack_discovery/generations",
      { params: { size: "1" }, headers: FLEET_HEADERS }
    );
    return data;
  }

  /** GET `/api/fleet/epm/packages/installed`. */
  async getInstalledPackages(): Promise<InstalledPackage[]> {
    const { data } = await this.options.kibanaClient.get<{
      items: InstalledPackage[];
    }>("/api/fleet/epm/packages/installed", {
      params: { perPage: "1000" },
      headers: FLEET_HEADERS,
    });
    return data.items ?? [];
  }

  /** GET `/api/fleet/package_policies?kuery=...package.name:{pkg}`. */
  async getPackagePolicies(packageName: string): Promise<RawPackagePolicy[]> {
    const { data } = await this.options.kibanaClient.get<{
      items: RawPackagePolicy[];
    }>("/api/fleet/package_policies", {
      params: {
        kuery: `ingest-package-policies.package.name: ${packageName}`,
        perPage: "1000",
      },
      headers: FLEET_HEADERS,
    });
    return data.items ?? [];
  }

  /** GET `/api/actions/connectors`. */
  async getConnectors(): Promise<RawActionConnector[]> {
    const { data } = await this.options.kibanaClient.get<RawActionConnector[]>(
      "/api/actions/connectors"
    );
    return data;
  }

  /** GET `/api/detection_engine/rules/_find` — returns just the total. */
  async countRules(filter?: string): Promise<number> {
    const params: Record<string, string> = { page: "1", per_page: "1" };
    if (filter) params.filter = filter;
    const { data } = await this.options.kibanaClient.get<{ total: number }>(
      "/api/detection_engine/rules/_find",
      { params, headers: FLEET_HEADERS }
    );
    return data.total ?? 0;
  }
}
