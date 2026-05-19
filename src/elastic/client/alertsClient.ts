/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  NetworkEvent,
  ProcessEvent,
  SecurityAlert,
} from "../../shared/types.js";
import type { EsClient } from "../es-client/index.js";

const DEFAULT_NAMESPACE = "default";
const ALERTS_INDEX_PREFIX = ".alerts-security.alerts-";

/** Endpoint integration process-event indices. */
const PROCESS_EVENTS_INDEX = "logs-endpoint.events.process-*";

/** Endpoint integration network-event indices. */
const NETWORK_EVENTS_INDEX = "logs-endpoint.events.network-*";

/**
 * Build the Security alerts index name for a namespace. Defaults to
 * `default` so unspecified callers see the same single space the Kibana
 * UI shows by default. For deployment-wide queries, callers enumerate
 * spaces via `list-namespaces` and pass each id explicitly.
 */
function alertsIndex(namespace?: string): string {
  return `${ALERTS_INDEX_PREFIX}${namespace || DEFAULT_NAMESPACE}`;
}

/**
 * Opaque Elasticsearch request body. The client does not introspect or
 * validate it — the service layer is responsible for shaping each query.
 */
export type EsRequestBody = Record<string, unknown>;

/** Generic `_search` envelope, parametric on the hit document shape. */
export interface SearchResponse<H> {
  readonly hits: {
    readonly total: { readonly value: number };
    readonly hits: H[];
  };
}

/** Single bucket from a `terms` aggregation. */
export interface TermBucket {
  readonly key: string;
  readonly doc_count: number;
}

/** Aggregations returned by {@link AlertsClient.searchAlerts}. */
export interface AlertSearchAggs {
  readonly by_severity: { readonly buckets: TermBucket[] };
  readonly by_rule: { readonly buckets: TermBucket[] };
  readonly by_host: { readonly buckets: TermBucket[] };
}

export type AlertSearchResponse = SearchResponse<SecurityAlert> & {
  readonly aggregations?: AlertSearchAggs;
};

export type ProcessEventSearchResponse = SearchResponse<{ _source: ProcessEvent }>;
export type NetworkEventSearchResponse = SearchResponse<{ _source: NetworkEvent }>;

export interface UpdateByQueryResponse {
  readonly updated: number;
}

interface AlertsClientOptions {
  readonly esClient: EsClient;
}

/**
 * Typed transport for the Elasticsearch endpoints used by alert triage.
 *
 * Bound to a single cluster via the injected {@link EsClient}. Each method
 * maps 1:1 to an ES API call, returns a typed response, and contains no
 * business logic — query construction and response shaping live in
 * {@link AlertsService}.
 */
export class AlertsClient {
  constructor(private readonly options: AlertsClientOptions) {}

  /** POST `/.alerts-security.alerts-<namespace>/_search` (defaults to `default`). */
  searchAlerts(
    body: EsRequestBody,
    namespace?: string
  ): Promise<AlertSearchResponse> {
    return this.post(`/${alertsIndex(namespace)}/_search`, body);
  }

  /** POST `/logs-endpoint.events.process-*\/_search` */
  searchProcessEvents(
    body: EsRequestBody
  ): Promise<ProcessEventSearchResponse> {
    return this.post(`/${PROCESS_EVENTS_INDEX}/_search`, body);
  }

  /** POST `/logs-endpoint.events.network-*\/_search` */
  searchNetworkEvents(
    body: EsRequestBody
  ): Promise<NetworkEventSearchResponse> {
    return this.post(`/${NETWORK_EVENTS_INDEX}/_search`, body);
  }

  /**
   * POST `/.alerts-security.alerts-<namespace>/_update/{id}` (defaults to `default`).
   *
   * Wraps the body in the required `{ doc }` envelope so callers only pass
   * the partial fields they want to merge into the alert.
   */
  async updateAlert(
    alertId: string,
    doc: EsRequestBody,
    namespace?: string
  ): Promise<void> {
    await this.post(`/${alertsIndex(namespace)}/_update/${alertId}`, { doc });
  }

  /** POST `/.alerts-security.alerts-<namespace>/_update_by_query` (defaults to `default`). */
  updateAlertsByQuery(
    body: EsRequestBody,
    namespace?: string
  ): Promise<UpdateByQueryResponse> {
    return this.post(`/${alertsIndex(namespace)}/_update_by_query`, body);
  }

  private async post<T>(path: string, body: EsRequestBody): Promise<T> {
    const { data } = await this.options.esClient.post<T>(path, body);
    return data;
  }
}
