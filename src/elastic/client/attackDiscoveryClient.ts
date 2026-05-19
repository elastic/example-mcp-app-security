/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { EsqlResult } from "../../shared/types.js";
import type { EsClient } from "../es-client/index.js";
import type { KibanaClient } from "../kibana-client/index.js";

const KIBANA_API_VERSION = "2023-10-31";
const DEFAULT_NAMESPACE = "default";

const KIBANA_HEADERS = {
  "elastic-api-version": KIBANA_API_VERSION,
} as const;

/**
 * Prefix Kibana paths with `/s/<namespace>` when the namespace is set to
 * anything other than the default space. Mirrors `casesBasePath` in
 * `casesClient.ts`.
 */
function spacePrefix(namespace?: string): string {
  return namespace && namespace !== DEFAULT_NAMESPACE ? `/s/${namespace}` : "";
}

/** Opaque body — shaped by the service. */
export type EsRequestBody = Record<string, unknown>;

/** Single attack-discovery record returned by ES|QL. */
export interface AttackDiscovery {
  id: string;
  timestamp: string;
  executionUuid: string;
  title: string;
  summaryMarkdown: string;
  detailsMarkdown: string;
  mitreTactics: string[];
  alertIds: string[];
  alertsContextCount: number;
  riskScore: number;
}

/** Signals that feed {@link ConfidenceLevel} synthesis. */
export interface ConfidenceSignals {
  alertDiversity: {
    alertCount: number;
    ruleCount: number;
    severities: string[];
  };
  ruleFrequency: {
    ruleName: string;
    totalAlerts7d: number;
    hostCount: number;
  }[];
  entityRisk: {
    name: string;
    type: "host" | "user";
    riskLevel: string;
    riskScore: number;
  }[];
}

export type ConfidenceLevel = "high" | "moderate" | "low";

/** A single discovery enriched with synthesised confidence signals. */
export interface TriagedDiscovery extends AttackDiscovery {
  confidence: ConfidenceLevel;
  signals: ConfidenceSignals;
  hosts: string[];
  users: string[];
  ruleNames: string[];
}

/** List of discoveries returned by `getDiscoveries`. */
export interface DiscoverySummary {
  total: number;
  discoveries: AttackDiscovery[];
  byConfidence?: Record<string, number>;
}

/** Result of an on-demand generation request. */
export interface GenerationResult {
  execution_uuid: string;
}

/** Anonymisation field shape used during generation. */
export interface AnonymizationField {
  field: string;
  allowed: boolean;
  anonymized: boolean;
  id: string;
}

/** Update-by-query response shape. */
export interface UpdateByQueryResponse {
  readonly updated?: number;
}

/** Raw connector record from `/api/actions/connectors`. */
export interface RawConnector {
  id: string;
  name: string;
  connector_type_id?: string;
  action_type_id?: string;
}

interface AttackDiscoveryClientOptions {
  readonly esClient: EsClient;
  readonly kibanaClient: KibanaClient;
}

/**
 * Typed transport for attack-discovery endpoints.
 *
 * Bound to a single cluster via the injected {@link EsClient} and
 * {@link KibanaClient}. Exposes ES|QL execution (used for both fetch and
 * confidence assessment), per-index `_update_by_query` for ack, the
 * Kibana generate endpoint, the connectors list, and the anonymisation
 * fields lookup.
 */
export class AttackDiscoveryClient {
  constructor(private readonly options: AttackDiscoveryClientOptions) {}

  /** POST `/_query?format=json` on `esClient`. */
  async runEsql(query: string): Promise<EsqlResult> {
    const { data } = await this.options.esClient.post<EsqlResult>(
      "/_query",
      { query },
      { params: { format: "json" } }
    );
    return data;
  }

  /** POST `/{index}/_update_by_query` on `esClient`. */
  async acknowledgeOnIndex(
    index: string,
    body: EsRequestBody
  ): Promise<UpdateByQueryResponse> {
    const { data } = await this.options.esClient.post<UpdateByQueryResponse>(
      `/${index}/_update_by_query`,
      body
    );
    return data;
  }

  /** POST `/api/attack_discovery/_generate` on `kibanaClient` (optionally space-scoped). */
  async generate(
    body: EsRequestBody,
    namespace?: string
  ): Promise<GenerationResult> {
    const { data } = await this.options.kibanaClient.post<GenerationResult>(
      `${spacePrefix(namespace)}/api/attack_discovery/_generate`,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/actions/connectors` on `kibanaClient` (optionally space-scoped). */
  async listConnectors(namespace?: string): Promise<RawConnector[]> {
    const { data } = await this.options.kibanaClient.get<RawConnector[]>(
      `${spacePrefix(namespace)}/api/actions/connectors`,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/security_ai_assistant/anonymization_fields/_find` (optionally space-scoped). */
  async findAnonymizationFields(
    namespace?: string
  ): Promise<{ data: AnonymizationField[] }> {
    const { data } = await this.options.kibanaClient.get<{
      data: AnonymizationField[];
    }>(
      `${spacePrefix(namespace)}/api/security_ai_assistant/anonymization_fields/_find`,
      {
        params: { perPage: "500" },
        headers: KIBANA_HEADERS,
      }
    );
    return data;
  }

  /**
   * GET `/api/attack_discovery/generations` on `kibanaClient` (optionally space-scoped).
   *
   * Returns the raw envelope shape so callers can read whichever fields the
   * UI expects — the Kibana surface here is intentionally not narrowed.
   */
  async getGenerations(
    params: Record<string, string>,
    namespace?: string
  ): Promise<unknown> {
    const { data } = await this.options.kibanaClient.get(
      `${spacePrefix(namespace)}/api/attack_discovery/generations`,
      { params, headers: KIBANA_HEADERS }
    );
    return data;
  }
}
