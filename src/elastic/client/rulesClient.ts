/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { DetectionRule, RuleException } from "../../shared/types.js";
import type { EsClient } from "../es-client/index.js";
import type { KibanaClient } from "../kibana-client/index.js";

const RULES_API = "/api/detection_engine/rules";
const EXCEPTIONS_API = "/api/exception_lists/items/_find";
const DEFAULT_NAMESPACE = "default";
const ALERTS_INDEX_PREFIX = ".alerts-security.alerts-";
const KIBANA_API_VERSION = "2023-10-31";

/** Headers required on every Kibana detection-engine call. */
const KIBANA_HEADERS = {
  "elastic-api-version": KIBANA_API_VERSION,
} as const;

/**
 * Prefix Kibana paths with `/s/<namespace>` for non-default spaces.
 * Detection rules and exception lists are space-scoped — a rule created
 * in space `soc` is only visible/editable via `/s/soc/api/detection_engine/...`.
 */
function spacePrefix(namespace?: string): string {
  return namespace && namespace !== DEFAULT_NAMESPACE ? `/s/${namespace}` : "";
}

function rulesPath(namespace?: string): string {
  return `${spacePrefix(namespace)}${RULES_API}`;
}

function exceptionsPath(namespace?: string): string {
  return `${spacePrefix(namespace)}${EXCEPTIONS_API}`;
}

function alertsIndex(namespace?: string): string {
  return `${ALERTS_INDEX_PREFIX}${namespace || DEFAULT_NAMESPACE}`;
}

/** Opaque request body — shaped by the service. */
export type EsRequestBody = Record<string, unknown>;

/** Standard Kibana `_find` envelope returned by `findRules` / `listExceptions`. */
export interface FindResponse<T> {
  readonly data: T[];
  readonly total: number;
  readonly page: number;
  readonly perPage: number;
}

/** Bucket shape returned by the noisy-rules aggregation. */
export interface NoisyRulesBucket {
  readonly key: string;
  readonly doc_count: number;
  readonly rule_id: { readonly buckets: { readonly key: string }[] };
}

/** Typed shape of the noisy-rules `_search` response. */
export interface NoisyRulesAggResponse {
  readonly aggregations: {
    readonly by_rule: { readonly buckets: NoisyRulesBucket[] };
  };
}

interface RulesClientOptions {
  readonly esClient: EsClient;
  readonly kibanaClient: KibanaClient;
}

/**
 * Typed transport for Kibana detection-engine endpoints plus the
 * Elasticsearch endpoints used for query validation and noisy-rule
 * analytics.
 *
 * Bound to a single cluster via the injected {@link EsClient} and
 * {@link KibanaClient}. Each method maps 1:1 to an HTTP endpoint and
 * returns the parsed response.
 */
export class RulesClient {
  constructor(private readonly options: RulesClientOptions) {}

  /** GET `/api/detection_engine/rules/_find` (optionally space-scoped). */
  async findRules(
    params: Record<string, string>,
    namespace?: string
  ): Promise<FindResponse<DetectionRule>> {
    const { data } = await this.options.kibanaClient.get<
      FindResponse<DetectionRule>
    >(`${rulesPath(namespace)}/_find`, { params, headers: KIBANA_HEADERS });
    return data;
  }

  /** GET `/api/detection_engine/rules?id=<id>` (optionally space-scoped). */
  async getRule(id: string, namespace?: string): Promise<DetectionRule> {
    const { data } = await this.options.kibanaClient.get<DetectionRule>(
      rulesPath(namespace),
      { params: { id }, headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** POST `/api/detection_engine/rules` (optionally space-scoped). */
  async createRule(
    body: EsRequestBody,
    namespace?: string
  ): Promise<DetectionRule> {
    const { data } = await this.options.kibanaClient.post<DetectionRule>(
      rulesPath(namespace),
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** PATCH `/api/detection_engine/rules` (optionally space-scoped). */
  async patchRule(
    body: EsRequestBody,
    namespace?: string
  ): Promise<DetectionRule> {
    const { data } = await this.options.kibanaClient.patch<DetectionRule>(
      rulesPath(namespace),
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** DELETE `/api/detection_engine/rules?id=<id>` (optionally space-scoped). */
  async deleteRule(id: string, namespace?: string): Promise<void> {
    await this.options.kibanaClient.delete(rulesPath(namespace), {
      params: { id },
      headers: KIBANA_HEADERS,
    });
  }

  /** POST `/api/detection_engine/rules/_bulk_action` (optionally space-scoped). */
  async bulkAction(
    body: EsRequestBody,
    namespace?: string
  ): Promise<unknown> {
    const { data } = await this.options.kibanaClient.post(
      `${rulesPath(namespace)}/_bulk_action`,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** POST `/api/detection_engine/rules/{ruleId}/exceptions` (optionally space-scoped). */
  async addException(
    ruleId: string,
    body: EsRequestBody,
    namespace?: string
  ): Promise<unknown> {
    const { data } = await this.options.kibanaClient.post(
      `${rulesPath(namespace)}/${ruleId}/exceptions`,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/exception_lists/items/_find` (optionally space-scoped). */
  async listExceptions(
    params: Record<string, string>,
    namespace?: string
  ): Promise<FindResponse<RuleException>> {
    const { data } = await this.options.kibanaClient.get<
      FindResponse<RuleException>
    >(exceptionsPath(namespace), { params, headers: KIBANA_HEADERS });
    return data;
  }

  /** POST `/_query` on `esClient` — used to validate ES|QL queries. */
  async validateEsql(query: string): Promise<unknown> {
    const { data } = await this.options.esClient.post(
      "/_query",
      { query, fetch_size: 0 }
    );
    return data;
  }

  /** POST `/.alerts-security.alerts-<namespace>/_validate/query` on `esClient`. */
  async validateKqlOrEql(
    body: EsRequestBody,
    namespace?: string
  ): Promise<unknown> {
    const { data } = await this.options.esClient.post(
      `/${alertsIndex(namespace)}/_validate/query`,
      body
    );
    return data;
  }

  /** POST `/.alerts-security.alerts-<namespace>/_search` on `esClient` for noisy-rules. */
  async searchAlertsAggregation(
    body: EsRequestBody,
    namespace?: string
  ): Promise<NoisyRulesAggResponse> {
    const { data } = await this.options.esClient.post<NoisyRulesAggResponse>(
      `/${alertsIndex(namespace)}/_search`,
      body
    );
    return data;
  }
}
