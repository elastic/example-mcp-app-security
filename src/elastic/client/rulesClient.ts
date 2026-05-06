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
const ALERTS_INDEX = ".alerts-security.alerts-*";
const KIBANA_API_VERSION = "2023-10-31";

/** Headers required on every Kibana detection-engine call. */
const KIBANA_HEADERS = {
  "elastic-api-version": KIBANA_API_VERSION,
} as const;

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

  /** GET `/api/detection_engine/rules/_find`. */
  async findRules(
    params: Record<string, string>
  ): Promise<FindResponse<DetectionRule>> {
    const { data } = await this.options.kibanaClient.get<
      FindResponse<DetectionRule>
    >(`${RULES_API}/_find`, { params, headers: KIBANA_HEADERS });
    return data;
  }

  /** GET `/api/detection_engine/rules?id=<id>`. */
  async getRule(id: string): Promise<DetectionRule> {
    const { data } = await this.options.kibanaClient.get<DetectionRule>(
      RULES_API,
      { params: { id }, headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** POST `/api/detection_engine/rules`. */
  async createRule(body: EsRequestBody): Promise<DetectionRule> {
    const { data } = await this.options.kibanaClient.post<DetectionRule>(
      RULES_API,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** PATCH `/api/detection_engine/rules`. */
  async patchRule(body: EsRequestBody): Promise<DetectionRule> {
    const { data } = await this.options.kibanaClient.patch<DetectionRule>(
      RULES_API,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** DELETE `/api/detection_engine/rules?id=<id>`. */
  async deleteRule(id: string): Promise<void> {
    await this.options.kibanaClient.delete(RULES_API, {
      params: { id },
      headers: KIBANA_HEADERS,
    });
  }

  /** POST `/api/detection_engine/rules/_bulk_action`. */
  async bulkAction(body: EsRequestBody): Promise<unknown> {
    const { data } = await this.options.kibanaClient.post(
      `${RULES_API}/_bulk_action`,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** POST `/api/detection_engine/rules/{ruleId}/exceptions`. */
  async addException(ruleId: string, body: EsRequestBody): Promise<unknown> {
    const { data } = await this.options.kibanaClient.post(
      `${RULES_API}/${ruleId}/exceptions`,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/exception_lists/items/_find`. */
  async listExceptions(
    params: Record<string, string>
  ): Promise<FindResponse<RuleException>> {
    const { data } = await this.options.kibanaClient.get<
      FindResponse<RuleException>
    >(EXCEPTIONS_API, { params, headers: KIBANA_HEADERS });
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

  /** POST `/.alerts-security.alerts-*\/_validate/query` on `esClient`. */
  async validateKqlOrEql(body: EsRequestBody): Promise<unknown> {
    const { data } = await this.options.esClient.post(
      `/${ALERTS_INDEX}/_validate/query`,
      body
    );
    return data;
  }

  /** POST `/.alerts-security.alerts-*\/_search` on `esClient` for noisy-rules. */
  async searchAlertsAggregation(
    body: EsRequestBody
  ): Promise<NoisyRulesAggResponse> {
    const { data } = await this.options.esClient.post<NoisyRulesAggResponse>(
      `/${ALERTS_INDEX}/_search`,
      body
    );
    return data;
  }
}
