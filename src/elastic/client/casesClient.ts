/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaCase } from "../../shared/types.js";
import type { EsClient } from "../es-client/index.js";
import type { KibanaClient } from "../kibana-client/index.js";

const CASES_API = "/api/cases";
const KIBANA_API_VERSION = "2023-10-31";

const KIBANA_HEADERS = {
  "elastic-api-version": KIBANA_API_VERSION,
} as const;

/** Opaque body — shaped by the service. */
export type EsRequestBody = Record<string, unknown>;

/** `_find` envelope for cases. */
export interface FindCasesResponse {
  readonly cases: KibanaCase[];
  readonly total: number;
  readonly page: number;
  readonly perPage: number;
}

/** Comment shape returned by `_find` on a case's comments. */
export interface CaseComment {
  id: string;
  type: string;
  comment?: string;
  created_at: string;
  created_by: { username?: string; full_name?: string; email?: string | null };
  updated_at?: string | null;
}

/** Find-comments envelope. */
export interface FindCommentsResponse {
  readonly comments: CaseComment[];
  readonly total: number;
}

/** Avatar metadata returned by the user profile endpoint. */
export interface UserAvatar {
  color?: string;
  initials?: string;
  imageUrl?: string;
}

/** Raw user profile envelope. */
export interface UserProfileResponse {
  readonly user?: { username?: string };
  readonly data?: { avatar?: UserAvatar };
}

/** Raw case-alert attachment record (pre-enrichment). */
export interface RawCaseAlert {
  readonly id: string;
  readonly index: string;
  readonly attached_at: string;
}

/** A single hit from the alerts `ids`-query search. */
export interface AlertSearchHit {
  readonly _index: string;
  readonly _id: string;
  readonly _source?: Record<string, unknown>;
}

/** `_search` envelope, narrowed to the hits the service consumes. */
export interface SearchAlertsResponse {
  readonly hits: { readonly hits: AlertSearchHit[] };
}

interface CasesClientOptions {
  readonly esClient: EsClient;
  readonly kibanaClient: KibanaClient;
}

/**
 * Typed transport for Kibana cases plus the Elasticsearch `ids`-query
 * search used to resolve and enrich alert attachments.
 *
 * Bound to a single cluster via the injected {@link EsClient} and
 * {@link KibanaClient}. Each method maps 1:1 to an HTTP endpoint.
 * Body and param shaping is the service's responsibility.
 */
export class CasesClient {
  constructor(private readonly options: CasesClientOptions) {}

  /** GET `/api/cases/_find`. */
  async findCases(params: Record<string, string>): Promise<FindCasesResponse> {
    const { data } = await this.options.kibanaClient.get<FindCasesResponse>(
      `${CASES_API}/_find`,
      { params, headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/cases/{caseId}`. */
  async getCase(caseId: string): Promise<KibanaCase> {
    const { data } = await this.options.kibanaClient.get<KibanaCase>(
      `${CASES_API}/${caseId}`,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** POST `/api/cases`. */
  async createCase(body: EsRequestBody): Promise<KibanaCase> {
    const { data } = await this.options.kibanaClient.post<KibanaCase>(
      CASES_API,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** PATCH `/api/cases` (bulk patch envelope). */
  async updateCases(body: EsRequestBody): Promise<KibanaCase[]> {
    const { data } = await this.options.kibanaClient.patch<KibanaCase[]>(
      CASES_API,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** POST `/api/cases/{caseId}/comments`. */
  async addComment(caseId: string, body: EsRequestBody): Promise<unknown> {
    const { data } = await this.options.kibanaClient.post(
      `${CASES_API}/${caseId}/comments`,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/cases/{caseId}/alerts` — raw, pre-enrichment. */
  async getCaseAlerts(caseId: string): Promise<RawCaseAlert[]> {
    const { data } = await this.options.kibanaClient.get<RawCaseAlert[]>(
      `${CASES_API}/${caseId}/alerts`,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/cases/{caseId}/comments/_find`. */
  async getCommentsFind(
    caseId: string,
    params: Record<string, string>
  ): Promise<FindCommentsResponse> {
    const { data } = await this.options.kibanaClient.get<FindCommentsResponse>(
      `${CASES_API}/${caseId}/comments/_find`,
      { params, headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/cases/alerts/{alertId}`. */
  async getCasesForAlert(
    alertId: string
  ): Promise<{ id: string; title: string }[]> {
    const { data } = await this.options.kibanaClient.get<
      { id: string; title: string }[]
    >(`${CASES_API}/alerts/${alertId}`, { headers: KIBANA_HEADERS });
    return data;
  }

  /**
   * GET `/internal/security/user_profile`.
   *
   * Note: this endpoint does NOT take `elastic-api-version`; the legacy
   * implementation also omits it, so we omit it here.
   */
  async getUserProfile(
    params: Record<string, string>
  ): Promise<UserProfileResponse> {
    const { data } = await this.options.kibanaClient.get<UserProfileResponse>(
      "/internal/security/user_profile",
      { params }
    );
    return data;
  }

  /**
   * POST `/{indices}/_search` with an `ids` query on Elasticsearch — bulk
   * fetch alert documents by id.
   *
   * Deliberately a search rather than `GET _doc` / `_mget`: single-document
   * lookups must resolve to exactly one concrete index, so they fail with
   * `alias [...] has more than one index associated with it` as soon as the
   * alerts alias rolls over (which ILM does on any long-lived cluster). A
   * search fans out across all backing indices.
   */
  async searchAlertsByIds(
    indices: readonly string[],
    alertIds: readonly string[]
  ): Promise<AlertSearchHit[]> {
    const { data } = await this.options.esClient.post<SearchAlertsResponse>(
      `/${indices.join(",")}/_search`,
      {
        query: { ids: { values: alertIds } },
        // `size` must stay within `index.max_result_window` (default 10 000)
        // or the search rejects the request outright.
        size: Math.min(alertIds.length, 10_000),
      },
      { params: { ignore_unavailable: "true", allow_no_indices: "true" } }
    );
    return data.hits.hits;
  }
}
