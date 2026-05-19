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
const DEFAULT_NAMESPACE = "default";
const ALERTS_INDEX_PREFIX = ".alerts-security.alerts-";
const KIBANA_API_VERSION = "2023-10-31";

const KIBANA_HEADERS = {
  "elastic-api-version": KIBANA_API_VERSION,
} as const;

/**
 * Build the cases base path, scoped to a Kibana space when `namespace` is set
 * to anything other than the default. The default space uses the un-prefixed
 * path; non-default spaces use the `/s/<spaceId>/...` form.
 */
function casesBasePath(namespace?: string): string {
  return namespace && namespace !== DEFAULT_NAMESPACE
    ? `/s/${namespace}${CASES_API}`
    : CASES_API;
}

/**
 * The Security alerts index for a given namespace. By default in Security
 * Solution this tracks the Kibana space ID, so callers can pass the same
 * value they use to scope the cases path.
 */
function alertsIndex(namespace?: string): string {
  return `${ALERTS_INDEX_PREFIX}${namespace || DEFAULT_NAMESPACE}`;
}

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

/** Raw `_doc/{id}` envelope from Elasticsearch, narrowed to `_source`. */
export interface RawAlertDocument {
  readonly _source: Record<string, unknown>;
}

/** A single document entry in an `_mget` response. */
export interface MgetAlertDoc {
  readonly _index: string;
  readonly _id: string;
  readonly found: boolean;
  readonly _source?: Record<string, unknown>;
}

/** Envelope returned by `/.alerts-security.alerts-default/_mget`. */
export interface MgetAlertsResponse {
  readonly docs: MgetAlertDoc[];
}

interface CasesClientOptions {
  readonly esClient: EsClient;
  readonly kibanaClient: KibanaClient;
}

/**
 * Typed transport for Kibana cases plus the Elasticsearch `_doc` lookup
 * used to enrich alert attachments.
 *
 * Bound to a single cluster via the injected {@link EsClient} and
 * {@link KibanaClient}. Each method maps 1:1 to an HTTP endpoint.
 * Body and param shaping is the service's responsibility.
 */
export class CasesClient {
  constructor(private readonly options: CasesClientOptions) {}

  /** GET `/api/cases/_find` (optionally space-scoped). */
  async findCases(
    params: Record<string, string>,
    namespace?: string
  ): Promise<FindCasesResponse> {
    const { data } = await this.options.kibanaClient.get<FindCasesResponse>(
      `${casesBasePath(namespace)}/_find`,
      { params, headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/cases/{caseId}` (optionally space-scoped). */
  async getCase(caseId: string, namespace?: string): Promise<KibanaCase> {
    const { data } = await this.options.kibanaClient.get<KibanaCase>(
      `${casesBasePath(namespace)}/${caseId}`,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /**
   * POST `/api/cases` (or `/s/<namespace>/api/cases` for a non-default
   * Kibana space).
   */
  async createCase(
    body: EsRequestBody,
    namespace?: string
  ): Promise<KibanaCase> {
    const { data } = await this.options.kibanaClient.post<KibanaCase>(
      casesBasePath(namespace),
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** PATCH `/api/cases` (bulk patch envelope, optionally space-scoped). */
  async updateCases(
    body: EsRequestBody,
    namespace?: string
  ): Promise<KibanaCase[]> {
    const { data } = await this.options.kibanaClient.patch<KibanaCase[]>(
      casesBasePath(namespace),
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /**
   * POST `/api/cases/{caseId}/comments` (or the space-scoped equivalent for
   * a non-default namespace — must match the namespace the case was created
   * in or the case id won't resolve).
   */
  async addComment(
    caseId: string,
    body: EsRequestBody,
    namespace?: string
  ): Promise<unknown> {
    const { data } = await this.options.kibanaClient.post(
      `${casesBasePath(namespace)}/${caseId}/comments`,
      body,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/cases/{caseId}/alerts` — raw, pre-enrichment (optionally space-scoped). */
  async getCaseAlerts(
    caseId: string,
    namespace?: string
  ): Promise<RawCaseAlert[]> {
    const { data } = await this.options.kibanaClient.get<RawCaseAlert[]>(
      `${casesBasePath(namespace)}/${caseId}/alerts`,
      { headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/cases/{caseId}/comments/_find` (optionally space-scoped). */
  async getCommentsFind(
    caseId: string,
    params: Record<string, string>,
    namespace?: string
  ): Promise<FindCommentsResponse> {
    const { data } = await this.options.kibanaClient.get<FindCommentsResponse>(
      `${casesBasePath(namespace)}/${caseId}/comments/_find`,
      { params, headers: KIBANA_HEADERS }
    );
    return data;
  }

  /** GET `/api/cases/alerts/{alertId}` (optionally space-scoped). */
  async getCasesForAlert(
    alertId: string,
    namespace?: string
  ): Promise<{ id: string; title: string }[]> {
    const { data } = await this.options.kibanaClient.get<
      { id: string; title: string }[]
    >(`${casesBasePath(namespace)}/alerts/${alertId}`, {
      headers: KIBANA_HEADERS,
    });
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

  /** GET `/{index}/_doc/{id}` on Elasticsearch — used to enrich attachments. */
  async getAlertDocument(
    index: string,
    id: string
  ): Promise<RawAlertDocument> {
    const { data } = await this.options.esClient.get<RawAlertDocument>(
      `/${index}/_doc/${id}`
    );
    return data;
  }

  /**
   * POST `/.alerts-security.alerts-<namespace>/_mget` on Elasticsearch —
   * bulk fetch alert documents by id when attaching alerts to a case.
   * Defaults to the `default` namespace.
   */
  async mgetAlerts(
    alertIds: readonly string[],
    namespace?: string
  ): Promise<MgetAlertsResponse> {
    const { data } = await this.options.esClient.post<MgetAlertsResponse>(
      `/${alertsIndex(namespace)}/_mget`,
      { ids: alertIds }
    );
    return data;
  }
}
