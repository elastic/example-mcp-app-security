/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  spacePrefix,
  type AlertZeroCategory,
  type Conversation,
  type ConversationAttachment,
  type DismissReason,
  type ProposalItem,
  type ProposalWithMetadata,
} from "../../shared/alert-zero-types.js";
import type { EsClient } from "../es-client/index.js";
import type { KibanaClient } from "../kibana-client/index.js";
import { KibanaHttpError } from "../kibana-client/kibana-http-error.js";
import type { AlertSearchHit, SearchAlertsResponse } from "./casesClient.js";

const ALERTS_INDEX_PATTERN = ".alerts-security.alerts-*";

const INTERNAL_V1_HEADERS = { "elastic-api-version": "1" } as const;
const PUBLIC_HEADERS = { "elastic-api-version": "2023-10-31" } as const;

export interface InvestigationsCountResponse {
  readonly total: number;
}

/** `POST /api/core/capabilities` — feature id → capability flags. */
export type KibanaCapabilities = Readonly<
  Record<string, Readonly<Record<string, unknown>> | undefined>
>;

export interface ProposalsPage<T> {
  readonly proposals: T[];
  readonly total: number;
}

export interface PageParams {
  readonly size: number;
  readonly from: number;
}

export interface ConversationAttachmentsResponse {
  readonly results: ConversationAttachment[];
  readonly total_token_estimate?: number;
}

export interface UserProfileSummary {
  readonly uid: string;
  readonly user?: {
    readonly username?: string;
    readonly full_name?: string | null;
    readonly email?: string | null;
  };
}

export interface ApproveProposalBody {
  readonly actionInput?: Record<string, unknown>;
  readonly rationale?: string;
}

export interface DismissProposalBody {
  readonly dismissReason: DismissReason;
  readonly rationale?: string;
}

export type DetectionRule = Record<string, unknown>;

interface AlertZeroClientOptions {
  readonly esClient: EsClient;
  readonly kibanaClient: KibanaClient;
}

/**
 * Typed transport for Alert Zero, Proposals, Agent Builder conversations,
 * user profiles and detection rules, plus the Elasticsearch `ids`-query used
 * to enrich alert attachments.
 *
 * Each Kibana method maps 1:1 to an endpoint and takes an optional `spaceId`
 * that prefixes the path with `/s/<space>` (the default space has no prefix).
 */
export class AlertZeroClient {
  constructor(private readonly options: AlertZeroClientOptions) {}

  /** GET `/internal/alertzero/investigations/count` — the availability probe. */
  async getInvestigationsCount(spaceId?: string): Promise<InvestigationsCountResponse> {
    const { data } = await this.options.kibanaClient.get<InvestigationsCountResponse>(
      `${spacePrefix(spaceId)}/internal/alertzero/investigations/count`,
      { headers: INTERNAL_V1_HEADERS }
    );
    return data;
  }

  /** POST `/api/core/capabilities` (unversioned). */
  async getCapabilities(spaceId?: string): Promise<KibanaCapabilities> {
    const { data } = await this.options.kibanaClient.post<KibanaCapabilities>(
      `${spacePrefix(spaceId)}/api/core/capabilities`,
      { applications: [] }
    );
    return data;
  }

  /** GET `/api/spaces/space/{id}`; false on 404, other failures throw. */
  async spaceExists(spaceId: string): Promise<boolean> {
    try {
      await this.options.kibanaClient.get(`/api/spaces/space/${encodeURIComponent(spaceId)}`, {
        headers: PUBLIC_HEADERS,
      });
      return true;
    } catch (err) {
      if (err instanceof KibanaHttpError && err.status === 404) return false;
      throw err;
    }
  }

  /**
   * GET `/internal/alertzero/proposals/category/{category}` — pending rows, `size` ≤ 100.
   * Query schema: x-pack/solutions/security/plugins/alertzero/server/routes/proposals/get_proposals_by_category.ts
   */
  async getProposalsByCategory(
    category: AlertZeroCategory,
    page: PageParams,
    spaceId?: string
  ): Promise<ProposalsPage<ProposalItem>> {
    const { data } = await this.options.kibanaClient.get<ProposalsPage<ProposalItem>>(
      `${spacePrefix(spaceId)}/internal/alertzero/proposals/category/${encodeURIComponent(category)}`,
      { params: { size: page.size, from: page.from }, headers: INTERNAL_V1_HEADERS }
    );
    return data;
  }

  /** GET `/internal/proposals/{id}`. */
  async getProposal(proposalId: string, spaceId?: string): Promise<ProposalWithMetadata> {
    const { data } = await this.options.kibanaClient.get<ProposalWithMetadata>(
      `${spacePrefix(spaceId)}/internal/proposals/${encodeURIComponent(proposalId)}`,
      { headers: INTERNAL_V1_HEADERS }
    );
    return data;
  }

  /**
   * GET `/internal/proposals?conversationId=` — every status, superseded rows included.
   * Query schema: `listProposalsQuerySchema` in x-pack/platform/packages/shared/kbn-proposals-common/src/proposal.ts
   */
  async listProposalsByConversation(
    conversationId: string,
    page: PageParams,
    spaceId?: string
  ): Promise<ProposalsPage<ProposalWithMetadata>> {
    const { data } = await this.options.kibanaClient.get<ProposalsPage<ProposalWithMetadata>>(
      `${spacePrefix(spaceId)}/internal/proposals`,
      {
        params: { conversationId, size: page.size, from: page.from },
        headers: INTERNAL_V1_HEADERS,
      }
    );
    return data;
  }

  /** GET `/api/agent_builder/conversations/{id}`. */
  async getConversation(conversationId: string, spaceId?: string): Promise<Conversation> {
    const { data } = await this.options.kibanaClient.get<Conversation>(
      `${spacePrefix(spaceId)}/api/agent_builder/conversations/${encodeURIComponent(conversationId)}`,
      { headers: PUBLIC_HEADERS }
    );
    return data;
  }

  /**
   * GET `/api/agent_builder/conversations/{id}/attachments?include_deleted=true`.
   * Query schema: x-pack/platform/plugins/shared/agent_builder/server/routes/attachments.ts
   */
  async getConversationAttachments(
    conversationId: string,
    spaceId?: string
  ): Promise<ConversationAttachmentsResponse> {
    const { data } = await this.options.kibanaClient.get<ConversationAttachmentsResponse>(
      `${spacePrefix(spaceId)}/api/agent_builder/conversations/${encodeURIComponent(conversationId)}/attachments`,
      { params: { include_deleted: true }, headers: PUBLIC_HEADERS }
    );
    return data;
  }

  /** GET `/internal/security/user_profile` — for an API key, the key owner's profile. */
  async getCurrentUserProfile(spaceId?: string): Promise<UserProfileSummary> {
    const { data } = await this.options.kibanaClient.get<UserProfileSummary>(
      `${spacePrefix(spaceId)}/internal/security/user_profile`
    );
    return data;
  }

  /**
   * POST `/internal/security/user_profile/_bulk_get` — unknown uids are omitted from the result.
   * Body schema: x-pack/platform/plugins/shared/security/server/routes/user_profile/bulk_get.ts
   */
  async bulkGetUserProfiles(
    uids: readonly string[],
    spaceId?: string
  ): Promise<UserProfileSummary[]> {
    const { data } = await this.options.kibanaClient.post<UserProfileSummary[]>(
      `${spacePrefix(spaceId)}/internal/security/user_profile/_bulk_get`,
      { uids, dataPath: "avatar" }
    );
    return data;
  }

  /**
   * POST `/internal/proposals/{id}/approve` — responds before the decision is written.
   * Body schema: `approveProposalRequestSchema` in x-pack/platform/packages/shared/kbn-proposals-common/src/proposal.ts
   */
  async approveProposal(
    proposalId: string,
    body: ApproveProposalBody,
    spaceId?: string
  ): Promise<ProposalWithMetadata> {
    const { data } = await this.options.kibanaClient.post<ProposalWithMetadata>(
      `${spacePrefix(spaceId)}/internal/proposals/${encodeURIComponent(proposalId)}/approve`,
      body,
      { headers: INTERNAL_V1_HEADERS }
    );
    return data;
  }

  /**
   * POST `/internal/proposals/{id}/dismiss` — responds before the decision is written.
   * Body schema: `dismissProposalRequestSchema` in x-pack/platform/packages/shared/kbn-proposals-common/src/proposal.ts
   */
  async dismissProposal(
    proposalId: string,
    body: DismissProposalBody,
    spaceId?: string
  ): Promise<ProposalWithMetadata> {
    const { data } = await this.options.kibanaClient.post<ProposalWithMetadata>(
      `${spacePrefix(spaceId)}/internal/proposals/${encodeURIComponent(proposalId)}/dismiss`,
      body,
      { headers: INTERNAL_V1_HEADERS }
    );
    return data;
  }

  /**
   * GET `/api/detection_engine/rules?id=` — by saved-object id (must be a UUID).
   * Query schema: x-pack/solutions/security/plugins/security_solution/common/api/detection_engine/rule_management/crud/read_rule/read_rule_route.schema.yaml
   */
  async getRuleById(id: string, spaceId?: string): Promise<DetectionRule> {
    const { data } = await this.options.kibanaClient.get<DetectionRule>(
      `${spacePrefix(spaceId)}/api/detection_engine/rules`,
      { params: { id }, headers: PUBLIC_HEADERS }
    );
    return data;
  }

  /** GET `/api/detection_engine/rules?rule_id=` — by signature rule id (same schema as `getRuleById`). */
  async getRuleByRuleId(ruleId: string, spaceId?: string): Promise<DetectionRule> {
    const { data } = await this.options.kibanaClient.get<DetectionRule>(
      `${spacePrefix(spaceId)}/api/detection_engine/rules`,
      { params: { rule_id: ruleId }, headers: PUBLIC_HEADERS }
    );
    return data;
  }

  /**
   * POST `/.alerts-security.alerts-*` `_search` with an `ids` query. A search
   * rather than `_mget` so it spans every backing index after rollover.
   */
  async searchAlertsByIds(
    ids: readonly string[],
    sourceFields: readonly string[]
  ): Promise<AlertSearchHit[]> {
    const { data } = await this.options.esClient.post<SearchAlertsResponse>(
      `/${ALERTS_INDEX_PATTERN}/_search`,
      {
        size: Math.min(ids.length, 10_000),
        query: { ids: { values: ids } },
        _source: sourceFields,
      },
      { params: { ignore_unavailable: "true", allow_no_indices: "true" } }
    );
    return data.hits.hits;
  }
}
