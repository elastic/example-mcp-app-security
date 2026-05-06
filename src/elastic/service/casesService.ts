/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaCase } from "../../shared/types.js";
import type {
  CaseComment,
  CasesClient,
  FindCasesResponse,
  FindCommentsResponse,
  UserAvatar,
} from "../client/casesClient.js";

const ATTACHMENT_ENRICHMENT_LIMIT = 20;

interface CasesServiceOptions {
  readonly casesClient: CasesClient;
}

interface ListCasesOptions {
  readonly status?: string;
  readonly severity?: string;
  readonly tags?: string[];
  readonly search?: string;
  readonly page?: number;
  readonly perPage?: number;
  readonly sortField?: string;
  readonly sortOrder?: string;
}

interface CreateCaseInput {
  readonly title: string;
  readonly description: string;
  readonly tags?: string[];
  readonly severity?: string;
}

interface UpdateCaseInput {
  readonly status?: string;
  readonly severity?: string;
  readonly tags?: string[];
  readonly title?: string;
  readonly description?: string;
}

/** Domain shape for an enriched case alert attachment. */
export interface CaseAlertAttachment {
  id: string;
  index: string;
  attached_at: string;
  rule?: string;
  severity?: string;
  host?: string;
  user?: string;
  reason?: string;
}

/** Re-export so consumers can pull domain types from the service. */
export type { CaseComment, UserAvatar } from "../client/casesClient.js";

/**
 * Business logic for Kibana cases: case CRUD, comments, alert attachments,
 * and the current-user profile.
 *
 * Preserves every default and body shape from the legacy `cases.ts`:
 * `securitySolution` ownership on every write, the connector / settings
 * shape on `createCase`, the patch envelope on `updateCase`, and the
 * "first 20 attachments enriched, fail-soft per attachment" behaviour on
 * `getCaseAlerts`.
 */
export class CasesService {
  constructor(private readonly options: CasesServiceOptions) {}

  async listCases(options: ListCasesOptions): Promise<FindCasesResponse> {
    const params: Record<string, string> = {
      owner: "securitySolution",
      page: String(options.page || 1),
      perPage: String(options.perPage || 20),
      sortField: options.sortField || "createdAt",
      sortOrder: options.sortOrder || "desc",
    };

    if (options.status) params.status = options.status;
    if (options.severity) params.severity = options.severity;
    if (options.search) params.search = options.search;
    if (options.tags?.length) params.tags = options.tags.join(",");

    return this.options.casesClient.findCases(params);
  }

  getCase(caseId: string): Promise<KibanaCase> {
    return this.options.casesClient.getCase(caseId);
  }

  createCase(data: CreateCaseInput): Promise<KibanaCase> {
    return this.options.casesClient.createCase({
      title: data.title,
      description: data.description,
      tags: data.tags || [],
      severity: data.severity || "low",
      owner: "securitySolution",
      connector: { id: "none", name: "none", type: ".none", fields: null },
      settings: { syncAlerts: true },
    });
  }

  updateCase(
    caseId: string,
    version: string,
    updates: UpdateCaseInput
  ): Promise<KibanaCase[]> {
    return this.options.casesClient.updateCases({
      cases: [{ id: caseId, version, ...updates }],
    });
  }

  addComment(caseId: string, comment: string): Promise<unknown> {
    return this.options.casesClient.addComment(caseId, {
      type: "user",
      comment,
      owner: "securitySolution",
    });
  }

  attachAlert(
    caseId: string,
    alertId: string,
    alertIndex: string,
    ruleId: string,
    ruleName: string
  ): Promise<unknown> {
    return this.options.casesClient.addComment(caseId, {
      type: "alert",
      alertId,
      index: alertIndex,
      rule: { id: ruleId, name: ruleName },
      owner: "securitySolution",
    });
  }

  /**
   * Bulk-attach alerts to a case by id.
   *
   * Resolves each id via `_mget` to recover the source document (needed for
   * the rule id / name on the attachment), then attaches each found alert in
   * sequence. Per-attachment failures and the `_mget` failure itself are
   * swallowed — the case stays created and the caller learns how many of the
   * requested ids were successfully attached.
   */
  async attachAlertsByIds(
    caseId: string,
    alertIds: readonly string[]
  ): Promise<number> {
    if (alertIds.length === 0) return 0;
    let attached = 0;
    try {
      const { docs } = await this.options.casesClient.mgetAlerts(alertIds);
      for (const doc of docs) {
        if (!doc.found || !doc._source) continue;
        try {
          const ruleId = (doc._source["kibana.alert.rule.uuid"] as string) || "";
          const ruleName =
            (doc._source["kibana.alert.rule.name"] as string) || "Unknown Rule";
          await this.attachAlert(caseId, doc._id, doc._index, ruleId, ruleName);
          attached++;
        } catch {
          // skip individual alert attachment failures
        }
      }
    } catch {
      // alert lookup failed — case still created without attachments
    }
    return attached;
  }

  getCasesForAlert(
    alertId: string
  ): Promise<{ id: string; title: string }[]> {
    return this.options.casesClient.getCasesForAlert(alertId);
  }

  getComments(caseId: string): Promise<FindCommentsResponse> {
    return this.options.casesClient.getCommentsFind(caseId, {
      perPage: "100",
      sortOrder: "asc",
    });
  }

  async getUserProfile(): Promise<{ username: string; avatar: UserAvatar }> {
    const result = await this.options.casesClient.getUserProfile({
      dataPath: "avatar",
    });
    return {
      username: result.user?.username || "",
      avatar: result.data?.avatar || {},
    };
  }

  /**
   * Fetch case alert attachments and enrich the first 20 with summary
   * fields from Elasticsearch. If a per-attachment lookup fails, fall back
   * to the bare `{ id, index, attached_at }` record so a single missing
   * source document does not fail the entire request.
   */
  async getCaseAlerts(caseId: string): Promise<CaseAlertAttachment[]> {
    const attachments = await this.options.casesClient.getCaseAlerts(caseId);

    const enriched: CaseAlertAttachment[] = [];
    for (const a of attachments.slice(0, ATTACHMENT_ENRICHMENT_LIMIT)) {
      try {
        const doc = await this.options.casesClient.getAlertDocument(
          a.index,
          a.id
        );
        const src = doc._source;
        enriched.push({
          id: a.id,
          index: a.index,
          attached_at: a.attached_at,
          rule: src["kibana.alert.rule.name"] as string | undefined,
          severity: src["kibana.alert.severity"] as string | undefined,
          host: (src.host as Record<string, unknown>)?.name as
            | string
            | undefined,
          user: (src.user as Record<string, unknown>)?.name as
            | string
            | undefined,
          reason: src["kibana.alert.reason"] as string | undefined,
        });
      } catch {
        enriched.push({
          id: a.id,
          index: a.index,
          attached_at: a.attached_at,
        });
      }
    }
    return enriched;
  }
}
