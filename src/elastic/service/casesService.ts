/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { KibanaCase } from "../../shared/types.js";
import { createStderrLogger, type Logger } from "../../shared/logger.js";
import type {
  CaseComment,
  CasesClient,
  FindCasesResponse,
  FindCommentsResponse,
  UserAvatar,
} from "../client/casesClient.js";

const ATTACHMENT_ENRICHMENT_LIMIT = 20;
const ALERTS_INDEX = ".alerts-security.alerts-default";

interface CasesServiceOptions {
  readonly casesClient: CasesClient;
  readonly logger?: Pick<Logger, "warn">;
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
 * "first 20 attachments enriched, fail-soft" behaviour on `getCaseAlerts`.
 */
export class CasesService {
  private readonly logger: Pick<Logger, "warn">;

  constructor(private readonly options: CasesServiceOptions) {
    this.logger = options.logger ?? createStderrLogger(["cases"]);
  }

  async listCases(options: ListCasesOptions): Promise<FindCasesResponse> {
    // camelCase param names verified against `CasesFindRequestRt` in
    // cases/common/types/api/case/v1.ts (page, perPage, sortField, sortOrder)
    // — unlike the security_ai_assistant/rules APIs, the cases API expects
    // camelCase here, not snake_case. See #46 postmortem in CONTRIBUTING.md.
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
   * Resolves the ids via a single `ids`-query search over `ALERTS_INDEX` to
   * recover the source documents (needed for the rule id / name on the
   * attachment), then attaches each found alert in sequence. Per-attachment
   * failures are swallowed and a failed lookup is logged — the case stays
   * created and the caller learns how many of the requested ids were
   * successfully attached.
   */
  async attachAlertsByIds(
    caseId: string,
    alertIds: readonly string[]
  ): Promise<number> {
    const uniqueIds = [...new Set(alertIds)];
    if (uniqueIds.length === 0) return 0;
    let attached = 0;
    try {
      const hits = await this.options.casesClient.searchAlertsByIds(
        [ALERTS_INDEX],
        uniqueIds
      );
      for (const hit of hits) {
        if (!hit._source) continue;
        try {
          const ruleId = (hit._source["kibana.alert.rule.uuid"] as string) || "";
          const ruleName =
            (hit._source["kibana.alert.rule.name"] as string) || "Unknown Rule";
          await this.attachAlert(caseId, hit._id, hit._index, ruleId, ruleName);
          attached++;
        } catch {
          // skip individual alert attachment failures
        }
      }
    } catch (e) {
      // alert lookup failed — case still created without attachments
      this.logger.warn(
        `attachAlertsByIds: alert lookup failed for case ${caseId}: ` +
          (e instanceof Error ? e.message : String(e))
      );
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
   * fields from Elasticsearch via a single `ids`-query search over the
   * attachments' recorded indices. Alerts the search does not return fall
   * back to the bare `{ id, index, attached_at }` record so a missing
   * source document does not fail the entire request.
   */
  async getCaseAlerts(caseId: string): Promise<CaseAlertAttachment[]> {
    const attachments = await this.options.casesClient.getCaseAlerts(caseId);
    const toEnrich = attachments.slice(0, ATTACHMENT_ENRICHMENT_LIMIT);

    const sourcesById = new Map<string, Record<string, unknown>>();
    if (toEnrich.length > 0) {
      // Attachments may record either the alerts alias or a concrete backing
      // index, depending on who attached the alert — a multi-index search
      // accepts both.
      const indices = [
        ...new Set(toEnrich.map((a) => a.index).filter(Boolean)),
      ];
      const ids = [...new Set(toEnrich.map((a) => a.id))];
      try {
        const hits = await this.options.casesClient.searchAlertsByIds(
          indices.length > 0 ? indices : [ALERTS_INDEX],
          ids
        );
        for (const hit of hits) {
          if (hit._source) sourcesById.set(hit._id, hit._source);
        }
      } catch (e) {
        this.logger.warn(
          `getCaseAlerts: failed to enrich ${ids.length} alert attachment(s) for case ${caseId}: ` +
            (e instanceof Error ? e.message : String(e))
        );
      }
    }

    return toEnrich.map((a) => {
      const src = sourcesById.get(a.id);
      if (!src) {
        return { id: a.id, index: a.index, attached_at: a.attached_at };
      }
      return {
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
      };
    });
  }
}
