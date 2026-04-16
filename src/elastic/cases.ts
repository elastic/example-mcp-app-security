/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { kibanaRequest, esRequest } from "./client.js";
import type { KibanaCase } from "../shared/types.js";

const CASES_API = "/api/cases";
const API_VERSION = "2023-10-31";

export async function listCases(options: {
  status?: string;
  severity?: string;
  tags?: string[];
  search?: string;
  page?: number;
  perPage?: number;
  sortField?: string;
  sortOrder?: string;
}): Promise<{ cases: KibanaCase[]; total: number; page: number; perPage: number }> {
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

  return kibanaRequest<{ cases: KibanaCase[]; total: number; page: number; perPage: number }>(
    `${CASES_API}/_find`,
    { params, apiVersion: API_VERSION }
  );
}

export async function getCase(caseId: string): Promise<KibanaCase> {
  return kibanaRequest<KibanaCase>(`${CASES_API}/${caseId}`, { apiVersion: API_VERSION });
}

export async function createCase(data: {
  title: string;
  description: string;
  tags?: string[];
  severity?: string;
}): Promise<KibanaCase> {
  return kibanaRequest<KibanaCase>(CASES_API, {
    apiVersion: API_VERSION,
    body: {
      title: data.title,
      description: data.description,
      tags: data.tags || [],
      severity: data.severity || "low",
      owner: "securitySolution",
      connector: { id: "none", name: "none", type: ".none", fields: null },
      settings: { syncAlerts: true },
    },
  });
}

export async function updateCase(
  caseId: string,
  version: string,
  updates: { status?: string; severity?: string; tags?: string[]; title?: string; description?: string }
): Promise<KibanaCase[]> {
  return kibanaRequest<KibanaCase[]>(CASES_API, {
    method: "PATCH",
    apiVersion: API_VERSION,
    body: {
      cases: [{ id: caseId, version, ...updates }],
    },
  });
}

export async function addComment(caseId: string, comment: string): Promise<unknown> {
  return kibanaRequest(`${CASES_API}/${caseId}/comments`, {
    apiVersion: API_VERSION,
    body: {
      type: "user",
      comment,
      owner: "securitySolution",
    },
  });
}

export async function attachAlert(
  caseId: string,
  alertId: string,
  alertIndex: string,
  ruleId: string,
  ruleName: string
): Promise<unknown> {
  return kibanaRequest(`${CASES_API}/${caseId}/comments`, {
    apiVersion: API_VERSION,
    body: {
      type: "alert",
      alertId,
      index: alertIndex,
      rule: { id: ruleId, name: ruleName },
      owner: "securitySolution",
    },
  });
}

export async function getCasesForAlert(alertId: string): Promise<{ id: string; title: string }[]> {
  return kibanaRequest<{ id: string; title: string }[]>(
    `${CASES_API}/alerts/${alertId}`,
    { apiVersion: API_VERSION }
  );
}

export interface CaseComment {
  id: string;
  type: string;
  comment?: string;
  created_at: string;
  created_by: { username?: string; full_name?: string; email?: string | null };
  updated_at?: string | null;
}

export async function getComments(caseId: string): Promise<{ comments: CaseComment[]; total: number }> {
  return kibanaRequest<{ comments: CaseComment[]; total: number }>(
    `${CASES_API}/${caseId}/comments/_find`,
    { params: { perPage: "100", sortOrder: "asc" }, apiVersion: API_VERSION }
  );
}

export interface UserAvatar {
  color?: string;
  initials?: string;
  imageUrl?: string;
}

export async function getUserProfile(): Promise<{ username: string; avatar: UserAvatar }> {
  const result = await kibanaRequest<{
    user: { username: string };
    data?: { avatar?: UserAvatar };
  }>("/internal/security/user_profile", {
    params: { dataPath: "avatar" },
  });
  return {
    username: result.user?.username || "",
    avatar: result.data?.avatar || {},
  };
}

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

export async function getCaseAlerts(caseId: string): Promise<CaseAlertAttachment[]> {
  const attachments = await kibanaRequest<{ id: string; index: string; attached_at: string }[]>(
    `${CASES_API}/${caseId}/alerts`,
    { apiVersion: API_VERSION }
  );

  const enriched: CaseAlertAttachment[] = [];
  for (const a of attachments.slice(0, 20)) {
    try {
      const doc = await esRequest<{ _source: Record<string, unknown> }>(`/${a.index}/_doc/${a.id}`);
      const src = doc._source;
      enriched.push({
        id: a.id,
        index: a.index,
        attached_at: a.attached_at,
        rule: src["kibana.alert.rule.name"] as string | undefined,
        severity: src["kibana.alert.severity"] as string | undefined,
        host: (src.host as Record<string, unknown>)?.name as string | undefined,
        user: (src.user as Record<string, unknown>)?.name as string | undefined,
        reason: src["kibana.alert.reason"] as string | undefined,
      });
    } catch {
      enriched.push({ id: a.id, index: a.index, attached_at: a.attached_at });
    }
  }
  return enriched;
}
