import { kibanaRequest } from "./client.js";
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
