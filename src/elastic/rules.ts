/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { esRequest, kibanaRequest } from "./client.js";
import type { DetectionRule, RuleException } from "../shared/types.js";

const RULES_API = "/api/detection_engine/rules";
const API_VERSION = "2023-10-31";

export async function findRules(options: {
  filter?: string;
  page?: number;
  perPage?: number;
  sortField?: string;
  sortOrder?: string;
}): Promise<{ data: DetectionRule[]; total: number; page: number; perPage: number }> {
  const params: Record<string, string> = {
    page: String(options.page || 1),
    per_page: String(options.perPage || 20),
    sort_field: options.sortField || "updated_at",
    sort_order: options.sortOrder || "desc",
  };
  if (options.filter) params.filter = options.filter;

  return kibanaRequest<{ data: DetectionRule[]; total: number; page: number; perPage: number }>(
    `${RULES_API}/_find`,
    { params, apiVersion: API_VERSION }
  );
}

export async function getRule(id: string): Promise<DetectionRule> {
  return kibanaRequest<DetectionRule>(RULES_API, {
    params: { id },
    apiVersion: API_VERSION,
  });
}

export async function createRule(rule: Record<string, unknown>): Promise<DetectionRule> {
  return kibanaRequest<DetectionRule>(RULES_API, { body: rule, apiVersion: API_VERSION });
}

export async function patchRule(
  id: string,
  updates: Record<string, unknown>
): Promise<DetectionRule> {
  return kibanaRequest<DetectionRule>(RULES_API, {
    method: "PATCH",
    apiVersion: API_VERSION,
    body: { id, ...updates },
  });
}

export async function deleteRule(id: string): Promise<void> {
  await kibanaRequest(RULES_API, {
    method: "DELETE",
    apiVersion: API_VERSION,
    params: { id },
  });
}

export async function toggleRule(id: string, enabled: boolean): Promise<DetectionRule> {
  return patchRule(id, { enabled });
}

export async function bulkAction(
  action: "enable" | "disable" | "delete" | "duplicate",
  ids: string[]
): Promise<unknown> {
  return kibanaRequest(`${RULES_API}/_bulk_action`, {
    body: { action, ids },
    apiVersion: "2023-10-31",
  });
}

export async function addException(
  ruleId: string,
  listId: string,
  exception: {
    name: string;
    description?: string;
    entries: { field: string; operator: string; type: string; value: string | string[] }[];
  }
): Promise<unknown> {
  return kibanaRequest(`${RULES_API}/${ruleId}/exceptions`, {
    apiVersion: API_VERSION,
    body: {
      items: [
        {
          ...exception,
          list_id: listId,
          namespace_type: "single",
          type: "simple",
        },
      ],
    },
  });
}

export async function listExceptions(listId: string): Promise<{
  data: RuleException[];
  total: number;
}> {
  return kibanaRequest<{ data: RuleException[]; total: number }>(
    "/api/exception_lists/items/_find",
    { params: { list_id: listId, namespace_type: "single" }, apiVersion: API_VERSION }
  );
}

export async function validateQuery(
  query: string,
  language: string
): Promise<{ valid: boolean; error?: string }> {
  try {
    if (language === "esql") {
      await esRequest("/_query", {
        body: { query, fetch_size: 0 },
      });
    } else {
      await esRequest("/.alerts-security.alerts-*/_validate/query", {
        body: {
          query:
            language === "eql"
              ? { eql: { query } }
              : { query_string: { query } },
        },
      });
    }
    return { valid: true };
  } catch (e) {
    return { valid: false, error: e instanceof Error ? e.message : String(e) };
  }
}

export async function noisyRules(options: {
  days?: number;
  limit?: number;
}): Promise<{ ruleName: string; ruleId: string; alertCount: number }[]> {
  const { days = 7, limit = 20 } = options;
  const result = await esRequest<{
    aggregations: {
      by_rule: {
        buckets: { key: string; doc_count: number; rule_id: { buckets: { key: string }[] } }[];
      };
    };
  }>("/.alerts-security.alerts-*/_search", {
    body: {
      size: 0,
      query: {
        range: { "@timestamp": { gte: `now-${days}d` } },
      },
      aggs: {
        by_rule: {
          terms: { field: "kibana.alert.rule.name", size: limit, order: { _count: "desc" } },
          aggs: {
            rule_id: { terms: { field: "kibana.alert.rule.uuid", size: 1 } },
          },
        },
      },
    },
  });

  return result.aggregations.by_rule.buckets.map((b) => ({
    ruleName: b.key,
    ruleId: b.rule_id.buckets[0]?.key || "",
    alertCount: b.doc_count,
  }));
}
