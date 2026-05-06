/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { DetectionRule, RuleException } from "../../shared/types.js";
import type { FindResponse, RulesClient } from "../client/rulesClient.js";

interface RulesServiceOptions {
  readonly rulesClient: RulesClient;
}

interface FindRulesOptions {
  readonly filter?: string;
  readonly page?: number;
  readonly perPage?: number;
  readonly sortField?: string;
  readonly sortOrder?: string;
}

interface AddExceptionInput {
  readonly name: string;
  readonly description?: string;
  readonly entries: {
    field: string;
    operator: string;
    type: string;
    value: string | string[];
  }[];
}

/**
 * Business logic for detection-rule management.
 *
 * Preserves every default and body shape from the legacy `rules.ts`:
 * pagination defaults, the `addException` `items` envelope, the
 * try/catch in `validateQuery`, and the noisy-rules aggregation body.
 */
export class RulesService {
  constructor(private readonly options: RulesServiceOptions) {}

  async findRules(
    options: FindRulesOptions
  ): Promise<FindResponse<DetectionRule>> {
    const params: Record<string, string> = {
      page: String(options.page || 1),
      per_page: String(options.perPage || 20),
      sort_field: options.sortField || "updated_at",
      sort_order: options.sortOrder || "desc",
    };
    if (options.filter) params.filter = options.filter;

    return this.options.rulesClient.findRules(params);
  }

  getRule(id: string): Promise<DetectionRule> {
    return this.options.rulesClient.getRule(id);
  }

  createRule(rule: Record<string, unknown>): Promise<DetectionRule> {
    return this.options.rulesClient.createRule(rule);
  }

  patchRule(
    id: string,
    updates: Record<string, unknown>
  ): Promise<DetectionRule> {
    return this.options.rulesClient.patchRule({ id, ...updates });
  }

  deleteRule(id: string): Promise<void> {
    return this.options.rulesClient.deleteRule(id);
  }

  toggleRule(id: string, enabled: boolean): Promise<DetectionRule> {
    return this.patchRule(id, { enabled });
  }

  bulkAction(
    action: "enable" | "disable" | "delete" | "duplicate",
    ids: string[]
  ): Promise<unknown> {
    return this.options.rulesClient.bulkAction({ action, ids });
  }

  addException(
    ruleId: string,
    listId: string,
    exception: AddExceptionInput
  ): Promise<unknown> {
    return this.options.rulesClient.addException(ruleId, {
      items: [
        {
          ...exception,
          list_id: listId,
          namespace_type: "single",
          type: "simple",
        },
      ],
    });
  }

  listExceptions(
    listId: string
  ): Promise<{ data: RuleException[]; total: number }> {
    return this.options.rulesClient.listExceptions({
      list_id: listId,
      namespace_type: "single",
    });
  }

  async validateQuery(
    query: string,
    language: string
  ): Promise<{ valid: boolean; error?: string }> {
    try {
      if (language === "esql") {
        await this.options.rulesClient.validateEsql(query);
      } else {
        await this.options.rulesClient.validateKqlOrEql({
          query:
            language === "eql"
              ? { eql: { query } }
              : { query_string: { query } },
        });
      }
      return { valid: true };
    } catch (e) {
      return { valid: false, error: e instanceof Error ? e.message : String(e) };
    }
  }

  async noisyRules(options: {
    days?: number;
    limit?: number;
  }): Promise<{ ruleName: string; ruleId: string; alertCount: number }[]> {
    const { days = 7, limit = 20 } = options;
    const result = await this.options.rulesClient.searchAlertsAggregation({
      size: 0,
      query: { range: { "@timestamp": { gte: `now-${days}d` } } },
      aggs: {
        by_rule: {
          terms: {
            field: "kibana.alert.rule.name",
            size: limit,
            order: { _count: "desc" },
          },
          aggs: {
            rule_id: { terms: { field: "kibana.alert.rule.uuid", size: 1 } },
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
}
