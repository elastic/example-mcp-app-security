/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { RulesService } from "./rulesService.js";
import { createMockRulesClient } from "../../test/helpers/mockServiceClients.js";

const emptyFind = { data: [], total: 0, page: 1, perPage: 20 };

describe("RulesService", () => {
  describe("findRules", () => {
    it("applies sane defaults (page=1, per_page=20, sort=updated_at desc)", async () => {
      const rulesClient = createMockRulesClient();
      vi.mocked(rulesClient.findRules).mockResolvedValueOnce(emptyFind);

      const service = new RulesService({ rulesClient });
      await service.findRules({});

      expect(rulesClient.findRules).toHaveBeenCalledWith({
        page: "1",
        per_page: "20",
        sort_field: "updated_at",
        sort_order: "desc",
      });
    });

    it("forwards a filter when provided and stringifies pagination", async () => {
      const rulesClient = createMockRulesClient();
      vi.mocked(rulesClient.findRules).mockResolvedValueOnce(emptyFind);

      const service = new RulesService({ rulesClient });
      await service.findRules({
        filter: 'alert.attributes.tags:"x"',
        page: 3,
        perPage: 50,
      });

      expect(rulesClient.findRules).toHaveBeenCalledWith({
        page: "3",
        per_page: "50",
        sort_field: "updated_at",
        sort_order: "desc",
        filter: 'alert.attributes.tags:"x"',
      });
    });
  });

  it("getRule / createRule / deleteRule delegate to the client", async () => {
    const rulesClient = createMockRulesClient();
    vi.mocked(rulesClient.getRule).mockResolvedValueOnce({} as never);
    vi.mocked(rulesClient.createRule).mockResolvedValueOnce({} as never);
    vi.mocked(rulesClient.deleteRule).mockResolvedValueOnce(undefined);

    const service = new RulesService({ rulesClient });
    await service.getRule("r1");
    await service.createRule({ name: "n" });
    await service.deleteRule("r1");

    expect(rulesClient.getRule).toHaveBeenCalledWith("r1");
    expect(rulesClient.createRule).toHaveBeenCalledWith({ name: "n" });
    expect(rulesClient.deleteRule).toHaveBeenCalledWith("r1");
  });

  it("patchRule injects the id into the patch body", async () => {
    const rulesClient = createMockRulesClient();
    vi.mocked(rulesClient.patchRule).mockResolvedValueOnce({} as never);

    const service = new RulesService({ rulesClient });
    await service.patchRule("r1", { enabled: true });

    expect(rulesClient.patchRule).toHaveBeenCalledWith({
      id: "r1",
      enabled: true,
    });
  });

  it("toggleRule patches `enabled` only", async () => {
    const rulesClient = createMockRulesClient();
    vi.mocked(rulesClient.patchRule).mockResolvedValueOnce({} as never);

    const service = new RulesService({ rulesClient });
    await service.toggleRule("r1", false);

    expect(rulesClient.patchRule).toHaveBeenCalledWith({
      id: "r1",
      enabled: false,
    });
  });

  it("bulkAction wraps the action + ids", async () => {
    const rulesClient = createMockRulesClient();
    vi.mocked(rulesClient.bulkAction).mockResolvedValueOnce({});

    const service = new RulesService({ rulesClient });
    await service.bulkAction("disable", ["a", "b"]);

    expect(rulesClient.bulkAction).toHaveBeenCalledWith({
      action: "disable",
      ids: ["a", "b"],
    });
  });

  it("addException wraps the exception in the items envelope with namespace + type defaults", async () => {
    const rulesClient = createMockRulesClient();
    vi.mocked(rulesClient.addException).mockResolvedValueOnce({});

    const service = new RulesService({ rulesClient });
    await service.addException("r1", "L", {
      name: "Block this",
      description: "noise",
      entries: [
        { field: "host.name", operator: "included", type: "match", value: "h1" },
      ],
    });

    expect(rulesClient.addException).toHaveBeenCalledWith("r1", {
      items: [
        {
          name: "Block this",
          description: "noise",
          entries: [
            {
              field: "host.name",
              operator: "included",
              type: "match",
              value: "h1",
            },
          ],
          list_id: "L",
          namespace_type: "single",
          type: "simple",
        },
      ],
    });
  });

  it("listExceptions adds list_id + namespace_type=single", async () => {
    const rulesClient = createMockRulesClient();
    vi.mocked(rulesClient.listExceptions).mockResolvedValueOnce(emptyFind);

    const service = new RulesService({ rulesClient });
    await service.listExceptions("L");

    expect(rulesClient.listExceptions).toHaveBeenCalledWith({
      list_id: "L",
      namespace_type: "single",
    });
  });

  describe("validateQuery", () => {
    it("returns valid=true when ES|QL validation succeeds", async () => {
      const rulesClient = createMockRulesClient();
      vi.mocked(rulesClient.validateEsql).mockResolvedValueOnce({});

      const service = new RulesService({ rulesClient });
      const out = await service.validateQuery("FROM x", "esql");

      expect(out).toEqual({ valid: true });
      expect(rulesClient.validateEsql).toHaveBeenCalledWith("FROM x");
      expect(rulesClient.validateKqlOrEql).not.toHaveBeenCalled();
    });

    it("returns valid=false with the error message when ES|QL validation throws", async () => {
      const rulesClient = createMockRulesClient();
      vi.mocked(rulesClient.validateEsql).mockRejectedValueOnce(
        new Error("syntax")
      );

      const service = new RulesService({ rulesClient });
      const out = await service.validateQuery("FROM x", "esql");

      expect(out).toEqual({ valid: false, error: "syntax" });
    });

    it("wraps an EQL query in `{ eql: { query } }`", async () => {
      const rulesClient = createMockRulesClient();
      vi.mocked(rulesClient.validateKqlOrEql).mockResolvedValueOnce({});

      const service = new RulesService({ rulesClient });
      await service.validateQuery("process where true", "eql");

      expect(rulesClient.validateKqlOrEql).toHaveBeenCalledWith({
        query: { eql: { query: "process where true" } },
      });
    });

    it("wraps a KQL query in `{ query_string: { query } }`", async () => {
      const rulesClient = createMockRulesClient();
      vi.mocked(rulesClient.validateKqlOrEql).mockResolvedValueOnce({});

      const service = new RulesService({ rulesClient });
      await service.validateQuery("foo:bar", "kuery");

      expect(rulesClient.validateKqlOrEql).toHaveBeenCalledWith({
        query: { query_string: { query: "foo:bar" } },
      });
    });
  });

  describe("noisyRules", () => {
    it("applies sane defaults (7 days, 20 buckets)", async () => {
      const rulesClient = createMockRulesClient();
      vi.mocked(rulesClient.searchAlertsAggregation).mockResolvedValueOnce({
        aggregations: { by_rule: { buckets: [] } },
      });

      const service = new RulesService({ rulesClient });
      await service.noisyRules({});

      const body = vi.mocked(rulesClient.searchAlertsAggregation).mock
        .calls[0][0] as {
        query: { range: { "@timestamp": { gte: string } } };
        aggs: {
          by_rule: { terms: { size: number } };
        };
      };
      expect(body.query.range["@timestamp"].gte).toBe("now-7d");
      expect(body.aggs.by_rule.terms.size).toBe(20);
    });

    it("normalises buckets into { ruleName, ruleId, alertCount }", async () => {
      const rulesClient = createMockRulesClient();
      vi.mocked(rulesClient.searchAlertsAggregation).mockResolvedValueOnce({
        aggregations: {
          by_rule: {
            buckets: [
              {
                key: "RuleA",
                doc_count: 200,
                rule_id: { buckets: [{ key: "ru-1" }] },
              },
              {
                key: "RuleB",
                doc_count: 5,
                rule_id: { buckets: [] },
              },
            ],
          },
        },
      });

      const service = new RulesService({ rulesClient });
      const out = await service.noisyRules({});

      expect(out).toEqual([
        { ruleName: "RuleA", ruleId: "ru-1", alertCount: 200 },
        { ruleName: "RuleB", ruleId: "", alertCount: 5 },
      ]);
    });
  });
});
