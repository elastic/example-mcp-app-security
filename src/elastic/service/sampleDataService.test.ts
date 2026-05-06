/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { SampleDataService } from "./sampleDataService.js";
import {
  createMockSampleDataClient,
  createMockRulesService,
} from "../../test/helpers/mockServiceClients.js";

const TAG = "elastic-security-sample-data";

describe("SampleDataService", () => {
  describe("generateSampleData", () => {
    it("indexes events for a single scenario and reports the touched indices", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.bulkIndex).mockResolvedValue({
        items: Array.from({ length: 200 }, () => ({
          create: { _index: "logs-x", status: 201 },
        })),
        errors: false,
      });

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.generateSampleData({
        scenario: "windows-credential-theft",
        count: 5,
      });

      expect(out.scenario).toBe("windows-credential-theft");
      expect(out.indexed).toBeGreaterThan(0);
      expect(out.indices.length).toBeGreaterThan(0);
      expect(sampleDataClient.bulkIndex).toHaveBeenCalled();
      const ndjson = vi.mocked(sampleDataClient.bulkIndex).mock.calls[0][0];
      expect(ndjson).toContain('"create"');
      expect(ndjson).toContain(TAG);
    });

    it("walks the CDR cross-domain extra-events loops when count is high", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.bulkIndex).mockResolvedValue({
        items: Array.from({ length: 200 }, () => ({
          create: { _index: "x", status: 201 },
        })),
        errors: false,
      });

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.generateSampleData({
        scenario: "cdr-cross-domain",
        count: 50,
      });

      expect(out.scenario).toBe("cdr-cross-domain");
      // The extra CrowdStrike + Okta events are emitted into their respective
      // indices when count * 0.4 exceeds the seeded chain lengths.
      expect(out.indices).toEqual(
        expect.arrayContaining([
          "logs-crowdstrike.fdr-default",
          "logs-okta.system-default",
        ])
      );
    });

    it.each([
      "windows-credential-theft",
      "ransomware-kill-chain",
      "linux-persistence",
      "network-ids-threats",
      "aws-privilege-escalation",
      "okta-identity-takeover",
      "entra-id-compromise",
      "gworkspace-exfiltration",
      "crowdstrike-edr-attack",
      "cdr-cross-domain",
      "mac-endpoint-activity",
      "gcp-cloud-audit",
      "cloudflare-waf-threats",
      "github-audit-events",
      "docker-container-events",
      "kubernetes-audit",
      "messy-custom-log",
    ] as const)(
      "generates events for the %s scenario at a count high enough to walk every per-event branch",
      async (scenario) => {
        const sampleDataClient = createMockSampleDataClient();
        const rulesService = createMockRulesService();
        vi.mocked(sampleDataClient.bulkIndex).mockResolvedValue({
          items: Array.from({ length: 200 }, () => ({
            create: { _index: "x", status: 201 },
          })),
          errors: false,
        });

        const service = new SampleDataService({
          sampleDataClient,
          rulesService,
        });
        const out = await service.generateSampleData({ scenario, count: 30 });

        expect(out.scenario).toBe(scenario);
        expect(out.indices.length).toBeGreaterThan(0);
        expect(sampleDataClient.bulkIndex).toHaveBeenCalled();
      }
    );

    it("forwards a supplied ruleIdMap so generated alerts use known rule UUIDs", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.bulkIndex).mockResolvedValue({
        items: Array.from({ length: 50 }, () => ({
          create: { _index: "x", status: 201 },
        })),
        errors: false,
      });

      const service = new SampleDataService({ sampleDataClient, rulesService });
      await service.generateSampleData({
        scenario: "windows-credential-theft",
        count: 5,
        ruleIdMap: { "Credential Dumping via Mimikatz": "fixed-rule-uuid" },
      });

      const ndjson = vi.mocked(sampleDataClient.bulkIndex).mock.calls[0][0];
      expect(ndjson).toContain("fixed-rule-uuid");
    });

    it("falls back to all scenarios with `scenario: 'all'` when no scenario is given", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.bulkIndex).mockResolvedValue({
        items: [{ create: { _index: "x", status: 201 } }],
        errors: false,
      });

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.generateSampleData({ count: 1 });

      expect(out.scenario).toBe("all");
    });

    it("throws a descriptive error when bulk reports `errors: true`", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.bulkIndex).mockResolvedValueOnce({
        items: [
          {
            create: {
              _index: "x",
              status: 400,
              error: { type: "mapper_parsing_exception" },
            },
          },
        ],
        errors: true,
      });

      const service = new SampleDataService({ sampleDataClient, rulesService });

      await expect(
        service.generateSampleData({
          scenario: "windows-credential-theft",
          count: 1,
        })
      ).rejects.toThrow(/Bulk indexing had errors/);
    });
  });

  describe("cleanupSampleData", () => {
    it("issues delete-by-query against every cleanup index and sums the totals", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.deleteByQuery).mockResolvedValue({
        deleted: 2,
      });

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.cleanupSampleData();

      expect(
        vi.mocked(sampleDataClient.deleteByQuery).mock.calls.length
      ).toBeGreaterThan(5);
      expect(out.deleted).toBeGreaterThan(0);
      // All calls filter on the sample-data tag.
      for (const call of vi.mocked(sampleDataClient.deleteByQuery).mock.calls) {
        expect(call[1]).toEqual({ query: { term: { tags: TAG } } });
      }
    });

    it("swallows per-index errors and keeps going", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.deleteByQuery)
        .mockRejectedValueOnce(new Error("missing"))
        .mockResolvedValue({ deleted: 1 });

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.cleanupSampleData();

      expect(out.deleted).toBeGreaterThan(0);
    });
  });

  describe("checkExistingData", () => {
    it("returns zeros when nothing matches", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.searchAlertsAggregation).mockResolvedValueOnce(
        {
          hits: { total: { value: 0 } },
          aggregations: { by_rule: { buckets: [] } },
        }
      );
      vi.mocked(sampleDataClient.count).mockResolvedValue({ count: 0 });
      vi.mocked(rulesService.findRules).mockResolvedValueOnce({
        data: [],
        total: 0,
        page: 1,
        perPage: 1,
      });

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.checkExistingData();

      expect(out).toEqual({
        totalDocs: 0,
        totalAlerts: 0,
        existingRules: 0,
        byScenario: {},
      });
    });

    it("aggregates events by scenario and distributes alerts proportionally", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.searchAlertsAggregation).mockResolvedValueOnce(
        {
          hits: { total: { value: 10 } },
          aggregations: { by_rule: { buckets: [] } },
        }
      );
      vi.mocked(sampleDataClient.count).mockImplementation(async (index) => {
        if (index === "logs-endpoint.events.process-default") {
          return { count: 50 };
        }
        return { count: 0 };
      });
      vi.mocked(rulesService.findRules).mockResolvedValueOnce({
        data: [{ id: "r1", name: "n" } as never],
        total: 5,
        page: 1,
        perPage: 1,
      });

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.checkExistingData();

      // The 50 events from `process-default` get attributed to every
      // scenario whose `scenarioIndices` map contains that index. Scenarios
      // that observed events should also receive a share of the total
      // alerts (≥1); other scenarios stay at 0 alerts.
      expect(out.totalAlerts).toBe(10);
      expect(out.existingRules).toBe(5);
      const withEvents = Object.values(out.byScenario).filter(
        (s) => s.events > 0
      );
      expect(withEvents.length).toBeGreaterThan(0);
      for (const s of withEvents) {
        expect(s.alerts).toBeGreaterThanOrEqual(1);
      }
    });

    it("ignores rule-lookup failures (existingRules stays 0)", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();
      vi.mocked(sampleDataClient.searchAlertsAggregation).mockResolvedValueOnce(
        {
          hits: { total: { value: 0 } },
          aggregations: { by_rule: { buckets: [] } },
        }
      );
      vi.mocked(sampleDataClient.count).mockResolvedValue({ count: 0 });
      vi.mocked(rulesService.findRules).mockRejectedValueOnce(
        new Error("auth")
      );

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.checkExistingData();

      expect(out.existingRules).toBe(0);
    });
  });

  describe("createRulesForScenario", () => {
    it("returns an empty result for scenarios with no rule definitions", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.createRulesForScenario(
        "no-such-scenario" as never
      );

      expect(out).toEqual({
        created: 0,
        existing: 0,
        ruleIds: [],
        ruleIdMap: {},
      });
      expect(rulesService.findRules).not.toHaveBeenCalled();
      expect(rulesService.createRule).not.toHaveBeenCalled();
    });

    it("reuses existing rules by name and only creates missing ones", async () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();

      // Pre-populate one of the windows-credential-theft rule names so the
      // service should report it as `existing` and not call `createRule` for it.
      vi.mocked(rulesService.findRules).mockResolvedValueOnce({
        data: [
          { id: "existing-1", name: "Credential Dumping via Mimikatz" } as never,
        ],
        total: 1,
        page: 1,
        perPage: 100,
      });
      vi.mocked(rulesService.createRule).mockResolvedValue({
        id: "new",
      } as never);

      const service = new SampleDataService({ sampleDataClient, rulesService });
      const out = await service.createRulesForScenario(
        "windows-credential-theft"
      );

      expect(out.existing).toBe(1);
      expect(out.created).toBeGreaterThan(0);
      expect(out.ruleIdMap["Credential Dumping via Mimikatz"]).toBe(
        "existing-1"
      );
      expect(rulesService.createRule).not.toHaveBeenCalledWith(
        expect.objectContaining({ name: "Credential Dumping via Mimikatz" })
      );
    });
  });

  describe("setRuleIdMap", () => {
    it("can be set without throwing", () => {
      const sampleDataClient = createMockSampleDataClient();
      const rulesService = createMockRulesService();

      const service = new SampleDataService({ sampleDataClient, rulesService });

      expect(() => service.setRuleIdMap({ A: "id-A" })).not.toThrow();
    });
  });
});
