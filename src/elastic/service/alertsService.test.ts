/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { AlertsService } from "./alertsService.js";
import { createMockAlertsClient } from "../../test/helpers/mockServiceClients.js";
import type { SecurityAlert } from "../../shared/types.js";

const emptyAlertsResponse = {
  hits: { total: { value: 0 }, hits: [] },
  aggregations: {
    by_severity: { buckets: [] },
    by_rule: { buckets: [] },
    by_host: { buckets: [] },
  },
};

describe("AlertsService", () => {
  describe("getAlerts", () => {
    it("applies sane defaults (7 days, status=open, size=50)", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchAlerts).mockResolvedValueOnce(
        emptyAlertsResponse
      );

      const service = new AlertsService({ alertsClient });
      await service.getAlerts();

      expect(alertsClient.searchAlerts).toHaveBeenCalledTimes(1);
      const body = vi.mocked(alertsClient.searchAlerts).mock.calls[0][0] as {
        size: number;
        query: { bool: { must: unknown[] } };
      };

      expect(body.size).toBe(50);
      expect(body.query.bool.must).toContainEqual({
        range: { "@timestamp": { gte: "now-7d", lte: "now" } },
      });
      expect(body.query.bool.must).toContainEqual({
        term: { "kibana.alert.workflow_status": "open" },
      });
    });

    it("adds severity filter when provided", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchAlerts).mockResolvedValueOnce(
        emptyAlertsResponse
      );

      const service = new AlertsService({ alertsClient });
      await service.getAlerts({ severity: "high" });

      const body = vi.mocked(alertsClient.searchAlerts).mock.calls[0][0] as {
        query: { bool: { must: unknown[] } };
      };
      expect(body.query.bool.must).toContainEqual({
        term: { "kibana.alert.severity": "high" },
      });
    });

    it("translates a free-text `query` into a wildcard bool clause", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchAlerts).mockResolvedValueOnce(
        emptyAlertsResponse
      );

      const service = new AlertsService({ alertsClient });
      await service.getAlerts({ query: "  Mimikatz  " });

      const body = vi.mocked(alertsClient.searchAlerts).mock.calls[0][0] as {
        query: { bool: { must: unknown[] } };
      };

      const wildcardClause = body.query.bool.must.at(-1) as {
        bool: {
          should: { wildcard: Record<string, { value: string }> }[];
          minimum_should_match: number;
        };
      };
      expect(wildcardClause.bool.minimum_should_match).toBe(1);
      const fieldsHit = wildcardClause.bool.should.map(
        (c) => Object.keys(c.wildcard)[0]
      );
      expect(fieldsHit).toContain("kibana.alert.rule.name");
      expect(wildcardClause.bool.should[0].wildcard["kibana.alert.rule.name"].value).toBe(
        "*mimikatz*"
      );
    });

    it("ANDs multiple terms in a free-text query", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchAlerts).mockResolvedValueOnce(
        emptyAlertsResponse
      );

      const service = new AlertsService({ alertsClient });
      await service.getAlerts({ query: "ransom kill" });

      const body = vi.mocked(alertsClient.searchAlerts).mock.calls[0][0] as {
        query: { bool: { must: unknown[] } };
      };
      const last = body.query.bool.must.at(-1) as {
        bool: { should: unknown[]; minimum_should_match: number };
      };
      expect(last.bool.should).toHaveLength(2);
    });

    it("passes status=undefined through without adding a workflow filter", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchAlerts).mockResolvedValueOnce(
        emptyAlertsResponse
      );

      const service = new AlertsService({ alertsClient });
      await service.getAlerts({ status: "" });

      const body = vi.mocked(alertsClient.searchAlerts).mock.calls[0][0] as {
        query: { bool: { must: unknown[] } };
      };
      const hasStatus = body.query.bool.must.some(
        (c: unknown) =>
          typeof c === "object" &&
          c !== null &&
          "term" in (c as Record<string, unknown>) &&
          "kibana.alert.workflow_status" in
            ((c as { term: Record<string, unknown> }).term ?? {})
      );
      expect(hasStatus).toBe(false);
    });

    it("ignores a whitespace-only `query` (no wildcard clause emitted)", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchAlerts).mockResolvedValueOnce(
        emptyAlertsResponse
      );

      const service = new AlertsService({ alertsClient });
      await service.getAlerts({ query: "   " });

      const body = vi.mocked(alertsClient.searchAlerts).mock.calls[0][0] as {
        query: { bool: { must: unknown[] } };
      };
      // Only the time-range and workflow_status filters — no wildcard clause.
      expect(body.query.bool.must).toHaveLength(2);
    });

    it("returns empty aggregations when the ES response has no aggregations key", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchAlerts).mockResolvedValueOnce({
        hits: { total: { value: 0 }, hits: [] },
      });

      const service = new AlertsService({ alertsClient });
      const out = await service.getAlerts();

      expect(out).toEqual({
        total: 0,
        bySeverity: {},
        byRule: [],
        byHost: [],
        alerts: [],
      });
    });

    it("normalises aggregations into the AlertSummary shape", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchAlerts).mockResolvedValueOnce({
        hits: { total: { value: 2 }, hits: [] },
        aggregations: {
          by_severity: {
            buckets: [
              { key: "high", doc_count: 1 },
              { key: "low", doc_count: 1 },
            ],
          },
          by_rule: { buckets: [{ key: "R", doc_count: 2 }] },
          by_host: { buckets: [{ key: "h1", doc_count: 2 }] },
        },
      });

      const service = new AlertsService({ alertsClient });
      const out = await service.getAlerts();

      expect(out).toEqual({
        total: 2,
        bySeverity: { high: 1, low: 1 },
        byRule: [{ name: "R", count: 2 }],
        byHost: [{ name: "h1", count: 2 }],
        alerts: [],
      });
    });
  });

  describe("getAlertContext", () => {
    const baseAlert = (overrides?: Partial<SecurityAlert["_source"]>): SecurityAlert => ({
      _id: "a1",
      _index: ".alerts-security.alerts-default",
      _source: {
        "@timestamp": "2024-01-01T00:00:00Z",
        "kibana.alert.uuid": "u",
        "kibana.alert.rule.name": "R",
        "kibana.alert.rule.uuid": "r",
        "kibana.alert.severity": "high",
        "kibana.alert.risk_score": 75,
        "kibana.alert.workflow_status": "open",
        "kibana.alert.reason": "x",
        host: { name: "h1" },
        agent: { id: "agent-1" },
        ...overrides,
      },
    });

    it("returns empty arrays when host.name is missing", async () => {
      const alertsClient = createMockAlertsClient();
      const alert = baseAlert({ host: undefined, agent: undefined });

      const service = new AlertsService({ alertsClient });
      const out = await service.getAlertContext("a1", alert);

      expect(out).toEqual({
        processEvents: [],
        networkEvents: [],
        relatedAlerts: [],
      });
      expect(alertsClient.searchProcessEvents).not.toHaveBeenCalled();
      expect(alertsClient.searchNetworkEvents).not.toHaveBeenCalled();
      expect(alertsClient.searchAlerts).not.toHaveBeenCalled();
    });

    it("fans out parallel searches with a ±5 minute window", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchProcessEvents).mockResolvedValue({
        hits: { total: { value: 0 }, hits: [{ _source: { event: "p" } as never }] },
      });
      vi.mocked(alertsClient.searchNetworkEvents).mockResolvedValue({
        hits: { total: { value: 0 }, hits: [{ _source: { event: "n" } as never }] },
      });
      vi.mocked(alertsClient.searchAlerts).mockResolvedValue({
        hits: { total: { value: 0 }, hits: [] },
      });

      const service = new AlertsService({ alertsClient });
      const out = await service.getAlertContext("a1", baseAlert());

      expect(out.processEvents).toEqual([{ event: "p" }]);
      expect(out.networkEvents).toEqual([{ event: "n" }]);
      expect(out.relatedAlerts).toEqual([]);

      const procBody = vi.mocked(alertsClient.searchProcessEvents).mock
        .calls[0][0] as {
        query: {
          bool: {
            must: { range?: { "@timestamp": { gte: string; lte: string } } }[];
          };
        };
      };
      const range = procBody.query.bool.must[0].range!["@timestamp"];
      expect(range.gte).toBe("2023-12-31T23:55:00.000Z");
      expect(range.lte).toBe("2024-01-01T00:05:00.000Z");
    });

    it("excludes the focal alert from related-alert results via must_not", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.searchProcessEvents).mockResolvedValue({
        hits: { total: { value: 0 }, hits: [] },
      });
      vi.mocked(alertsClient.searchNetworkEvents).mockResolvedValue({
        hits: { total: { value: 0 }, hits: [] },
      });
      vi.mocked(alertsClient.searchAlerts).mockResolvedValue({
        hits: { total: { value: 0 }, hits: [] },
      });

      const service = new AlertsService({ alertsClient });
      await service.getAlertContext("a1", baseAlert());

      const body = vi.mocked(alertsClient.searchAlerts).mock.calls[0][0] as {
        query: { bool: { must_not: { term: Record<string, unknown> }[] } };
      };
      expect(body.query.bool.must_not).toEqual([{ term: { _id: "a1" } }]);
    });
  });

  describe("acknowledgeAlert / acknowledgeAlerts / setAlertWorkflowStatus", () => {
    it("acknowledgeAlert delegates to the bulk path because _update does not accept wildcard indices", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.updateAlertsByQuery).mockResolvedValueOnce({
        updated: 1,
      });

      const service = new AlertsService({ alertsClient });
      await service.acknowledgeAlert("a1");

      expect(alertsClient.updateAlert).not.toHaveBeenCalled();
      const body = vi.mocked(alertsClient.updateAlertsByQuery).mock.calls[0][0] as {
        query: { ids: { values: string[] } };
        script: { params: { status: string } };
      };
      expect(body.query).toEqual({ ids: { values: ["a1"] } });
      expect(body.script.params).toEqual({ status: "acknowledged" });
    });

    it("acknowledgeAlerts uses _update_by_query with an ids filter and returns the count", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.updateAlertsByQuery).mockResolvedValueOnce({
        updated: 3,
      });

      const service = new AlertsService({ alertsClient });
      const out = await service.acknowledgeAlerts(["a", "b", "c"]);

      expect(out).toEqual({ updated: 3 });
      const body = vi.mocked(alertsClient.updateAlertsByQuery).mock.calls[0][0] as {
        query: { ids: { values: string[] } };
        script: { source: string; lang: string; params: { status: string } };
      };
      expect(body.query).toEqual({ ids: { values: ["a", "b", "c"] } });
      expect(body.script.lang).toBe("painless");
      expect(body.script.source).toContain("params.status");
      expect(body.script.params).toEqual({ status: "acknowledged" });
    });

    it("setAlertWorkflowStatus passes the chosen status as a script param", async () => {
      const alertsClient = createMockAlertsClient();
      vi.mocked(alertsClient.updateAlertsByQuery).mockResolvedValueOnce({
        updated: 2,
      });

      const service = new AlertsService({ alertsClient });
      const out = await service.setAlertWorkflowStatus(["a", "b"], "open");

      expect(out).toEqual({ updated: 2 });
      const body = vi.mocked(alertsClient.updateAlertsByQuery).mock.calls[0][0] as {
        script: { params: { status: string } };
      };
      expect(body.script.params).toEqual({ status: "open" });
    });

    it("setAlertWorkflowStatus short-circuits on an empty id list", async () => {
      const alertsClient = createMockAlertsClient();
      const service = new AlertsService({ alertsClient });

      const out = await service.setAlertWorkflowStatus([], "closed");

      expect(out).toEqual({ updated: 0 });
      expect(alertsClient.updateAlertsByQuery).not.toHaveBeenCalled();
    });
  });
});
