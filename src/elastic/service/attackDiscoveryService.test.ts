/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { AttackDiscoveryService } from "./attackDiscoveryService.js";
import { createMockAttackDiscoveryClient } from "../../test/helpers/mockServiceClients.js";
import type { AttackDiscovery } from "../client/attackDiscoveryClient.js";

const SCHEDULED_INDEX = ".alerts-security.attack.discovery.alerts-default";
const ADHOC_INDEX = ".adhoc.alerts-security.attack.discovery.alerts-default";

function envelope(columnNames: string[], values: unknown[][]) {
  return {
    columns: columnNames.map((name) => ({ name, type: "keyword" })),
    values,
  };
}

const DISCOVERY_COLUMNS = [
  "_id",
  "@timestamp",
  "kibana.alert.rule.execution.uuid",
  "kibana.alert.attack_discovery.title",
  "kibana.alert.attack_discovery.summary_markdown",
  "kibana.alert.attack_discovery.details_markdown",
  "kibana.alert.attack_discovery.mitre_attack_tactics",
  "kibana.alert.attack_discovery.alert_ids",
  "kibana.alert.attack_discovery.alerts_context_count",
  "kibana.alert.risk_score",
];

describe("AttackDiscoveryService", () => {
  describe("getDiscoveries", () => {
    it("returns an empty summary when both queries fail", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.runEsql).mockRejectedValue(
        new Error("missing")
      );

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.getDiscoveries({});

      expect(out).toEqual({ total: 0, discoveries: [] });
    });

    it("falls back to per-index queries when the multi-index query fails", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.runEsql)
        .mockRejectedValueOnce(new Error("multi-fails"))
        .mockResolvedValueOnce(envelope(DISCOVERY_COLUMNS, [makeRow("d1")]))
        .mockResolvedValueOnce(envelope(DISCOVERY_COLUMNS, [makeRow("d2")]));

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.getDiscoveries({});

      expect(out.total).toBe(2);
      expect(out.discoveries.map((d) => d.id)).toEqual(["d1", "d2"]);

      const queries = vi
        .mocked(attackDiscoveryClient.runEsql)
        .mock.calls.map((c) => c[0]);
      expect(queries[0]).toContain(
        `${SCHEDULED_INDEX}, ${ADHOC_INDEX} METADATA _id`
      );
      expect(queries[1]).toContain(`FROM ${SCHEDULED_INDEX} METADATA _id`);
      expect(queries[1]).not.toContain(ADHOC_INDEX);
      expect(queries[2]).toContain(`FROM ${ADHOC_INDEX} METADATA _id`);
    });

    it("normalises an ES|QL row into the AttackDiscovery domain shape", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(DISCOVERY_COLUMNS, [
          [
            "d1",
            "2024-01-01T00:00:00Z",
            "exec-1",
            "T",
            "S",
            "D",
            ["TA0001"],
            ["a1", "a2"],
            "5",
            "73",
          ],
        ])
      );

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.getDiscoveries({});

      expect(out.discoveries[0]).toEqual({
        id: "d1",
        timestamp: "2024-01-01T00:00:00Z",
        executionUuid: "exec-1",
        title: "T",
        summaryMarkdown: "S",
        detailsMarkdown: "D",
        mitreTactics: ["TA0001"],
        alertIds: ["a1", "a2"],
        alertsContextCount: 5,
        riskScore: 73,
      });
    });
  });

  describe("acknowledgeDiscoveries", () => {
    it("sums updated counts across the scheduled + adhoc indices", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.acknowledgeOnIndex)
        .mockResolvedValueOnce({ updated: 3 })
        .mockResolvedValueOnce({ updated: 1 });

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.acknowledgeDiscoveries(["d1", "d2"]);

      expect(out).toEqual({ updated: 4 });
      expect(attackDiscoveryClient.acknowledgeOnIndex).toHaveBeenNthCalledWith(
        1,
        SCHEDULED_INDEX,
        expect.objectContaining({
          query: { ids: { values: ["d1", "d2"] } },
        })
      );
      expect(attackDiscoveryClient.acknowledgeOnIndex).toHaveBeenNthCalledWith(
        2,
        ADHOC_INDEX,
        expect.anything()
      );
    });

    it("swallows per-index errors", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.acknowledgeOnIndex)
        .mockRejectedValueOnce(new Error("missing"))
        .mockResolvedValueOnce({ updated: 2 });

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.acknowledgeDiscoveries(["d1"]);

      expect(out).toEqual({ updated: 2 });
    });
  });

  describe("assessConfidence", () => {
    it("returns low-confidence stubs when there are no alert ids to look up", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      const service = new AttackDiscoveryService({ attackDiscoveryClient });

      const discovery: AttackDiscovery = {
        ...emptyDiscovery,
        id: "d1",
        alertIds: [],
      };
      const [out] = await service.assessConfidence([discovery]);

      expect(out.confidence).toBe("low");
      expect(out.signals.alertDiversity).toEqual({
        alertCount: 0,
        ruleCount: 0,
        severities: [],
      });
      expect(attackDiscoveryClient.runEsql).not.toHaveBeenCalled();
    });

    it("synthesises 'high' confidence from rich diversity, low rule frequency, and high entity risk", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      // Diversity query.
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "_id",
            "kibana.alert.rule.name",
            "kibana.alert.rule.uuid",
            "kibana.alert.severity",
            "host.name",
            "user.name",
            "agent.id",
          ],
          [
            ["a1", "RuleA", "ru1", "critical", "h1", "u1", "ag1"],
            ["a2", "RuleA", "ru1", "critical", "h1", "u1", "ag1"],
            ["a3", "RuleB", "ru2", "critical", "h1", "u1", "ag1"],
            ["a4", "RuleB", "ru2", "critical", "h1", "u1", "ag1"],
            ["a5", "RuleB", "ru2", "critical", "h1", "u1", "ag1"],
          ]
        )
      );
      // Rule-frequency query (low totals + low host counts → +1 per rule).
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          ["total", "hosts", "kibana.alert.rule.name"],
          [
            [1, 1, "RuleA"],
            [1, 1, "RuleB"],
          ]
        )
      );
      // Entity-risk query (Critical → +2 per entity).
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "host.name",
            "user.name",
            "host.risk.calculated_level",
            "host.risk.calculated_score_norm",
            "user.risk.calculated_level",
            "user.risk.calculated_score_norm",
          ],
          [["h1", "u1", "Critical", 95, "Critical", 95]]
        )
      );

      const discovery: AttackDiscovery = {
        ...emptyDiscovery,
        id: "d1",
        alertIds: ["a1", "a2", "a3", "a4", "a5"],
      };

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const [out] = await service.assessConfidence([discovery]);

      expect(out.confidence).toBe("high");
      expect(out.signals.alertDiversity).toEqual({
        alertCount: 5,
        ruleCount: 2,
        severities: ["critical"],
      });
      expect(out.hosts).toEqual(["h1"]);
      expect(out.users).toEqual(["u1"]);
      expect(out.ruleNames).toEqual(["RuleA", "RuleB"]);
      expect(out.signals.entityRisk).toContainEqual({
        name: "h1",
        type: "host",
        riskLevel: "Critical",
        riskScore: 95,
      });
    });
  });

  describe("generateAttackDiscovery", () => {
    it("injects _id into the anonymisation fields if missing and forwards the body", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(
        attackDiscoveryClient.findAnonymizationFields
      ).mockResolvedValueOnce({ data: [] });
      vi.mocked(attackDiscoveryClient.generate).mockResolvedValueOnce({
        execution_uuid: "exec-1",
      });

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.generateAttackDiscovery({
        connectorId: "c1",
        actionTypeId: ".gen-ai",
      });

      expect(out).toEqual({ execution_uuid: "exec-1" });
      expect(attackDiscoveryClient.generate).toHaveBeenCalledTimes(1);
      const body = vi.mocked(attackDiscoveryClient.generate).mock.calls[0][0];
      expect(body.alertsIndexPattern).toBe(".alerts-security.alerts-default");
      expect(body.size).toBe(50);
      expect(body.start).toBe("now-7d");
      expect(body.end).toBe("now");
      expect(body.subAction).toBe("invokeAI");
      expect(body.apiConfig).toEqual({
        connectorId: "c1",
        actionTypeId: ".gen-ai",
      });
      const fields = body.anonymizationFields as { field: string; allowed: boolean; anonymized: boolean }[];
      const idField = fields.find((f) => f.field === "_id");
      expect(idField).toMatchObject({ allowed: true, anonymized: false });
    });

    it("forces an existing _id field to allowed/non-anonymised", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(
        attackDiscoveryClient.findAnonymizationFields
      ).mockResolvedValueOnce({
        data: [
          { field: "_id", allowed: false, anonymized: true, id: "x" },
          { field: "host.name", allowed: true, anonymized: false, id: "y" },
        ],
      });
      vi.mocked(attackDiscoveryClient.generate).mockResolvedValueOnce({
        execution_uuid: "exec-1",
      });

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      await service.generateAttackDiscovery({
        connectorId: "c1",
        actionTypeId: ".gen-ai",
      });

      const fields = vi.mocked(attackDiscoveryClient.generate).mock
        .calls[0][0].anonymizationFields as {
        field: string;
        allowed: boolean;
        anonymized: boolean;
      }[];
      const idField = fields.find((f) => f.field === "_id");
      expect(idField).toMatchObject({ allowed: true, anonymized: false });
    });
  });

  describe("getGenerations", () => {
    it("forwards only supplied params, stringifying size", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.getGenerations).mockResolvedValueOnce({});

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      await service.getGenerations({ size: 5 });

      expect(attackDiscoveryClient.getGenerations).toHaveBeenCalledWith(
        { size: "5" },
        undefined
      );
    });

    it("forwards all params when supplied", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.getGenerations).mockResolvedValueOnce({});

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      await service.getGenerations({
        size: 10,
        start: "now-1d",
        end: "now",
      });

      expect(attackDiscoveryClient.getGenerations).toHaveBeenCalledWith(
        { size: "10", start: "now-1d", end: "now" },
        undefined
      );
    });

    it("forwards namespace to the client when supplied", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.getGenerations).mockResolvedValueOnce({});

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      await service.getGenerations({ size: 5, namespace: "soc" });

      expect(attackDiscoveryClient.getGenerations).toHaveBeenCalledWith(
        { size: "5" },
        "soc"
      );
    });
  });

  describe("getDiscoveryDetail", () => {
    it("returns a stub detail when the discovery has no alert ids", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      // Only the with-replacements lookup should fire (alerts query is skipped).
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope([], [])
      );

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.getDiscoveryDetail({
        ...emptyDiscovery,
        id: "d1",
        title: "T",
        summaryMarkdown: "S",
        detailsMarkdown: "D",
      });

      expect(out.alerts).toEqual([]);
      expect(out.entityRisk).toEqual([]);
      expect(out.titleWithReplacements).toBe("T");
      expect(out.summaryWithReplacements).toBe("S");
      expect(out.detailsWithReplacements).toBe("D");
      // Only the with-replacements query fired — no alert / risk queries.
      expect(attackDiscoveryClient.runEsql).toHaveBeenCalledTimes(1);
    });

    it("normalises alert rows and aggregates entity risk", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      // 1) Alerts query.
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "_id",
            "kibana.alert.rule.name",
            "kibana.alert.severity",
            "kibana.alert.rule.description",
            "kibana.alert.risk_score",
            "kibana.alert.reason",
            "host.name",
            "user.name",
            "process.name",
            "process.executable",
            "file.name",
            "file.path",
            "source.ip",
            "destination.ip",
            "@timestamp",
          ],
          [
            [
              "a1",
              "RuleA",
              "critical",
              "desc",
              "95",
              "because",
              "h1",
              "u1",
              "bash",
              "/bin/bash",
              "f.txt",
              "/tmp/f.txt",
              "1.1.1.1",
              "2.2.2.2",
              "2024-01-01T00:00:00Z",
            ],
          ]
        )
      );
      // 2) Entity-risk query.
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "host.name",
            "user.name",
            "host.risk.calculated_level",
            "host.risk.calculated_score_norm",
            "user.risk.calculated_level",
            "user.risk.calculated_score_norm",
          ],
          [["h1", "u1", "High", 80, "High", 75]]
        )
      );
      // 3) With-replacements query (returns a row → markers from ES win).
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "kibana.alert.attack_discovery.title_with_replacements",
            "kibana.alert.attack_discovery.summary_markdown_with_replacements",
            "kibana.alert.attack_discovery.details_markdown_with_replacements",
          ],
          [["{{ host.name h1 }} pwned", "summary {{ host.name h1 }}", "details"]]
        )
      );

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.getDiscoveryDetail({
        ...emptyDiscovery,
        id: "d1",
        title: "fallback",
        alertIds: ["a1"],
      });

      expect(out.alerts).toEqual([
        {
          id: "a1",
          ruleName: "RuleA",
          severity: "critical",
          host: "h1",
          user: "u1",
          timestamp: "2024-01-01T00:00:00Z",
          details: {
            "host.name": "h1",
            "user.name": "u1",
            "process.name": "bash",
            "process.executable": "/bin/bash",
            "file.name": "f.txt",
            "file.path": "/tmp/f.txt",
            "source.ip": "1.1.1.1",
            "destination.ip": "2.2.2.2",
            "rule.description": "desc",
            risk_score: "95",
            reason: "because",
          },
        },
      ]);
      expect(out.entityRisk).toEqual([
        { name: "h1", type: "host", level: "High", score: 80 },
        { name: "u1", type: "user", level: "High", score: 75 },
      ]);
      expect(out.titleWithReplacements).toBe("{{ host.name h1 }} pwned");
      expect(out.summaryWithReplacements).toBe("summary {{ host.name h1 }}");
      expect(out.detailsWithReplacements).toBe("details");
    });

    it("injects replacement markers into raw text when none are present in ES results", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "_id",
            "kibana.alert.rule.name",
            "kibana.alert.severity",
            "host.name",
            "user.name",
            "@timestamp",
          ],
          [
            ["a1", "R", "high", "h1", "alice", "t"],
            ["a2", "R", "high", "h1", "alice", "t"],
          ]
        )
      );
      // No risk data.
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope([], [])
      );
      // With-replacements query returns no rows → fall back to discovery text.
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope([], [])
      );

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.getDiscoveryDetail({
        ...emptyDiscovery,
        id: "d1",
        title: "alice was on h1",
        summaryMarkdown: "h1 hit by alice",
        detailsMarkdown: "the host h1 and user alice",
        alertIds: ["a1", "a2"],
      });

      expect(out.titleWithReplacements).toBe(
        "{{ user.name alice }} was on {{ host.name h1 }}"
      );
      expect(out.summaryWithReplacements).toBe(
        "{{ host.name h1 }} hit by {{ user.name alice }}"
      );
      expect(out.detailsWithReplacements).toBe(
        "the host {{ host.name h1 }} and user {{ user.name alice }}"
      );
      expect(out.entityRisk).toEqual([
        { name: "h1", type: "host", level: "Unknown", score: 0 },
        { name: "alice", type: "user", level: "Unknown", score: 0 },
      ]);
    });
  });

  describe("synthesizeConfidence (via assessConfidence)", () => {
    it("returns 'low' when alerts are found but the diversity / risk signals are weak", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      // Diversity query returns a single low-severity alert.
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "_id",
            "kibana.alert.rule.name",
            "kibana.alert.rule.uuid",
            "kibana.alert.severity",
            "host.name",
            "user.name",
            "agent.id",
          ],
          [["a1", "RuleA", "ru1", "low", "h1", "u1", "ag1"]]
        )
      );
      // Rule frequency: middle-of-the-road (no penalty, no bonus).
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          ["total", "hosts", "kibana.alert.rule.name"],
          [[20, 3, "RuleA"]]
        )
      );
      // Entity risk: "Low" → -0.5 per entity (drives score below 1).
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "host.name",
            "user.name",
            "host.risk.calculated_level",
            "host.risk.calculated_score_norm",
            "user.risk.calculated_level",
            "user.risk.calculated_score_norm",
          ],
          [["h1", "u1", "Low", 10, "Low", 5]]
        )
      );

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const [out] = await service.assessConfidence([
        {
          ...emptyDiscovery,
          id: "d1",
          alertIds: ["a1"],
        },
      ]);

      expect(out.confidence).toBe("low");
      expect(out.signals.entityRisk).toContainEqual({
        name: "h1",
        type: "host",
        riskLevel: "Low",
        riskScore: 10,
      });
    });

    it("returns 'moderate' when signals add up to a mid-range score", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      // Diversity: 3 alerts / 2 rules / "high" severity → +1 + 0.5 = 1.5.
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "_id",
            "kibana.alert.rule.name",
            "kibana.alert.rule.uuid",
            "kibana.alert.severity",
            "host.name",
            "user.name",
            "agent.id",
          ],
          [
            ["a1", "RuleA", "ru1", "high", "h1", "u1", "ag1"],
            ["a2", "RuleA", "ru1", "high", "h1", "u1", "ag1"],
            ["a3", "RuleB", "ru2", "high", "h1", "u1", "ag1"],
          ]
        )
      );
      // Rule frequency: high totals + many hosts → -1 per rule, dragging score down.
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          ["total", "hosts", "kibana.alert.rule.name"],
          [
            [200, 10, "RuleA"],
            [200, 10, "RuleB"],
          ]
        )
      );
      // Entity risk: "High" → +1 per entity.
      vi.mocked(attackDiscoveryClient.runEsql).mockResolvedValueOnce(
        envelope(
          [
            "host.name",
            "user.name",
            "host.risk.calculated_level",
            "host.risk.calculated_score_norm",
            "user.risk.calculated_level",
            "user.risk.calculated_score_norm",
          ],
          [["h1", "u1", "High", 80, "High", 75]]
        )
      );

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const [out] = await service.assessConfidence([
        {
          ...emptyDiscovery,
          id: "d1",
          alertIds: ["a1", "a2", "a3"],
        },
      ]);

      // 1 (3/2 rules) + 0.5 (high) − 2 (rule freq) + 2 (entity risk) = 1.5 → moderate.
      expect(out.confidence).toBe("moderate");
    });
  });

  describe("listAIConnectors", () => {
    it("filters connectors to AI types and normalises the action type id", async () => {
      const attackDiscoveryClient = createMockAttackDiscoveryClient();
      vi.mocked(attackDiscoveryClient.listConnectors).mockResolvedValueOnce([
        { id: "1", name: "Bedrock", connector_type_id: ".bedrock" },
        { id: "2", name: "Slack", connector_type_id: ".slack" },
        { id: "3", name: "GenAI", action_type_id: ".gen-ai" },
        { id: "4", name: "Mystery" },
      ]);

      const service = new AttackDiscoveryService({ attackDiscoveryClient });
      const out = await service.listAIConnectors();

      expect(out).toEqual([
        { id: "1", name: "Bedrock", actionTypeId: ".bedrock" },
        { id: "3", name: "GenAI", actionTypeId: ".gen-ai" },
      ]);
    });
  });
});

const emptyDiscovery: AttackDiscovery = {
  id: "",
  timestamp: "",
  executionUuid: "",
  title: "",
  summaryMarkdown: "",
  detailsMarkdown: "",
  mitreTactics: [],
  alertIds: [],
  alertsContextCount: 0,
  riskScore: 0,
};

function makeRow(id: string): unknown[] {
  return [id, "2024-01-01T00:00:00Z", "exec", "t", "s", "d", [], [], 0, 0];
}
