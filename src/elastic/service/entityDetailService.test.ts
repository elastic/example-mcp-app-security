/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { EntityDetailService } from "./entityDetailService.js";
import { createMockEntityDetailClient } from "../../test/helpers/mockServiceClients.js";

const emptyHits = { hits: { hits: [] } };

describe("EntityDetailService", () => {
  describe("getEntityDetail", () => {
    it("returns an empty card without calling the client for unknown types", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      const service = new EntityDetailService({ entityDetailClient });

      const out = await service.getEntityDetail("planet", "saturn");

      expect(out).toEqual({ type: "planet", value: "saturn", fields: [] });
      expect(entityDetailClient.searchByTerms).not.toHaveBeenCalled();
    });
  });

  describe("alert detail", () => {
    it("returns a 'no matching alert' placeholder when nothing is found", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms).mockResolvedValueOnce(
        emptyHits
      );

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("alert", "Some Rule");

      expect(out).toEqual({
        type: "alert",
        value: "Some Rule",
        fields: [{ label: "Status", value: "No matching alert found" }],
      });
    });

    it("flattens MITRE ATT&CK threats and exposes core fields", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms).mockResolvedValueOnce({
        hits: {
          hits: [
            {
              _source: {
                "kibana.alert.rule.name": "R",
                "kibana.alert.severity": "high",
                "kibana.alert.risk_score": 73,
                "kibana.alert.workflow_status": "open",
                "kibana.alert.reason": "because",
                "kibana.alert.rule.threat": [
                  {
                    tactic: { name: "Execution" },
                    technique: [{ id: "T1059", name: "Cmd" }],
                  },
                ],
                host: { name: "h1" },
                user: { name: "u1" },
                process: { name: "p1", executable: "/p" },
                "@timestamp": "2024-01-01T00:00:00Z",
              },
            },
          ],
        },
      });

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("alert", "R");

      expect(out.fields).toContainEqual({ label: "Rule", value: "R" });
      expect(out.fields).toContainEqual({ label: "Severity", value: "high" });
      expect(out.fields).toContainEqual({
        label: "MITRE ATT&CK",
        value: "Execution, T1059 Cmd",
      });
      expect(out.fields).toContainEqual({
        label: "Host",
        value: "h1",
        mono: true,
      });
    });
  });

  describe("host detail", () => {
    it("aggregates results from process / network / alert searches", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms)
        .mockResolvedValueOnce({
          hits: {
            hits: [
              {
                _source: {
                  "@timestamp": "2024-01-01T00:00:00Z",
                  process: { name: "bash", command_line: "ls -la" },
                  user: { name: "alice" },
                  host: { os: { name: "Linux" }, ip: ["10.0.0.1"] },
                },
              },
            ],
          },
        })
        .mockResolvedValueOnce({
          hits: {
            hits: [
              {
                _source: {
                  destination: { ip: "10.0.0.5", port: 443 },
                  process: { name: "curl" },
                },
              },
            ],
          },
        })
        .mockResolvedValueOnce({
          hits: {
            hits: [
              {
                _source: {
                  "kibana.alert.rule.name": "Suspicious",
                  "kibana.alert.severity": "high",
                },
              },
            ],
          },
        });

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("host", "h1");

      expect(out.type).toBe("host");
      expect(out.value).toBe("h1");
      expect(out.fields).toContainEqual({
        label: "Hostname",
        value: "h1",
        mono: true,
      });
      expect(out.fields).toContainEqual({ label: "OS", value: "Linux" });
      expect(out.fields).toContainEqual({
        label: "IP",
        value: "10.0.0.1",
        mono: true,
      });
      expect(out.fields).toContainEqual({
        label: "Recent Processes",
        value: "bash",
        mono: true,
      });
      expect(out.fields).toContainEqual({
        label: "Recent Connections",
        value: "10.0.0.5:443",
        mono: true,
      });
      expect(out.fields).toContainEqual({
        label: "Open Alerts",
        value: "high — Suspicious",
      });
      expect(out.events).toEqual([
        {
          timestamp: "2024-01-01T00:00:00Z",
          action: "process",
          detail: "alice ran bash: ls -la",
        },
      ]);
    });

    it("swallows individual sub-search failures", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms)
        .mockRejectedValueOnce(new Error("processes-down"))
        .mockResolvedValueOnce(emptyHits)
        .mockRejectedValueOnce(new Error("alerts-down"));

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("host", "h1");

      expect(out.type).toBe("host");
      expect(out.fields[0]).toEqual({
        label: "Hostname",
        value: "h1",
        mono: true,
      });
    });
  });

  describe("user / process / ip detail", () => {
    it("host detail falls back to host.os.platform when host.os.name is absent", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms)
        .mockResolvedValueOnce({
          hits: {
            hits: [
              {
                _source: {
                  "@timestamp": "t",
                  process: { name: "bash" },
                  user: { name: "alice" },
                  host: { os: { platform: "linux" }, ip: "10.0.0.1" },
                },
              },
            ],
          },
        })
        .mockResolvedValueOnce(emptyHits)
        .mockResolvedValueOnce(emptyHits);

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("host", "h1");

      expect(out.fields).toContainEqual({ label: "OS", value: "linux" });
      // host.ip as a scalar (not array) is also surfaced.
      expect(out.fields).toContainEqual({
        label: "IP",
        value: "10.0.0.1",
        mono: true,
      });
    });

    it("user detail surfaces alerts when the alert sub-search returns hits", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms)
        .mockResolvedValueOnce(emptyHits)
        .mockResolvedValueOnce({
          hits: {
            hits: [
              {
                _source: {
                  "@timestamp": "t",
                  "kibana.alert.severity": "high",
                  "kibana.alert.rule.name": "RuleA",
                  host: { name: "h1" },
                },
              },
            ],
          },
        });

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("user", "alice");

      expect(out.fields).toContainEqual({
        label: "Alerts",
        value: "high — RuleA (h1)",
      });
    });

    it("process detail surfaces command_line when present on the first hit", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms).mockResolvedValueOnce({
        hits: {
          hits: [
            {
              _source: {
                host: { name: "h1" },
                user: { name: "u1" },
                process: { command_line: "bash -c whoami" },
              },
            },
          ],
        },
      });

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("process", "bash");

      expect(out.fields).toContainEqual({
        label: "Command Line",
        value: "bash -c whoami",
        mono: true,
      });
    });

    it("user detail collects active hosts from process search", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms)
        .mockResolvedValueOnce({
          hits: {
            hits: [
              {
                _source: {
                  "@timestamp": "t",
                  host: { name: "h1" },
                  process: { name: "bash" },
                },
              },
              {
                _source: {
                  "@timestamp": "t",
                  host: { name: "h1" },
                  process: { name: "ls" },
                },
              },
            ],
          },
        })
        .mockResolvedValueOnce(emptyHits);

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("user", "alice");

      expect(out.fields).toContainEqual({
        label: "Active Hosts",
        value: "h1",
        mono: true,
      });
      expect(out.fields).toContainEqual({
        label: "Recent Processes",
        value: "bash, ls",
        mono: true,
      });
    });

    it("process detail dedupes host names", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms).mockResolvedValueOnce({
        hits: {
          hits: [
            { _source: { host: { name: "h1" }, user: { name: "u1" } } },
            { _source: { host: { name: "h2" }, user: { name: "u1" } } },
            { _source: { host: { name: "h1" }, user: { name: "u2" } } },
          ],
        },
      });

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("process", "bash");

      expect(out.fields).toContainEqual({
        label: "Hosts",
        value: "h1, h2",
        mono: true,
      });
      expect(out.fields).toContainEqual({
        label: "Users",
        value: "u1, u2",
        mono: true,
      });
    });

    it("ip detail produces a connection event per hit", async () => {
      const entityDetailClient = createMockEntityDetailClient();
      vi.mocked(entityDetailClient.searchByTerms).mockResolvedValueOnce({
        hits: {
          hits: [
            {
              _source: {
                "@timestamp": "t",
                host: { name: "h1" },
                process: { name: "curl" },
                destination: { port: 443 },
                network: { protocol: "https" },
              },
            },
          ],
        },
      });

      const service = new EntityDetailService({ entityDetailClient });
      const out = await service.getEntityDetail("ip", "10.0.0.1");

      expect(out.events).toEqual([
        {
          timestamp: "t",
          action: "connection",
          detail: "curl → 10.0.0.1:443 (https)",
        },
      ]);
    });
  });
});
