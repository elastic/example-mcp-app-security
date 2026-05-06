/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { InvestigateService } from "./investigateService.js";
import type { EsqlEnvelope } from "../client/investigateClient.js";
import { createMockInvestigateClient } from "../../test/helpers/mockServiceClients.js";

function envelope(
  columns: string[],
  values: unknown[][]
): EsqlEnvelope {
  return { columns: columns.map((name) => ({ name })), values };
}

describe("InvestigateService", () => {
  it("returns an empty graph for an unknown entity type", async () => {
    const investigateClient = createMockInvestigateClient();
    const service = new InvestigateService({ investigateClient });

    const out = await service.investigateEntity("planet", "saturn");

    expect(out).toEqual({ nodes: [], edges: [] });
    expect(investigateClient.runEsql).not.toHaveBeenCalled();
  });

  it("escapes embedded quotes in entity values when building the ES|QL query", async () => {
    const investigateClient = createMockInvestigateClient();
    vi.mocked(investigateClient.runEsql).mockResolvedValue(envelope([], []));

    const service = new InvestigateService({ investigateClient });
    await service.investigateEntity("user", 'al"ice');

    const queries = vi
      .mocked(investigateClient.runEsql)
      .mock.calls.map((call) => call[0]);
    for (const q of queries) {
      expect(q).toContain('user.name == "al\\"ice"');
    }
  });

  it("swallows query failures and still returns whatever subqueries succeeded", async () => {
    const investigateClient = createMockInvestigateClient();
    // Three calls fan out for `user`: processes, hosts, alerts. Make middle fail.
    vi.mocked(investigateClient.runEsql)
      .mockResolvedValueOnce(envelope([], []))
      .mockRejectedValueOnce(new Error("index missing"))
      .mockResolvedValueOnce(envelope([], []));

    const service = new InvestigateService({ investigateClient });
    const out = await service.investigateEntity("user", "alice");

    expect(out.nodes).toEqual([
      { id: "user:alice", type: "user", value: "alice" },
    ]);
    expect(out.edges).toEqual([]);
  });

  it("aggregates rows from successful subqueries into nodes and edges", async () => {
    const investigateClient = createMockInvestigateClient();
    // host investigation = 4 subqueries: users, processes, network, alerts.
    vi.mocked(investigateClient.runEsql)
      .mockResolvedValueOnce(
        envelope(["count", "user.name"], [
          [10, "alice"],
        ])
      )
      .mockResolvedValueOnce(envelope([], []))
      .mockResolvedValueOnce(envelope([], []))
      .mockResolvedValueOnce(envelope([], []));

    const service = new InvestigateService({ investigateClient });
    const out = await service.investigateEntity("host", "h1");

    expect(out.nodes).toContainEqual({
      id: "host:h1",
      type: "host",
      value: "h1",
    });
    expect(out.nodes).toContainEqual({
      id: "user:alice",
      type: "user",
      value: "alice",
      metadata: { count: 10 },
    });
    expect(out.edges).toEqual([
      { source: "host:h1", target: "user:alice", label: "user" },
    ]);
  });

  it("investigateProcess pivots over children / parents / hosts / network", async () => {
    const investigateClient = createMockInvestigateClient();
    // children
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(
      envelope(["count", "process.name"], [
        [3, "child.exe"],
      ])
    );
    // parents
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(
      envelope(["count", "process.parent.name"], [
        [2, "explorer.exe"],
      ])
    );
    // hosts
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(
      envelope(["count", "host.name"], [
        [10, "h1"],
      ])
    );
    // network
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(
      envelope(["count", "destination.ip"], [
        [4, "10.0.0.5"],
      ])
    );

    const service = new InvestigateService({ investigateClient });
    const out = await service.investigateEntity("process", "bash");

    const ids = out.nodes.map((n) => n.id);
    expect(ids).toContain("process:bash");
    expect(ids).toContain("process:child.exe");
    expect(ids).toContain("process:explorer.exe");
    expect(ids).toContain("host:h1");
    expect(ids).toContain("ip:10.0.0.5");
    expect(out.edges.map((e) => e.label).sort()).toEqual([
      "connected to",
      "on host",
      "parent",
      "spawned",
    ]);
  });

  it("addResults dedupes when subsequent rows reference an already-linked node", async () => {
    const investigateClient = createMockInvestigateClient();
    // host investigation: users subquery returns alice twice. The second row
    // should hit the `edges.some(...)` branch with non-empty edges, exercising
    // the edge-dedupe predicate.
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(
      envelope(["count", "user.name"], [
        [10, "alice"],
        [5, "alice"],
      ])
    );
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(envelope([], []));
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(envelope([], []));
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(envelope([], []));

    const service = new InvestigateService({ investigateClient });
    const out = await service.investigateEntity("host", "h1");

    const aliceEdges = out.edges.filter((e) => e.target === "user:alice");
    expect(aliceEdges).toHaveLength(1);
  });

  it("ignores rows with `null` / non-string / falsy values in addResults", async () => {
    const investigateClient = createMockInvestigateClient();
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(
      envelope(["count", "user.name"], [
        [10, null],
        [10, ""],
        [10, "null"],
        [10, 42],
      ])
    );
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(envelope([], []));
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(envelope([], []));
    vi.mocked(investigateClient.runEsql).mockResolvedValueOnce(envelope([], []));

    const service = new InvestigateService({ investigateClient });
    const out = await service.investigateEntity("host", "h1");

    expect(out.nodes.find((n) => n.id !== "host:h1")).toBeUndefined();
  });

  it("translates an `hour` time range into an ES|QL `NOW() - N hours` clause", async () => {
    const investigateClient = createMockInvestigateClient();
    vi.mocked(investigateClient.runEsql).mockResolvedValue(envelope([], []));

    const service = new InvestigateService({ investigateClient });
    await service.investigateEntity("ip", "10.0.0.1", "now-3h");

    const firstQuery = vi.mocked(investigateClient.runEsql).mock.calls[0][0];
    expect(firstQuery).toContain("@timestamp >= NOW() - 3 hours");
  });

  it("treats malformed time ranges as 'no time clause'", async () => {
    const investigateClient = createMockInvestigateClient();
    vi.mocked(investigateClient.runEsql).mockResolvedValue(envelope([], []));

    const service = new InvestigateService({ investigateClient });
    await service.investigateEntity("ip", "10.0.0.1", "garbage");

    const firstQuery = vi.mocked(investigateClient.runEsql).mock.calls[0][0];
    expect(firstQuery).not.toContain("@timestamp >=");
  });

  it("translates a `now-Nd` time range into an ES|QL `NOW() - N days` clause", async () => {
    const investigateClient = createMockInvestigateClient();
    vi.mocked(investigateClient.runEsql).mockResolvedValue(envelope([], []));

    const service = new InvestigateService({ investigateClient });
    await service.investigateEntity("ip", "10.0.0.1", "now-2d");

    const firstQuery = vi.mocked(investigateClient.runEsql).mock.calls[0][0];
    expect(firstQuery).toContain("@timestamp >= NOW() - 2 days");
  });
});
