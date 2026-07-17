/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import { EnvironmentService } from "./environmentService.js";
import { createMockEnvironmentClient } from "../../test/helpers/mockServiceClients.js";
import type { EnvironmentClient } from "../client/environmentClient.js";
import {
  emptyCatalog,
  type CatalogData,
  type ClassificationCatalog,
} from "../../shared/classification-catalog.js";

/** In-memory catalog store for exercising sticky-verdict behavior without fs. */
function memCatalog(initial: CatalogData = emptyCatalog()): ClassificationCatalog {
  let data = initial;
  return {
    async load() {
      return data;
    },
    async save(next) {
      data = next;
    },
  };
}

function seedHappyPath(client: EnvironmentClient) {
  vi.mocked(client.getDataStreams).mockResolvedValue([
    {
      name: "logs-aws.cloudtrail-default",
      _meta: { package: { name: "aws" } },
    },
  ]);
  vi.mocked(client.getDataStreamStats).mockResolvedValue([
    {
      data_stream: "logs-aws.cloudtrail-default",
      backing_indices: 1,
      store_size_bytes: 1000,
      maximum_timestamp: 123,
    },
  ]);
  vi.mocked(client.catDocCounts).mockResolvedValue([
    {
      index: ".ds-logs-aws.cloudtrail-default-2024.01.01-000001",
      "docs.count": "50",
    },
  ]);
  vi.mocked(client.getInstalledPackages).mockResolvedValue([
    { name: "aws" },
    { name: "endpoint" },
    { name: "crowdstrike" },
    { name: "system" },
  ]);
  vi.mocked(client.runEsql).mockImplementation(async (query: string) => {
    if (query.includes("STATS total = COUNT(*)")) {
      // Terrain family probe: total plus one count column per field (f0, f1, ...).
      return {
        columns: [
          { name: "total", type: "long" },
          { name: "f0", type: "long" },
          { name: "f1", type: "long" },
          { name: "f2", type: "long" },
        ],
        values: [[100, 90, 40, 0]],
      };
    }
    if (query.includes("COUNT_DISTINCT(host.name)")) {
      return {
        columns: [
          { name: "hosts", type: "long" },
          { name: "platform", type: "keyword" },
        ],
        values: [
          [10, "windows"],
          [3, "linux"],
        ],
      };
    }
    if (query.includes(".entities")) {
      // Entity Store v2 reports capitalized types; the service must normalize.
      return {
        columns: [
          { name: "c", type: "long" },
          { name: "type", type: "keyword" },
        ],
        values: [
          [5, "Host"],
          [7, "User"],
        ],
      };
    }
    return { columns: [], values: [] };
  });
  vi.mocked(client.getFieldCaps).mockResolvedValue({});
  vi.mocked(client.getMappingsMeta).mockResolvedValue({});
  vi.mocked(client.catIndices).mockResolvedValue([]);
  vi.mocked(client.count).mockResolvedValue(0);
  vi.mocked(client.countCases).mockResolvedValue(0);
  vi.mocked(client.getAttackDiscoveryGenerations).mockResolvedValue({
    generations: [],
  });
  vi.mocked(client.countRules).mockImplementation(async (filter?: string) =>
    filter ? 8 : 12
  );
  vi.mocked(client.getPackagePolicies).mockResolvedValue([
    {
      id: "pol-1",
      name: "Endpoint Policy",
      package: { name: "endpoint" },
      inputs: [
        {
          config: {
            policy: {
              value: {
                windows: {
                  malware: { mode: "prevent" },
                  ransomware: { mode: "detect" },
                  memory_protection: { mode: "off" },
                  behavior_protection: { mode: "prevent" },
                  events: { process: true, network: true, file: false },
                },
              },
            },
          },
        },
      ],
    },
  ]);
  vi.mocked(client.getConnectors).mockResolvedValue([
    { id: "c1", connector_type_id: ".slack", name: "SecOps Slack" },
    { id: "c2", connector_type_id: ".crowdstrike", name: "CrowdStrike" },
    { id: "c3", connector_type_id: ".gen-ai", name: "GPT" },
  ]);
}

describe("EnvironmentService.profileEnvironment", () => {
  it("builds a deployment-scoped leaf profile with a stable scope id", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    const service = new EnvironmentService({ environmentClient: client });

    const profile = await service.profileEnvironment();

    expect(profile.scope.level).toBe("deployment");
    expect(profile.scope.ref.deployment).toBe("test-cluster");
    expect(profile.scope.scope_id).toMatch(/^[0-9a-f]{16}$/);
    expect(profile.collection_errors).toEqual([]);
  });

  it("derives integration presence, cloud providers, and os mix", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    const service = new EnvironmentService({ environmentClient: client });

    const { inventory } = await service.profileEnvironment();

    expect(inventory.integration_presence.aws).toBe(true);
    expect(inventory.integration_presence.endpoint).toBe(true);
    expect(inventory.integration_presence.gcp).toBe(false);
    expect(inventory.integration_presence.installed).toHaveLength(4);
    expect(inventory.deployed_tech.cloud_providers).toEqual(["aws"]);
    expect(inventory.deployed_tech.os_mix).toEqual({ windows: 10, linux: 3 });
    expect(inventory.entity_counts).toEqual({
      host: 5,
      user: 7,
      service: 0,
      generic: 0,
    });
    expect(inventory.rule_inventory).toEqual({
      total: 12,
      enabled: 8,
      disabled: 4,
    });
  });

  it("degrades entity counts to zero (no error) when the entity store is absent", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    // A cluster without Entity Analytics: the `.entities.*.latest*` pattern
    // matches nothing, so ES|QL rejects `entity.type` as an unknown column.
    vi.mocked(client.runEsql).mockImplementation(async (query: string) => {
      if (query.includes(".entities")) {
        throw new Error(
          'Elasticsearch [analytics] 400: {"error":{"type":"verification_exception",' +
            '"reason":"Found 1 problem\\nline 1:57: Unknown column [entity.type]"}}'
        );
      }
      return { columns: [], values: [] };
    });
    const service = new EnvironmentService({ environmentClient: client });

    const profile = await service.profileEnvironment();

    expect(profile.inventory.entity_counts).toEqual({
      host: 0,
      user: 0,
      service: 0,
      generic: 0,
    });
    expect(profile.capabilities.entity_analytics).toBe(false);
    // Absent capability, not a collection failure.
    expect(profile.collection_errors).toEqual([]);
  });

  it("surfaces non-entity-schema ES|QL failures as collection errors", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.runEsql).mockImplementation(async (query: string) => {
      if (query.includes(".entities")) {
        throw new Error("Elasticsearch [analytics] 403: security_exception");
      }
      return { columns: [], values: [] };
    });
    const service = new EnvironmentService({ environmentClient: client });

    const profile = await service.profileEnvironment();

    expect(profile.collection_errors).toEqual(
      expect.arrayContaining([
        expect.stringContaining("inventory.entity_counts"),
      ])
    );
  });

  it("merges data-stream stats and doc counts", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    const service = new EnvironmentService({ environmentClient: client });

    const { inventory } = await service.profileEnvironment();
    const ds = inventory.active_data_streams[0];

    expect(ds.name).toBe("logs-aws.cloudtrail-default");
    expect(ds.dataset).toBe("aws.cloudtrail");
    expect(ds.integration).toBe("aws");
    expect(ds.doc_count).toBe(50);
    expect(ds.store_size_bytes).toBe(1000);
    expect(ds.last_seen).toBe(123);
  });

  it("parses intended Defend protection modes and captured events", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    const service = new EnvironmentService({ environmentClient: client });

    const { endpoint_posture } = await service.profileEnvironment();

    expect(endpoint_posture.defend).toHaveLength(1);
    const policy = endpoint_posture.defend[0];
    expect(policy.os).toBe("windows");
    expect(policy.protections).toContainEqual({
      protection: "malware",
      intended_mode: "prevent",
    });
    expect(policy.protections).toContainEqual({
      protection: "memory_protection",
      intended_mode: "off",
    });
    expect(policy.captured_event_categories).toEqual(["process", "network"]);
    expect(endpoint_posture.third_party.map((t) => t.vendor)).toEqual([
      "crowdstrike",
    ]);
  });

  it("maps connectors to capability domains and excludes LLM connectors", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    const service = new EnvironmentService({ environmentClient: client });

    const { response_capabilities } = await service.profileEnvironment();
    const connectors = response_capabilities.connectors;

    expect(connectors).toHaveLength(2);
    expect(connectors.find((c) => c.type === ".crowdstrike")).toMatchObject({
      capability_domain: "endpoint",
      reveals_third_party_tech: "crowdstrike",
    });
    expect(connectors.find((c) => c.type === ".slack")?.capability_domain).toBe(
      "notify"
    );
    expect(connectors.find((c) => c.type === ".gen-ai")).toBeUndefined();
  });

  it("degrades a failed section instead of failing the whole profile", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getConnectors).mockRejectedValue(new Error("403 forbidden"));
    vi.mocked(client.getInstalledPackages).mockRejectedValue(
      new Error("fleet unavailable")
    );
    const service = new EnvironmentService({ environmentClient: client });

    const profile = await service.profileEnvironment();

    // The profile is still returned, with the working sections intact.
    expect(profile.inventory.active_data_streams).toHaveLength(1);
    expect(profile.inventory.rule_inventory.total).toBe(12);
    // Failed sections fall back and are recorded honestly.
    expect(profile.response_capabilities.connectors).toEqual([]);
    expect(profile.inventory.integration_presence.installed).toEqual([]);
    expect(profile.collection_errors).toEqual(
      expect.arrayContaining([
        expect.stringContaining("response_capabilities: 403 forbidden"),
        expect.stringContaining("inventory.integrations: fleet unavailable"),
      ])
    );
  });

  it("probes field population and flags type conflicts", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    // A field mapped as both ip and keyword across indices is a conflict.
    vi.mocked(client.getFieldCaps).mockResolvedValue({
      "source.ip": { ip: {}, keyword: {} },
    });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    const sourceIp = terrain.populated_ecs_fields.find(
      (f) => f.field === "source.ip"
    );
    expect(sourceIp?.population_ratio).toBe(0.9);
    expect(sourceIp?.type_conflict).toBe(true);
    expect(sourceIp?.detected_types).toEqual(["ip", "keyword"]);
    expect(terrain.resolved_hunt_indices).toContain(
      "logs-aws.cloudtrail-default"
    );
  });

  it("ranks hunt indices by volume and surfaces high-volume off-schema data", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getDataStreams).mockResolvedValue([
      { name: "logs-system.system-default" },
      { name: "logs-aws.cloudtrail-default", _meta: { package: { name: "aws" } } },
      { name: "custom_telemetry_wardenseye" },
    ]);
    vi.mocked(client.getDataStreamStats).mockResolvedValue([
      {
        data_stream: "custom_telemetry_wardenseye",
        backing_indices: 1,
        store_size_bytes: 1_900_000_000,
        maximum_timestamp: 1_784_000_000_000,
      },
    ]);
    // logs-system is empty; logs-aws has some docs; the custom stream is huge.
    vi.mocked(client.catDocCounts).mockResolvedValue([
      { index: ".ds-logs-aws.cloudtrail-default-2026.01.01-000001", "docs.count": "500" },
      { index: ".ds-custom_telemetry_wardenseye-2026.07.16-000001", "docs.count": "35005" },
    ]);
    // Huntable material lives under NON-ECS field names — the classifier must
    // still discover it by semantics, not exact ECS names.
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (
        pattern: string
      ): Promise<Record<string, Record<string, unknown>>> =>
        pattern === "custom_telemetry_wardenseye"
          ? {
              "host.name": { keyword: {} },
              "data.breakdown.command_line": { text: {} },
              "data.breakdown.exe_path": { keyword: {} },
              svc_port: { long: {} },
              "wardenseye.vt.ip.malicious": { long: {} },
              event_time: { date: {} },
              _index: { _index: {} },
            }
          : {}
    );
    // No ECS-shaped telemetry populated in the probe window.
    vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    // Empty logs-system dropped; populated ECS streams ranked by volume.
    expect(terrain.resolved_hunt_indices).toEqual([
      "logs-aws.cloudtrail-default",
    ]);

    const off = terrain.high_volume_off_schema.find(
      (o) => o.name === "custom_telemetry_wardenseye"
    );
    expect(off?.doc_count).toBe(35005);
    // Internal `_index` excluded from the field count.
    expect(off?.total_fields).toBe(6);
    // Date field surfaced as a time anchor.
    expect(off?.timestamp_fields).toContain("event_time");
    // Custom-named fields classified into observable categories.
    const cat = (c: string) =>
      off?.huntable_fields?.find((g) => g.category === c)?.fields ?? [];
    expect(cat("command_line")).toContain("data.breakdown.command_line");
    expect(cat("executable")).toContain("data.breakdown.exe_path");
    expect(cat("port")).toContain("svc_port");
    expect(cat("host")).toContain("host.name");

    // Ranked "hunt here too" list surfaces the stream with material.
    expect(terrain.huntable_off_schema_indices).toContain(
      "custom_telemetry_wardenseye"
    );

    // Blind spots credit off-schema coverage instead of claiming "no host".
    expect(terrain.blind_spots).toEqual(
      expect.arrayContaining([
        expect.stringContaining("bulk of data lives in"),
        expect.stringContaining("host telemetry present only in off-schema"),
      ])
    );
    expect(terrain.blind_spots).not.toContain(
      "no host telemetry in the last 30 days"
    );
  });

  it("ranks off-schema hunt indices by huntable breadth, not raw volume, and drops noise", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getDataStreams).mockResolvedValue([]);
    vi.mocked(client.catDocCounts).mockResolvedValue([]);
    // A huge operational index with no huntable material, plus a small
    // telemetry corpus rich in observables. Volume ranking would surface the
    // noise and bury the telemetry; breadth ranking must do the opposite.
    vi.mocked(client.catIndices).mockResolvedValue([
      { index: "export-ilm-stats", "docs.count": "9000000", "store.size": "1" },
      { index: "endpoint-behavior-corpus", "docs.count": "1000", "store.size": "1" },
    ]);
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (
        pattern: string
      ): Promise<Record<string, Record<string, unknown>>> =>
        pattern === "endpoint-behavior-corpus"
          ? {
              "agent.id": { keyword: {} },
              "host.name": { keyword: {} },
              "event.category": { keyword: {} },
              "process.name": { keyword: {} },
              "source.ip": { ip: {} },
              "destination.ip": { ip: {} },
              "file.hash.sha256": { keyword: {} },
              "dns.question.name": { keyword: {} },
            }
          : pattern === "export-ilm-stats"
            ? {
                policy_name: { keyword: {} },
                phase: { keyword: {} },
                size_in_bytes: { long: {} },
              }
            : {}
    );
    vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    // Small-but-rich telemetry corpus ranks first; huge-but-empty noise dropped.
    expect(terrain.huntable_off_schema_indices[0]).toBe("endpoint-behavior-corpus");
    expect(terrain.huntable_off_schema_indices).not.toContain("export-ilm-stats");
    // But the volume signal is preserved for the blind-spot summary.
    expect(terrain.blind_spots).toEqual(
      expect.arrayContaining([
        expect.stringContaining("largest: export-ilm-stats"),
      ])
    );
  });

  it("probes huntable-named streams whose volume is unreported (frozen tier) and backfills counts", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    // Data stream exists but cat/stats report nothing (searchable-snapshot tier).
    vi.mocked(client.getDataStreams).mockResolvedValue([
      { name: "alert_telemetry_elastic" },
    ]);
    vi.mocked(client.getDataStreamStats).mockResolvedValue([]);
    vi.mocked(client.catDocCounts).mockResolvedValue([]);
    vi.mocked(client.catIndices).mockResolvedValue([]);
    // Real data is only observable via a direct _count.
    vi.mocked(client.count).mockResolvedValue(1100);
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (
        pattern: string
      ): Promise<Record<string, Record<string, unknown>>> =>
        pattern === "alert_telemetry_elastic"
          ? {
              "process.command_line": { keyword: {} },
              "host.name": { keyword: {} },
              "source.ip": { ip: {} },
              "@timestamp": { date: {} },
            }
          : {}
    );
    vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    // Rescued despite zero reported volume: probed, counted, and surfaced.
    expect(terrain.huntable_off_schema_indices).toContain("alert_telemetry_elastic");
    const off = terrain.high_volume_off_schema.find(
      (o) => o.name === "alert_telemetry_elastic"
    );
    expect(off?.doc_count).toBe(1100);
    expect(client.count).toHaveBeenCalledWith("alert_telemetry_elastic");
  });

  it("separates intelligence/enrichment sources from hunt targets", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getDataStreams).mockResolvedValue([]);
    vi.mocked(client.catDocCounts).mockResolvedValue([]);
    vi.mocked(client.catIndices).mockResolvedValue([
      { index: "ia-loupe-indicators", "docs.count": "900", "store.size": "1" },
      { index: "custom_telemetry_wardenseye", "docs.count": "800", "store.size": "1" },
      { index: "reindexed-v8-threatintel", "docs.count": "700", "store.size": "1" },
      { index: "alert_telemetry_elastic", "docs.count": "600", "store.size": "1" },
    ]);
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (
        pattern: string
      ): Promise<Record<string, Record<string, unknown>>> => {
        // IOC feed: threat.indicator.* with no owned-asset anchor.
        if (pattern === "ia-loupe-indicators")
          return {
            "threat.indicator.ip": { ip: {} },
            "threat.indicator.type": { keyword: {} },
            "event.category": { keyword: {} },
          };
        // External HTTP prober: intel schema, no owned-asset anchor, no events.
        if (pattern === "custom_telemetry_wardenseye")
          return {
            "threat.indicator.url": { keyword: {} },
            "wardenseye.vt.malicious": { long: {} },
            "url.domain": { keyword: {} },
          };
        // Threat-intel feed by name, even though it carries a collector host.
        if (pattern === "reindexed-v8-threatintel")
          return {
            "agent.id": { keyword: {} },
            "host.name": { keyword: {} },
            "event.category": { keyword: {} },
            "process.name": { keyword: {} },
          };
        // Real telemetry: owned-asset anchor + events, no intel name/schema.
        return {
          "agent.id": { keyword: {} },
          "host.id": { keyword: {} },
          "event.category": { keyword: {} },
          "process.name": { keyword: {} },
        };
      }
    );
    vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    // Intel/enrichment sources bucketed out of the huntable list.
    expect(terrain.intel_sources).toEqual(
      expect.arrayContaining([
        "ia-loupe-indicators",
        "custom_telemetry_wardenseye",
        "reindexed-v8-threatintel",
      ])
    );
    expect(terrain.huntable_off_schema_indices).toEqual(["alert_telemetry_elastic"]);
    expect(terrain.huntable_off_schema_indices).not.toContain("ia-loupe-indicators");
    // Intel indices don't pollute the process-tree tiers either.
    expect(terrain.process_tree_indices.full).not.toContain("reindexed-v8-threatintel");

    const aff = (name: string) =>
      terrain.classified_indices?.find((o) => o.name === name)?.affordances;

    // Structural IOC feed: matchable, not huntable, high confidence, heuristic.
    const ioc = aff("ia-loupe-indicators");
    expect(ioc).toMatchObject({
      huntable: false,
      matchable: true,
      confidence: "high",
      source: "heuristic",
    });
    expect(ioc?.evidence.length).toBeGreaterThan(0);

    // Real telemetry: huntable, high confidence (owned asset + events).
    expect(aff("alert_telemetry_elastic")).toMatchObject({
      huntable: true,
      confidence: "high",
      source: "heuristic",
    });

    // Name says intel but structure says telemetry — flagged low-confidence so
    // the LLM/human stage re-examines it.
    expect(aff("reindexed-v8-threatintel")).toMatchObject({
      huntable: false,
      matchable: true,
      confidence: "low",
    });
  });

  it("derives hunt primitives (beyond lineage) from field shape", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getDataStreams).mockResolvedValue([]);
    vi.mocked(client.catDocCounts).mockResolvedValue([]);
    vi.mocked(client.catIndices).mockResolvedValue([
      { index: "rich-endpoint", "docs.count": "1000", "store.size": "1" },
      { index: "okta-audit", "docs.count": "900", "store.size": "1" },
    ]);
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (
        pattern: string
      ): Promise<Record<string, Record<string, unknown>>> => {
        if (pattern === "rich-endpoint")
          return {
            "@timestamp": { date: {} },
            "process.entity_id": { keyword: {} },
            "process.parent.entity_id": { keyword: {} },
            "process.name": { keyword: {} },
            "event.category": { keyword: {} },
            "host.id": { keyword: {} },
            "destination.ip": { ip: {} },
            "network.bytes": { long: {} },
            "dns.question.name": { keyword: {} },
            "file.code_signature.trusted": { boolean: {} },
          };
        if (pattern === "okta-audit")
          return {
            "@timestamp": { date: {} },
            "okta.actor.id": { keyword: {} },
            "okta.event_type": { keyword: {} },
            "event.action": { keyword: {} },
            "source.ip": { ip: {} },
            "user.name": { keyword: {} },
            "source.geo.country_name": { keyword: {} },
          };
        return {};
      }
    );
    vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    const prims = (name: string) =>
      new Set(
        terrain.classified_indices
          ?.find((o) => o.name === name)
          ?.primitives?.map((p) => p.primitive)
      );

    const endpoint = prims("rich-endpoint");
    expect(endpoint).toContain("process_lineage");
    expect(endpoint).toContain("temporal_sequence");
    expect(endpoint).toContain("network_beaconing");
    expect(endpoint).toContain("dns_analytics");
    expect(endpoint).toContain("code_signature");

    const okta = prims("okta-audit");
    expect(okta).toContain("cloud_identity");
    expect(okta).toContain("geo_impossible_travel");

    // Rolled up into the worker-facing matrix.
    const m = terrain.primitive_matrix ?? {};
    expect(m.dns_analytics).toContain("rich-endpoint");
    expect(m.cloud_identity).toContain("okta-audit");
    expect(m.temporal_sequence).toEqual(
      expect.arrayContaining(["rich-endpoint", "okta-audit"])
    );
  });

  it("treats ECS logs streams as first-class hunt targets with join keys", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getDataStreams).mockResolvedValue([
      { name: "logs-endpoint.events.process-default" },
      { name: "logs-okta.system-default" },
    ]);
    vi.mocked(client.getDataStreamStats).mockResolvedValue([
      {
        data_stream: "logs-endpoint.events.process-default",
        backing_indices: 1,
        store_size_bytes: 9000,
        maximum_timestamp: 123,
      },
      {
        data_stream: "logs-okta.system-default",
        backing_indices: 1,
        store_size_bytes: 4000,
        maximum_timestamp: 123,
      },
    ]);
    vi.mocked(client.catDocCounts).mockResolvedValue([
      {
        index: ".ds-logs-endpoint.events.process-default-2024.01.01-000001",
        "docs.count": "5000",
      },
      {
        index: ".ds-logs-okta.system-default-2024.01.01-000001",
        "docs.count": "3000",
      },
    ]);
    vi.mocked(client.catIndices).mockResolvedValue([]);
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (
        pattern: string
      ): Promise<Record<string, Record<string, unknown>>> => {
        if (pattern === "logs-endpoint.events.process-default")
          return {
            "@timestamp": { date: {} },
            "agent.id": { keyword: {} },
            "host.id": { keyword: {} },
            "host.name": { keyword: {} },
            "process.entity_id": { keyword: {} },
            "process.parent.entity_id": { keyword: {} },
            "process.name": { keyword: {} },
            "event.category": { keyword: {} },
            "source.ip": { ip: {} },
          };
        if (pattern === "logs-okta.system-default")
          return {
            "@timestamp": { date: {} },
            "okta.actor.id": { keyword: {} },
            "user.name": { keyword: {} },
            "host.name": { keyword: {} },
            "event.action": { keyword: {} },
            "source.ip": { ip: {} },
            "source.geo.country_name": { keyword: {} },
          };
        return {};
      }
    );
    vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    // ECS streams are first-class in the unified hunt catalog.
    const ep = terrain.hunt_indices?.find(
      (o) => o.name === "logs-endpoint.events.process-default"
    );
    const okta = terrain.hunt_indices?.find(
      (o) => o.name === "logs-okta.system-default"
    );
    expect(ep?.schema_alignment).toBe("ecs");
    expect(okta?.schema_alignment).toBe("ecs");
    // …and drive the primitive matrix.
    expect(terrain.primitive_matrix?.process_lineage).toContain(
      "logs-endpoint.events.process-default"
    );
    expect(terrain.primitive_matrix?.cloud_identity).toContain(
      "logs-okta.system-default"
    );

    // Join keys are derived per index.
    const kinds = (o?: { join_keys?: { kind: string }[] }) =>
      new Set(o?.join_keys?.map((j) => j.kind));
    expect(kinds(ep)).toContain("agent");
    expect(kinds(ep)).toContain("process");
    expect(kinds(okta)).toContain("user");

    // Joinability fabric: both share host.name (mutually joinable), okta adds user.
    expect(terrain.joinability?.by_key.host).toEqual(
      expect.arrayContaining([
        "logs-endpoint.events.process-default",
        "logs-okta.system-default",
      ])
    );
    expect(terrain.joinability?.by_key.user).toContain("logs-okta.system-default");
  });

  it("collapses reindex mirrors and drops confirmed-empty streams", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getDataStreams).mockResolvedValue([]);
    vi.mocked(client.catDocCounts).mockResolvedValue([]);
    vi.mocked(client.catIndices).mockResolvedValue([
      { index: "2024_gtr_raw_edr_behavior", "docs.count": "189498", "store.size": "1" },
      { index: "export-2024_gtr_raw_edr_behavior", "docs.count": "189498", "store.size": "1" },
      { index: "detections_alert_telemetry_v2", "docs.count": "0", "store.size": "1" },
    ]);
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (): Promise<Record<string, Record<string, unknown>>> => ({
        "host.id": { keyword: {} },
        "process.name": { keyword: {} },
        "event.category": { keyword: {} },
        "kibana.alert.rule.uuid": { keyword: {} },
      })
    );
    // The empty stream's real count is 0; base/mirror already report volume.
    vi.mocked(client.count).mockResolvedValue(0);
    vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    // Canonical surfaces; the equal-volume `export-` mirror does not.
    expect(terrain.huntable_off_schema_indices).toContain("2024_gtr_raw_edr_behavior");
    expect(terrain.huntable_off_schema_indices).not.toContain(
      "export-2024_gtr_raw_edr_behavior"
    );
    // Mirror is kept (flagged) in the review for transparency.
    const mirror = terrain.classified_indices?.find(
      (o) => o.name === "export-2024_gtr_raw_edr_behavior"
    );
    expect(mirror?.mirror_of).toBe("2024_gtr_raw_edr_behavior");

    // Confirmed-empty stream is dropped from the hunt list and the review.
    expect(terrain.huntable_off_schema_indices).not.toContain(
      "detections_alert_telemetry_v2"
    );
    expect(
      terrain.classified_indices?.some(
        (o) => o.name === "detections_alert_telemetry_v2"
      )
    ).toBe(false);
  });

  it("applies sticky catalog verdicts and re-flows the buckets", async () => {
    const seed = (client: EnvironmentClient) => {
      seedHappyPath(client);
      vi.mocked(client.getDataStreams).mockResolvedValue([]);
      vi.mocked(client.catDocCounts).mockResolvedValue([]);
      vi.mocked(client.catIndices).mockResolvedValue([
        { index: "looks-like-telemetry", "docs.count": "500", "store.size": "1" },
      ]);
      // Heuristically a hunt target: owned-asset anchor + events.
      vi.mocked(client.getFieldCaps).mockResolvedValue({
        "agent.id": { keyword: {} },
        "host.id": { keyword: {} },
        "event.category": { keyword: {} },
        "process.name": { keyword: {} },
      });
      vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    };

    // Pass 1 (no catalog): heuristic classifies it huntable; grab its signature.
    const c1 = createMockEnvironmentClient();
    seed(c1);
    const p1 = await new EnvironmentService({ environmentClient: c1 }).profileEnvironment();
    expect(p1.terrain.huntable_off_schema_indices).toContain("looks-like-telemetry");
    const idx = p1.terrain.classified_indices?.find(
      (o) => o.name === "looks-like-telemetry"
    );
    expect(idx?.affordances?.huntable).toBe(true);
    const signature = idx?.signature;
    expect(signature).toBeTruthy();

    // Analyst overrides: it's actually an enrichment source, not a hunt target.
    const c2 = createMockEnvironmentClient();
    seed(c2);
    const catalog = memCatalog();
    const service = new EnvironmentService({ environmentClient: c2, catalog });
    await service.approveClassifications([
      {
        name: "looks-like-telemetry",
        signature: signature!,
        affordances: {
          huntable: false,
          matchable: true,
          enrichable: false,
          pivotable: false,
          confidence: "high",
          evidence: ["analyst: curated enrichment source"],
        },
      },
    ]);

    // Pass 2: the sticky verdict re-flows the buckets on rerun.
    const p2 = await service.profileEnvironment();
    expect(p2.terrain.huntable_off_schema_indices).not.toContain(
      "looks-like-telemetry"
    );
    expect(p2.terrain.intel_sources).toContain("looks-like-telemetry");
    const idx2 = p2.terrain.classified_indices?.find(
      (o) => o.name === "looks-like-telemetry"
    );
    expect(idx2?.affordances?.source).toBe("human");
    expect(idx2?.affordances?.huntable).toBe(false);
  });

  it("no-ops approvals when no catalog store is configured", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    const service = new EnvironmentService({ environmentClient: client });
    const result = await service.approveClassifications([
      {
        name: "x",
        signature: "sig",
        affordances: {
          huntable: true,
          matchable: false,
          enrichable: false,
          pivotable: false,
          confidence: "high",
          evidence: [],
        },
      },
    ]);
    expect(result.entries).toEqual({});
  });

  it("derives process-lineage capability tiers from field maps", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getDataStreams).mockResolvedValue([]);
    vi.mocked(client.catDocCounts).mockResolvedValue([]);
    vi.mocked(client.catIndices).mockResolvedValue([
      { index: "full_tree", "docs.count": "300", "store.size": "1" },
      { index: "parent_only_tree", "docs.count": "200", "store.size": "1" },
      { index: "no_tree", "docs.count": "100", "store.size": "1" },
    ]);
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (
        pattern: string
      ): Promise<Record<string, Record<string, unknown>>> => {
        if (pattern === "full_tree")
          return {
            "process.entity_id": { keyword: {} },
            "process.parent.entity_id": { keyword: {} },
            "process.parent.name": { keyword: {} },
            "process.parent.command_line": { keyword: {} },
          };
        if (pattern === "parent_only_tree")
          return {
            "process.parent.name": { keyword: {} },
            "process.parent.command_line": { keyword: {} },
          };
        // no_tree: process material but nothing lineage-related.
        return { "process.name": { keyword: {} }, "source.ip": { ip: {} } };
      }
    );
    vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    expect(terrain.process_tree_indices.full).toEqual(["full_tree"]);
    expect(terrain.process_tree_indices.parent_only).toEqual(["parent_only_tree"]);

    const full = terrain.high_volume_off_schema.find((o) => o.name === "full_tree");
    expect(full?.lineage?.capability).toBe("full");
    expect(full?.lineage?.child_id).toBe(true);
    expect(full?.lineage?.parent_join_key).toBe(true);
    expect(full?.lineage?.join_fields).toContain("process.parent.entity_id");

    const none = terrain.high_volume_off_schema.find((o) => o.name === "no_tree");
    expect(none?.lineage).toBeUndefined();
  });

  it("folds standalone (non-data-stream) indices into terrain discovery", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getDataStreams).mockResolvedValue([]);
    vi.mocked(client.catDocCounts).mockResolvedValue([]);
    // Plain indices — invisible to GET /_data_stream — hold the real data.
    vi.mocked(client.catIndices).mockResolvedValue([
      { index: "export-detections-alert-updates", "docs.count": "25455470", "store.size": "9000000000" },
      { index: ".ds-logs-aws.cloudtrail-default-2026.01.01-000001", "docs.count": "500", "store.size": "5000" },
      { index: "shrink-abcd-.ds-export-endpoint-info-ds-2026.01.05-000384", "docs.count": "98167094", "store.size": "1000000" },
      { index: ".internal.alerts-security", "docs.count": "10", "store.size": "100" },
      { index: "empty-index", "docs.count": "0", "store.size": "0" },
    ]);
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (
        pattern: string
      ): Promise<Record<string, Record<string, unknown>>> =>
        pattern === "export-detections-alert-updates"
          ? {
              "process.name": { keyword: {} },
              "host.name": { keyword: {} },
              "user.name": { keyword: {} },
              "@timestamp": { date: {} },
            }
          : {}
    );
    vi.mocked(client.runEsql).mockResolvedValue({ columns: [], values: [] });
    const service = new EnvironmentService({ environmentClient: client });

    const { inventory, terrain } = await service.profileEnvironment();

    // The standalone index is now part of the inventory (dot/backing excluded).
    const names = inventory.active_data_streams.map((d) => d.name);
    expect(names).toContain("export-detections-alert-updates");
    expect(names).not.toContain(".ds-logs-aws.cloudtrail-default-2026.01.01-000001");
    expect(names).not.toContain(".internal.alerts-security");
    expect(names).not.toContain("empty-index");
    // ILM shrink/backing index (embeds `.ds-`) must be excluded as noise.
    expect(names).not.toContain(
      "shrink-abcd-.ds-export-endpoint-info-ds-2026.01.05-000384"
    );

    // And it's probed: canonical ECS hunt fields recovered.
    const off = terrain.high_volume_off_schema.find(
      (o) => o.name === "export-detections-alert-updates"
    );
    expect(off?.doc_count).toBe(25455470);
    expect(off?.ecs_hunt_fields_mapped).toEqual(
      expect.arrayContaining(["process.name", "host.name", "user.name"])
    );
    expect(terrain.huntable_off_schema_indices).toContain(
      "export-detections-alert-updates"
    );
  });

  it("probes the detection-alert alias behind dot-prefixed backing indices", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    // Alerts live behind `.internal.alerts-*` backing indices (dot-excluded);
    // the canonical alias resolves the union.
    vi.mocked(client.count).mockImplementation(async (pattern: string) =>
      pattern === ".alerts-security.alerts-*" ? 3_152_595 : 0
    );
    vi.mocked(client.getFieldCaps).mockImplementation(
      async (
        pattern: string
      ): Promise<Record<string, Record<string, unknown>>> =>
        pattern === ".alerts-security.alerts-*"
          ? {
              "process.name": { keyword: {} },
              "host.name": { keyword: {} },
              "@timestamp": { date: {} },
              "kibana.alert.rule.threat.technique.id": { keyword: {} },
            }
          : {}
    );
    const service = new EnvironmentService({ environmentClient: client });

    const { inventory, terrain } = await service.profileEnvironment();

    // Represented in the inventory as a single alias entry.
    const entry = inventory.active_data_streams.find(
      (d) => d.name === ".alerts-security.alerts-*"
    );
    expect(entry?.integration).toBe("detection_alerts");
    expect(entry?.doc_count).toBe(3_152_595);

    // It's a prime hunt surface, ranked into resolved_hunt_indices by volume.
    expect(terrain.resolved_hunt_indices).toContain(".alerts-security.alerts-*");

    // ECS happy-path alias: first-class in the unified hunt catalog (not the
    // off-schema bucket), with its field map recovered (ECS names + ATT&CK intel).
    const hit = terrain.hunt_indices?.find(
      (o) => o.name === ".alerts-security.alerts-*"
    );
    expect(hit?.schema_alignment).toBe("ecs");
    expect(hit?.ecs_hunt_fields_mapped).toEqual(
      expect.arrayContaining(["process.name", "host.name"])
    );
    expect(hit?.huntable_fields?.some((g) => g.category === "intel")).toBe(true);
    // ECS alias stays out of the off-schema-only bucket.
    expect(terrain.huntable_off_schema_indices).not.toContain(
      ".alerts-security.alerts-*"
    );
  });

  it("classifies enrich and automation connector domains", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.getConnectors).mockResolvedValue([
      { id: "vt", connector_type_id: ".virustotal", name: "VT" },
      { id: "gh", connector_type_id: ".github", name: "GH" },
      { id: "wh", connector_type_id: ".webhook", name: "Hook" },
      { id: "idx", connector_type_id: ".index", name: "Threat Tracking" },
      { id: "novel", connector_type_id: ".made-up", name: "Mystery" },
    ]);
    const service = new EnvironmentService({ environmentClient: client });

    const { connectors } = (await service.profileEnvironment())
      .response_capabilities;
    const domain = (type: string) =>
      connectors.find((c) => c.type === type)?.capability_domain;

    expect(domain(".virustotal")).toBe("enrich");
    expect(domain(".github")).toBe("automation");
    expect(domain(".webhook")).toBe("automation");
    expect(domain(".index")).toBe("automation");
    // Unknown types no longer masquerade as "notify".
    expect(domain(".made-up")).toBe("other");
  });

  it("derives human-readable blind spots when families are empty", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    // No telemetry anywhere: every terrain probe returns empty.
    vi.mocked(client.runEsql).mockImplementation(async (query: string) => {
      if (query.includes(".entities")) {
        return { columns: [], values: [] };
      }
      return { columns: [], values: [] };
    });
    const service = new EnvironmentService({ environmentClient: client });

    const { terrain } = await service.profileEnvironment();

    expect(terrain.blind_spots).toContain("no network telemetry");
    expect(terrain.blind_spots).toEqual(
      expect.arrayContaining([expect.stringContaining("no process telemetry")])
    );
  });

  it("detects advanced capabilities in use", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.countCases).mockResolvedValue(4);
    vi.mocked(client.count).mockImplementation(async (pattern: string) =>
      pattern.startsWith("ti-reports") ? 250 : 0
    );
    vi.mocked(client.getAttackDiscoveryGenerations).mockResolvedValue({
      generations: [{ id: "gen-1" }],
    });
    const service = new EnvironmentService({ environmentClient: client });

    const { capabilities } = await service.profileEnvironment();

    expect(capabilities.entity_analytics).toBe(true);
    expect(capabilities.cases).toBe(true);
    expect(capabilities.correlation_corpus).toBe(true);
    expect(capabilities.attack_discovery).toBe(true);
    expect(capabilities.is_sample_data).toBe(false);
  });

  it("flags sample/demo data deployments", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    vi.mocked(client.count).mockImplementation(async (_pattern, body) =>
      body ? 5000 : 0
    );
    const service = new EnvironmentService({ environmentClient: client });

    const { capabilities } = await service.profileEnvironment();

    expect(capabilities.is_sample_data).toBe(true);
  });

  it("honors an explicit space scope", async () => {
    const client = createMockEnvironmentClient();
    seedHappyPath(client);
    const service = new EnvironmentService({ environmentClient: client });

    const profile = await service.profileEnvironment({ space: "tenant-a" });

    expect(profile.scope.level).toBe("space");
    expect(profile.scope.ref.space).toBe("tenant-a");
  });
});
