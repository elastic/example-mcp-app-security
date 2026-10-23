/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { renderProfileCanvas } from "./environment-profile-canvas.js";
import type { EnvironmentProfile } from "./environment-profile.js";

function baseProfile(overrides: Partial<EnvironmentProfile> = {}): EnvironmentProfile {
  return {
    scope: { level: "deployment", ref: { deployment: "acme-prod" }, scope_id: "abc123def456" },
    generated_at: "2026-07-15T00:00:00.000Z",
    inventory: {
      active_data_streams: [
        { name: "logs-aws.cloudtrail-default", doc_count: 1234, last_seen: 1_700_000_000_000 },
      ],
      integration_presence: {
        aws: true,
        azure: false,
        gcp: false,
        endpoint: true,
        network_traffic: false,
        vulnerability: false,
        alerts: true,
        fleet: true,
        installed: ["aws", "endpoint"],
      },
      deployed_tech: { cloud_providers: ["aws"], os_mix: { windows: 10 } },
      entity_counts: { host: 5, user: 7, service: 0, generic: 0 },
      rule_inventory: { total: 100, enabled: 80, disabled: 20 },
    },
    endpoint_posture: {
      defend: [
        {
          policy_id: "p1",
          policy_name: "Prod Endpoint",
          os: "windows",
          protections: [{ protection: "malware", intended_mode: "prevent" }],
          captured_event_categories: ["process"],
        },
      ],
      third_party: [],
    },
    response_capabilities: {
      connectors: [
        { id: "c1", type: ".slack", name: "SecOps Slack", capability_domain: "notify", actions: ["post_message"] },
        { id: "c2", type: ".virustotal", name: "VT", capability_domain: "enrich", actions: ["lookup"] },
      ],
    },
    terrain: {
      populated_ecs_fields: [
        { field: "source.ip", family: "network", population_ratio: 0.9, detected_types: ["ip"], type_conflict: false },
      ],
      resolved_hunt_indices: ["logs-endpoint.events.process-default"],
      off_schema_indices: [],
      high_volume_off_schema: [],
      hunt_indices: [
        {
          name: "logs-endpoint.events.process-default",
          schema_alignment: "ecs",
          doc_count: 5_000_000,
          ecs_hunt_fields_mapped: [],
          huntable_fields: [{ category: "process", fields: ["process.name"] }],
          primitives: [{ primitive: "process_lineage", confidence: "high", fields: [] }],
          join_keys: [
            { kind: "host", field: "host.name" },
            { kind: "agent", field: "agent.id" },
          ],
          lineage: {
            capability: "full",
            child_id: true,
            parent_attrs: true,
            parent_join_key: true,
            ancestry_array: true,
            session_leaders: false,
            ppid: true,
            parent_command_line: true,
            join_fields: ["process.entity_id"],
          },
        },
      ],
      classified_indices: [
        {
          name: "export-2024_gtr_raw_edr_behavior",
          doc_count: 189498,
          ecs_hunt_fields_mapped: [],
          mirror_of: "2024_gtr_raw_edr_behavior",
        },
      ],
      huntable_off_schema_indices: [],
      intel_sources: ["ia-loupe-indicators"],
      process_tree_indices: { full: ["logs-endpoint.events.process-default"], parent_only: [] },
      primitive_matrix: {
        process_lineage: ["logs-endpoint.events.process-default"],
        dns_analytics: ["logs-network.dns-default"],
      },
      joinability: {
        by_key: {
          host: ["logs-endpoint.events.process-default"],
          user: ["logs-okta.system-default"],
        },
      },
      blind_spots: ["no dns telemetry in ECS streams"],
    },
    capabilities: {
      entity_analytics: true,
      attack_discovery: false,
      cases: true,
      correlation_corpus: false,
      is_sample_data: false,
    },
    collection_errors: [],
    ...overrides,
  };
}

/** Pull the inlined `DATA` JSON back out of the emitted canvas source. */
function extractData(canvas: string): Record<string, unknown> {
  const start = canvas.indexOf("const DATA: BriefData = ");
  const from = canvas.indexOf("{", start);
  const end = canvas.indexOf(" as unknown as BriefData;");
  return JSON.parse(canvas.slice(from, end));
}

describe("renderProfileCanvas", () => {
  it("emits a self-contained canvas with the data placeholder substituted", () => {
    const canvas = renderProfileCanvas(baseProfile());

    // Canvas host contract.
    expect(canvas).toContain('from "cursor/canvas"');
    expect(canvas).toContain("export default function EnvironmentBrief()");
    // The placeholder must be gone (data baked in).
    expect(canvas).not.toContain("/*__DATA__*/ null");
    expect(canvas).not.toMatch(/from ['"](?!cursor\/canvas)/); // only cursor/canvas imports
  });

  it("bakes the profile findings into the inlined DATA literal", () => {
    const data = extractData(renderProfileCanvas(baseProfile())) as any;

    expect(data.cluster).toBe("acme-prod");
    expect(data.stats.huntTotal).toBe(1);
    expect(data.stats.huntEcs).toBe(1);
    // hunt-target row carries schema, primitives, and join keys.
    expect(data.hunt[0].name).toBe("logs-endpoint.events.process-default");
    expect(data.hunt[0].schema).toBe("ecs");
    expect(data.hunt[0].prims).toBe(1);
    expect(data.hunt[0].keys).toBe(2);
    // primitive + join charts (present only).
    expect(data.primitives.map((p: any) => p.key)).toContain("process_lineage");
    expect(data.joins.map((j: any) => j.key)).toContain("host");
    // glossaries only include present items, with defs.
    expect(data.primitiveGlossary.find((g: any) => g.key === "process_lineage").desc).toMatch(/process/i);
    // intel + mirrors + response domains.
    expect(data.intelSources).toContain("ia-loupe-indicators");
    expect(data.mirrors[0]).toEqual({ name: "export-2024_gtr_raw_edr_behavior", mirror_of: "2024_gtr_raw_edr_behavior" });
    expect(data.response.map((r: any) => r.key).sort()).toEqual(["enrich", "notify"]);
  });

  it("derives a character read: off-schema dominance and empty entity store", () => {
    const data = extractData(
      renderProfileCanvas(
        baseProfile({
          inventory: {
            ...baseProfile().inventory,
            entity_counts: { host: 0, user: 0, service: 0, generic: 0 },
            deployed_tech: { cloud_providers: [], os_mix: { windows: 1 } },
          },
          endpoint_posture: { defend: [], third_party: [] },
          terrain: {
            ...baseProfile().terrain,
            hunt_indices: [
              {
                name: "custom_telemetry",
                schema_alignment: "off_schema",
                doc_count: 100,
                ecs_hunt_fields_mapped: [],
              },
            ],
          },
        })
      )
    ) as any;

    expect(data.stats.entities).toBe(0);
    expect(data.stats.huntOff).toBe(1);
    expect(data.notes.join(" ")).toMatch(/off the ECS happy path/);
    expect(data.notes.join(" ")).toMatch(/Entity Store is empty/);
    expect(data.notes.join(" ")).toMatch(/No Elastic Defend/);
  });

  it("flags sample-data deployments and notes low rule enablement", () => {
    const data = extractData(
      renderProfileCanvas(
        baseProfile({
          inventory: { ...baseProfile().inventory, rule_inventory: { total: 1000, enabled: 50, disabled: 950 } },
          capabilities: {
            entity_analytics: false,
            attack_discovery: false,
            cases: false,
            correlation_corpus: false,
            is_sample_data: true,
          },
        })
      )
    ) as any;

    expect(data.isSample).toBe(true);
    expect(data.notes.join(" ")).toMatch(/50 of 1000 detection rules enabled/);
  });
});
