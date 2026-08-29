/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { renderProfileMarkdown } from "./environment-profile-markdown.js";
import type { EnvironmentProfile } from "./environment-profile.js";

function baseProfile(overrides: Partial<EnvironmentProfile> = {}): EnvironmentProfile {
  return {
    scope: { level: "deployment", ref: { deployment: "acme-prod" }, scope_id: "abc123" },
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
      ],
    },
    terrain: {
      populated_ecs_fields: [
        { field: "source.ip", family: "network", population_ratio: 0.9, detected_types: ["ip", "keyword"], type_conflict: true },
      ],
      resolved_hunt_indices: ["logs-aws.cloudtrail-default"],
      off_schema_indices: [],
      high_volume_off_schema: [],
      huntable_off_schema_indices: [],
      intel_sources: [],
      process_tree_indices: { full: [], parent_only: [] },
      blind_spots: ["no dns telemetry"],
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

describe("renderProfileMarkdown", () => {
  it("renders the cluster, sections, and embedded JSON", () => {
    const md = renderProfileMarkdown(baseProfile());

    expect(md).toContain("# Environment Profile — acme-prod");
    expect(md).toContain("**Cluster:** `acme-prod`");
    expect(md).toContain("## Data sources");
    expect(md).toContain("logs-aws.cloudtrail-default");
    expect(md).toContain("## Field terrain (populated, not just mapped)");
    expect(md).toContain("yes (ip/keyword)");
    expect(md).toContain("## Coverage gaps");
    expect(md).toContain("- no dns telemetry");
    expect(md).toContain("## Not inspected");
    expect(md).toContain("```json");
  });

  it("surfaces the sample-data warning", () => {
    const md = renderProfileMarkdown(
      baseProfile({
        capabilities: {
          entity_analytics: false,
          attack_discovery: false,
          cases: false,
          correlation_corpus: false,
          is_sample_data: true,
        },
      })
    );
    expect(md).toContain("sample/demo data marker");
  });

  it("renders the high-volume off-schema section with discovered huntable fields", () => {
    const md = renderProfileMarkdown(
      baseProfile({
        terrain: {
          populated_ecs_fields: [],
          resolved_hunt_indices: [],
          off_schema_indices: ["export-endpoint-info-ds"],
          high_volume_off_schema: [
            {
              name: "export-endpoint-info-ds",
              doc_count: 4_000_000_000,
              store_size_bytes: 16_511_434_706_670,
              ecs_hunt_fields_mapped: [],
              total_fields: 88,
              timestamp_fields: ["ingested_at"],
              huntable_fields: [
                {
                  category: "command_line",
                  fields: ["data.noisy_process_trees.breakdown.command_line"],
                },
                { category: "executable", fields: ["data.system_impact.breakdown.exe_path"] },
              ],
              lineage: {
                capability: "parent_only",
                child_id: false,
                parent_attrs: false,
                parent_join_key: false,
                ancestry_array: false,
                session_leaders: false,
                ppid: false,
                parent_command_line: true,
                join_fields: [],
              },
            },
          ],
          huntable_off_schema_indices: ["export-endpoint-info-ds"],
          intel_sources: ["ia-loupe-indicators"],
          process_tree_indices: { full: [], parent_only: ["export-endpoint-info-ds"] },
          blind_spots: [
            "bulk of data lives in 1 non-ECS stream(s) not covered by ECS field probes (largest: export-endpoint-info-ds ~4,000,000,000 docs)",
          ],
        },
      })
    );

    expect(md).toContain("## High-volume off-schema data");
    expect(md).toContain("export-endpoint-info-ds");
    expect(md).toContain("15.0 TB");
    expect(md).toContain("**Hunt here too (ranked):**");
    expect(md).toContain("command_line (1)");
    expect(md).toContain("`data.noisy_process_trees.breakdown.command_line`");
    expect(md).toContain("**time anchors:**");
    expect(md).toContain("- bulk of data lives in 1 non-ECS stream(s)");
    // Lineage section rendered from the profiler-derived capability.
    expect(md).toContain("## Process lineage (parent/child)");
    expect(md).toContain("**Parent-only:** `export-endpoint-info-ds`");
    // Intelligence sources surfaced separately from hunt targets.
    expect(md).toContain("## Intelligence / enrichment sources (not hunt targets)");
    expect(md).toContain("- `ia-loupe-indicators`");
  });

  it("renders the classification-review artifact, low-confidence first", () => {
    const md = renderProfileMarkdown(
      baseProfile({
        terrain: {
          populated_ecs_fields: [],
          resolved_hunt_indices: [],
          off_schema_indices: [],
          high_volume_off_schema: [
            {
              name: "trusted-telemetry",
              doc_count: 100,
              ecs_hunt_fields_mapped: [],
              huntable_fields: [{ category: "process", fields: ["process.name"] }],
              affordances: {
                huntable: true,
                matchable: false,
                enrichable: false,
                pivotable: false,
                confidence: "high",
                evidence: ["owned-asset anchor (agent.id/host.*)"],
                source: "heuristic",
              },
            },
            {
              name: "ambiguous-threatintel",
              doc_count: 50,
              ecs_hunt_fields_mapped: [],
              huntable_fields: [{ category: "ip", fields: ["source.ip"] }],
              affordances: {
                huntable: false,
                matchable: true,
                enrichable: false,
                pivotable: false,
                confidence: "low",
                evidence: ["intel name/meta token", "owned-asset anchor (agent.id/host.*)"],
                source: "heuristic",
              },
            },
          ],
          huntable_off_schema_indices: ["trusted-telemetry"],
          intel_sources: [],
          process_tree_indices: { full: [], parent_only: [] },
          blind_spots: [],
        },
      })
    );

    expect(md).toContain("## Classification review (approve / correct)");
    // Within the review section, the low-confidence row precedes the high one.
    const review = md.slice(md.indexOf("## Classification review"));
    const lowIdx = review.indexOf("| `ambiguous-threatintel` |");
    const highIdx = review.indexOf("| `trusted-telemetry` |");
    expect(lowIdx).toBeGreaterThan(-1);
    expect(highIdx).toBeGreaterThan(-1);
    expect(lowIdx).toBeLessThan(highIdx);
    expect(review).toContain("intel name/meta token");
  });

  it("renders the hunt-primitive matrix and collapsed mirrors", () => {
    const md = renderProfileMarkdown(
      baseProfile({
        terrain: {
          populated_ecs_fields: [],
          resolved_hunt_indices: [],
          off_schema_indices: [],
          high_volume_off_schema: [],
          classified_indices: [
            {
              name: "export-2024_gtr_raw_edr_behavior",
              doc_count: 189498,
              ecs_hunt_fields_mapped: [],
              huntable_fields: [{ category: "process", fields: ["process.name"] }],
              mirror_of: "2024_gtr_raw_edr_behavior",
              affordances: {
                huntable: true,
                matchable: false,
                enrichable: false,
                pivotable: false,
                confidence: "high",
                evidence: [],
                source: "heuristic",
              },
            },
          ],
          huntable_off_schema_indices: ["endpoint-events"],
          hunt_indices: [
            {
              name: "logs-endpoint.events.process-default",
              schema_alignment: "ecs",
              doc_count: 5000,
              ecs_hunt_fields_mapped: [],
              huntable_fields: [{ category: "process", fields: ["process.name"] }],
              primitives: [
                { primitive: "process_lineage", confidence: "high", fields: [] },
              ],
              join_keys: [
                { kind: "host", field: "host.name" },
                { kind: "agent", field: "agent.id" },
              ],
            },
          ],
          intel_sources: [],
          process_tree_indices: { full: [], parent_only: [] },
          primitive_matrix: {
            temporal_sequence: ["endpoint-events"],
            dns_analytics: ["dns-logs"],
          },
          joinability: {
            by_key: {
              host: ["logs-endpoint.events.process-default", "logs-okta.system"],
              user: ["logs-okta.system"],
            },
          },
          blind_spots: [],
        },
      })
    );

    expect(md).toContain("## Hunt indices (ECS + off-schema)");
    expect(md).toContain("`logs-endpoint.events.process-default`");
    expect(md).toContain("| ECS |");
    expect(md).toContain("## Hunt-primitive matrix");
    expect(md).toContain("`temporal_sequence`");
    expect(md).toContain("`endpoint-events`");
    expect(md).toContain("`dns_analytics`");
    expect(md).toContain("## Joinability (pivot / sequence / dedup fabric)");
    expect(md).toContain("| `host` |");
    expect(md).toContain("## Duplicate mirrors collapsed");
    expect(md).toContain(
      "`export-2024_gtr_raw_edr_behavior` → mirror of `2024_gtr_raw_edr_behavior`"
    );
  });

  it("records uninspectable sections", () => {
    const md = renderProfileMarkdown(
      baseProfile({ collection_errors: ["response_capabilities: 403 forbidden"] })
    );
    expect(md).toContain("- response_capabilities: 403 forbidden");
  });
});
