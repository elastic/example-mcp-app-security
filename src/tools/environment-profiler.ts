/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import type { EnvironmentService } from "../elastic/service/index.js";
import type { EnvironmentProfile } from "../shared/environment-profile.js";
import { renderProfileMarkdown } from "../shared/environment-profile-markdown.js";
import { renderProfileCanvas } from "../shared/environment-profile-canvas.js";
import { registerTrackedAppTool } from "./tracked-app-tool.js";

export interface EnvironmentProfilerToolDeps {
  readonly environmentService: EnvironmentService;
  readonly analytics: AnalyticsClient;
}

export function registerEnvironmentProfilerTools(
  server: McpServer,
  deps: EnvironmentProfilerToolDeps
) {
  const { environmentService, analytics } = deps;

  registerTrackedAppTool(
    analytics,
    server,
    "profile-environment",
    {
      title: "Profile Environment (IPB/IPOE)",
      description:
        "Run an Intelligence Preparation of the Battlefield pass over the " +
        "Elastic deployment and return a typed EnvironmentProfile plus an " +
        "analyst-readable Markdown rendering (save it to the workspace as " +
        "environment-profile.md) and an interactive Cursor Canvas rendering " +
        "(save it as environment-brief.canvas.tsx). Covers: data streams and integrations, " +
        "deployed tech and entity counts, detection-rule inventory, intended " +
        "Elastic Defend endpoint protection posture, response/SOAR connector " +
        "capabilities, field terrain (which ECS fields are actually populated, " +
        "not just mapped), coverage gaps, and advanced capabilities in use " +
        "(Entity Analytics, Attack Discovery, Cases, correlation corpus, " +
        "sample-data marker). Agentic workers (hunts, threat-emulation, " +
        "correlation, risk, response) should call this to ground their " +
        "operations in what is actually deployed rather than assuming.",
      inputSchema: {
        level: z
          .enum(["fleet", "deployment", "space", "datastream"])
          .optional()
          .describe("Scope granularity; defaults to deployment (single leaf)."),
        space: z.string().optional().describe("Kibana space id to scope to."),
        indexPattern: z
          .string()
          .optional()
          .describe("Index/datastream pattern to scope to."),
        approvals: z
          .array(
            z.object({
              name: z.string().describe("Index name (readability)."),
              signature: z
                .string()
                .describe(
                  "Shape signature from a prior profile's classified_indices[] — the catalog key."
                ),
              affordances: z.object({
                huntable: z.boolean(),
                matchable: z.boolean(),
                enrichable: z.boolean(),
                pivotable: z.boolean(),
                confidence: z.enum(["high", "medium", "low"]),
                evidence: z.array(z.string()).default([]),
                source: z.enum(["heuristic", "llm", "human"]).optional(),
                characterization: z.string().optional(),
              }),
              note: z.string().optional(),
            })
          )
          .optional()
          .describe(
            "Human/LLM-approved (or corrected) classifications to persist to the " +
              "catalog before profiling. On this and future runs, indices whose " +
              "shape matches are re-classified with the approved affordances."
          ),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ level, space, indexPattern, approvals }) => {
      // Write-then-profile: persist approvals first so the returned profile
      // already reflects the sticky verdicts (Stage 4 rerun).
      if (approvals?.length) {
        await environmentService.approveClassifications(approvals);
      }
      const profile = await environmentService.profileEnvironment({
        level,
        space,
        indexPattern,
      });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              summary: summarize(profile),
              // Analyst-readable rendering the workflow saves to the workspace
              // (environment-profile.md) for review and reuse by other skills.
              markdown: renderProfileMarkdown(profile),
              // Interactive Cursor Canvas rendering of the same findings. The
              // workflow saves this to the workspace canvases directory as
              // environment-brief.canvas.tsx so the analyst can open it beside
              // the chat.
              canvas: renderProfileCanvas(profile),
              profile,
            }),
          },
        ],
      };
    }
  );
}

/** A compact, model-friendly digest so the agent isn't forced to parse the full profile. */
function summarize(profile: EnvironmentProfile) {
  const { inventory, endpoint_posture, response_capabilities, terrain, capabilities } =
    profile;
  return {
    scope: profile.scope,
    data_streams: inventory.active_data_streams.length,
    integrations_installed: inventory.integration_presence.installed.length,
    cloud_providers: inventory.deployed_tech.cloud_providers,
    os_platforms: Object.keys(inventory.deployed_tech.os_mix),
    entity_counts: inventory.entity_counts,
    rules: inventory.rule_inventory,
    defend_policies: endpoint_posture.defend.length,
    third_party_endpoint: endpoint_posture.third_party.map((t) => t.vendor),
    response_domains: [
      ...new Set(response_capabilities.connectors.map((c) => c.capability_domain)),
    ],
    populated_fields: terrain.populated_ecs_fields.filter(
      (f) => f.population_ratio > 0
    ).length,
    huntable_off_schema: terrain.huntable_off_schema_indices,
    // Unified first-class hunt catalog (ECS happy path + off-schema).
    hunt_indices: (terrain.hunt_indices ?? []).map((o) => ({
      name: o.name,
      schema: o.schema_alignment,
      doc_count: o.doc_count,
      primitives: (o.primitives ?? []).map((p) => p.primitive),
      join_keys: (o.join_keys ?? []).map((j) => j.kind),
    })),
    intel_sources: terrain.intel_sources,
    process_tree_indices: terrain.process_tree_indices,
    // Generalized hunt-primitive support (sequence, auth, beaconing, DNS, cloud
    // identity, …) beyond just process lineage.
    primitive_matrix: terrain.primitive_matrix ?? {},
    // Cross-index join fabric: for each key, the indices mutually joinable on it
    // (sequencing / dedup / matching across primitives / cueing follow-up hunts).
    joinability: terrain.joinability?.by_key ?? {},
    // Reindex mirrors collapsed out of the hunt list (name -> canonical it copies).
    mirrors: (terrain.classified_indices ?? [])
      .filter((o) => o.mirror_of)
      .map((o) => ({ name: o.name, mirror_of: o.mirror_of })),
    // Heuristic classification skeleton pending human approval — surface the
    // low-confidence calls so the agent leads the analyst there.
    classification_review: summarizeClassification(terrain.classified_indices),
    blind_spots: terrain.blind_spots,
    capabilities,
    collection_errors: profile.collection_errors,
  };
}

/** Roll up the affordance skeleton: totals by source/confidence + who needs review. */
function summarizeClassification(
  classified: EnvironmentProfile["terrain"]["classified_indices"]
) {
  const items = classified ?? [];
  const withAff = items.filter((o) => o.affordances);
  return {
    total: withAff.length,
    by_source: countBy(withAff, (o) => o.affordances!.source),
    by_confidence: countBy(withAff, (o) => o.affordances!.confidence),
    // Lead with what the heuristic is least sure about — the human's queue.
    needs_review: withAff
      .filter((o) => o.affordances!.confidence !== "high")
      .map((o) => ({
        name: o.name,
        confidence: o.affordances!.confidence,
        huntable: o.affordances!.huntable,
        matchable: o.affordances!.matchable,
        enrichable: o.affordances!.enrichable,
        pivotable: o.affordances!.pivotable,
        evidence: o.affordances!.evidence,
      })),
  };
}

function countBy<T>(items: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const k = key(item);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}
