/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import { registerTrackedTool } from "./tracked-app-tool.js";
import {
  createEmulationRunStore,
  EmulationRunError,
  type EmulationPlan,
  type EmulationRunSnapshot,
} from "./emulation-run-state.js";

const behaviorSchema = z.object({
  id: z.string().min(1),
  api: z.string().min(1).describe("Canonical provider API, not an ATT&CK id"),
  actor: z.string().min(1),
  target: z.string().min(1),
  expected_outcome: z.string().min(1),
  mitre: z.string().optional(),
  result: z.string().optional(),
});

const planSchema = z
  .object({
    schema_version: z.literal(1),
    run_id: z.string().min(1),
    mode: z.enum(["intelligence", "rule", "coverage", "conceptual", "tool"]),
    type: z.enum(["atomic", "micro", "full"]),
    source: z
      .object({
        reference: z.string().min(1),
        kind: z.enum(["published-url", "rule", "gap", "conceptual", "tool"]),
      })
      .passthrough(),
    objective: z.string().min(8),
    scope: z
      .object({
        provider: z.enum(["aws", "azure", "gcp"]),
        scope_id: z.string().min(1),
        region: z.string().min(1),
      })
      .passthrough(),
    behaviors: z.array(behaviorSchema).min(1),
  })
  .passthrough();

const resourceSchema = z.object({
  id: z.string().min(1),
  kind: z.string().min(1),
  origin: z.enum(["provisioned", "orphaned"]),
  cleaned: z.boolean(),
});

const emulationRunSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("init"),
    name: z.string().min(1),
    run_id: z.string().optional(),
  }),
  z.object({
    action: z.literal("status"),
    run_id: z.string().min(1),
  }),
  z.object({
    action: z.literal("set_plan"),
    run_id: z.string().min(1),
    plan: planSchema,
  }),
  z.object({
    action: z.literal("approve"),
    run_id: z.string().min(1),
    plan_digest: z.string().min(16),
  }),
  z.object({
    action: z.literal("advance"),
    run_id: z.string().min(1),
  }),
  z.object({
    action: z.literal("record_behavior"),
    run_id: z.string().min(1),
    behavior: behaviorSchema,
  }),
  z.object({
    action: z.literal("record_resource"),
    run_id: z.string().min(1),
    resource: resourceSchema,
  }),
  z.object({
    action: z.literal("set_detection_outcome"),
    run_id: z.string().min(1),
    detection_outcome: z.enum(["pending", "verified", "gaps", "no_telem"]),
  }),
  z.object({
    action: z.literal("finalize"),
    run_id: z.string().min(1),
    residual_count: z.number().int().min(0),
  }),
  z.object({
    action: z.literal("block"),
    run_id: z.string().min(1),
    reason: z.string().min(1),
  }),
]);

export interface EmulationRunToolDeps {
  readonly analytics: AnalyticsClient;
  readonly store?: ReturnType<typeof createEmulationRunStore>;
}

function textResult(snapshot: EmulationRunSnapshot, isError = false) {
  return {
    isError,
    content: [{ type: "text" as const, text: JSON.stringify(snapshot) }],
  };
}

export function registerEmulationRunTools(
  server: McpServer,
  deps: EmulationRunToolDeps
): void {
  const store = deps.store ?? createEmulationRunStore();

  registerTrackedTool(
    deps.analytics,
    server,
    "emulation-run",
    {
      title: "Cloud Emulation Run Harness",
      description:
        "State machine for a cloud threat-emulation run. Does not execute cloud APIs and has no UI. Use action=init, set_plan, approve (only after the engineer says yes), advance, record_behavior, record_resource, set_detection_outcome, status, finalize, or block. Illegal phase transitions return an error with allowed_actions. stop=true means halt and wait for the engineer.",
      inputSchema: emulationRunSchema,
    },
    async (input) => {
      try {
        const snapshot = dispatch(store, input);
        return textResult(snapshot, snapshot.ok === false);
      } catch (err) {
        if (err instanceof EmulationRunError) {
          return textResult(err.snapshot, true);
        }
        const message = err instanceof Error ? err.message : String(err);
        return textResult(
          {
            ok: false,
            error: message,
            phase: "blocked",
            run_id: "unknown",
            run_dir: "",
            allowed_actions: ["init"],
          },
          true
        );
      }
    }
  );
}

function dispatch(
  store: ReturnType<typeof createEmulationRunStore>,
  input: z.infer<typeof emulationRunSchema>
): EmulationRunSnapshot {
  switch (input.action) {
    case "init":
      return store.init({ name: input.name, run_id: input.run_id });
    case "status":
      return store.status(input.run_id);
    case "set_plan":
      return store.setPlan(input.run_id, input.plan as EmulationPlan);
    case "approve":
      return store.approve(input.run_id, input.plan_digest);
    case "advance":
      return store.advance(input.run_id);
    case "record_behavior":
      return store.recordBehavior(input.run_id, input.behavior);
    case "record_resource":
      return store.recordResource(input.run_id, input.resource);
    case "set_detection_outcome":
      return store.setDetectionOutcome(input.run_id, input.detection_outcome);
    case "finalize":
      return store.finalize(input.run_id, { residual_count: input.residual_count });
    case "block":
      return store.block(input.run_id, input.reason);
    default: {
      const _exhaustive: never = input;
      return _exhaustive;
    }
  }
}
