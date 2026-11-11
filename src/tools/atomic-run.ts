/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  AtomicRunError,
  createAtomicRunStore,
  type AtomicPlan,
  type AtomicRunSnapshot,
} from "./atomic-run-state.js";
import {
  atomicPlanSchema,
  coverageRecordSchema,
  executionRecordSchema,
  resourceSchema,
} from "./atomic-schemas.js";

const atomicRunSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("init"), name: z.string().min(1), run_id: z.string().optional() }),
  z.object({ action: z.literal("status"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("set_plan"), run_id: z.string().min(1), plan: atomicPlanSchema }),
  z.object({
    action: z.literal("approve"),
    run_id: z.string().min(1),
    plan_digest: z.string().regex(/^[0-9a-f]{64}$/i),
  }),
  z.object({ action: z.literal("advance"), run_id: z.string().min(1) }),
  z.object({
    action: z.literal("record_resource"),
    run_id: z.string().min(1),
    resource: resourceSchema,
  }),
  z.object({
    action: z.literal("record_execution"),
    run_id: z.string().min(1),
    execution: executionRecordSchema,
  }),
  z.object({
    action: z.literal("record_coverage"),
    run_id: z.string().min(1),
    coverage: coverageRecordSchema,
  }),
  z.object({
    action: z.literal("set_coverage_outcome"),
    run_id: z.string().min(1),
    coverage_outcome: z.enum(["verified", "gaps", "no_telem", "mixed", "not_applicable"]),
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

// MCP clients require a top-level object schema. Publishing a top-level Zod
// discriminated union currently collapses to { type: "object", properties: {} }
// in tools/list. Keep the union as the authoritative runtime validator and use
// this object-shaped superset only for tool discovery.
const atomicRunToolSchema = z.object({
  action: z.enum([
    "init",
    "status",
    "set_plan",
    "approve",
    "advance",
    "record_resource",
    "record_execution",
    "record_coverage",
    "set_coverage_outcome",
    "finalize",
    "block",
  ]),
  name: z.string().min(1).optional(),
  run_id: z.string().min(1).optional(),
  plan: atomicPlanSchema.optional(),
  plan_digest: z.string().regex(/^[0-9a-f]{64}$/i).optional(),
  resource: resourceSchema.optional(),
  execution: executionRecordSchema.optional(),
  coverage: coverageRecordSchema.optional(),
  coverage_outcome: z.enum(["verified", "gaps", "no_telem", "mixed", "not_applicable"]).optional(),
  residual_count: z.number().int().min(0).optional(),
  reason: z.string().min(1).optional(),
});

export function textResult(value: unknown, isError = false) {
  return {
    isError,
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
  };
}

export function registerAtomicRunTool(
  server: McpServer,
  store = createAtomicRunStore()
): void {
  server.registerTool(
    "atomic-run",
    {
      title: "Linux Atomic Run Harness",
      description:
        "Fail-closed state machine for one Atomic Red Team Linux engagement. It never runs a test itself. Use init, set_plan, digest-bound approve, advance, record_resource, record_execution, record_coverage, set_coverage_outcome, finalize, status, or block. Illegal transitions return allowed_actions. stop=true means halt for the engineer.",
      inputSchema: atomicRunToolSchema,
    },
    async (input) => {
      try {
        const result = dispatch(store, atomicRunSchema.parse(input));
        return textResult(result, !result.ok);
      } catch (error) {
        if (error instanceof AtomicRunError) return textResult(error.snapshot, true);
        const message = error instanceof Error ? error.message : String(error);
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
  store: ReturnType<typeof createAtomicRunStore>,
  input: z.infer<typeof atomicRunSchema>
): AtomicRunSnapshot {
  switch (input.action) {
    case "init":
      return store.init({ name: input.name, run_id: input.run_id });
    case "status":
      return store.status(input.run_id);
    case "set_plan":
      return store.setPlan(input.run_id, input.plan as AtomicPlan);
    case "approve":
      return store.approve(input.run_id, input.plan_digest);
    case "advance":
      return store.advance(input.run_id);
    case "record_resource":
      return store.recordResource(input.run_id, input.resource);
    case "record_execution":
      return store.recordExecution(input.run_id, input.execution);
    case "record_coverage":
      return store.recordCoverage(input.run_id, input.coverage);
    case "set_coverage_outcome":
      return store.setCoverageOutcome(input.run_id, input.coverage_outcome);
    case "finalize":
      return store.finalize(input.run_id, { residual_count: input.residual_count });
    case "block":
      return store.block(input.run_id, input.reason);
    default: {
      const neverInput: never = input;
      return neverInput;
    }
  }
}
