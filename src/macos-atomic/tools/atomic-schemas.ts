/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { z } from "zod";

export const jsonScalarSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.null(),
]);

export const queryPlanSchema = z.object({
  indices: z.array(z.string().min(1)).min(1),
  query: z.record(z.string(), z.unknown()),
});

export const fixtureSchema = z.object({
  input_name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
  content_base64: z
    .string()
    .min(4)
    .max(131_072)
    .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
  sha256: z.string().regex(/^[0-9a-f]{64}$/i),
  mode: z.enum(["0644", "0755"]).default("0644"),
  description: z.string().min(1).optional(),
});

export const sourceAssetSchema = z.object({
  path: z
    .string()
    .min(1)
    .max(4_096)
    .regex(/^(?!\/)(?!.*(?:^|\/)\.{1,2}(?:\/|$))(?!.*\/\/)(?!.*\/$)(?!.*[\0\r\n\\]).+$/),
  sha256: z.string().regex(/^[0-9a-f]{64}$/i),
  size: z.number().int().min(0).max(1_073_741_824),
});

export const approvedPackageSchema = z.object({
  manager: z.literal("brew"),
  name: z.string().regex(/^[a-z0-9][a-z0-9+@.-]{0,79}$/),
  version: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}$/).optional(),
  reason: z.string().min(1).max(500),
});

const outputNeedleSchema = z.string().min(1).max(4_096);
const targetPathSchema = z.string().regex(/^\/[^\0\r\n]{1,4095}$/);

export const successCriterionSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("stdout_contains"), value: outputNeedleSchema }),
  z.object({ kind: z.literal("stderr_contains"), value: outputNeedleSchema }),
  z.object({ kind: z.literal("target_path_exists"), path: targetPathSchema }),
  z.object({ kind: z.literal("target_path_absent"), path: targetPathSchema }),
  z.object({
    kind: z.literal("target_path_contains"),
    path: targetPathSchema,
    value: outputNeedleSchema,
  }),
  z.object({
    kind: z.literal("target_path_not_contains"),
    path: targetPathSchema,
    value: outputNeedleSchema,
  }),
  z.object({ kind: z.literal("target_rebooted") }),
  z.object({ kind: z.literal("target_stopped") }),
  z.object({
    kind: z.literal("manual_evidence"),
    description: z.string().min(1).max(1_000),
  }),
]);

export const setupStepSchema = z.object({
  description: z.string().min(1).max(500),
  command: z.array(z.string().min(1).max(4_096)).min(1).max(64),
  elevated: z.boolean().default(false),
});

export const targetCapabilitySchema = z.enum([
  "shell",
  "powershell",
  "launchd",
  "kernel",
  "network",
  "gui",
  "browser",
  "interactive",
  "reboot",
  "special_runtime",
  "endpoint_security",
  "full_disk_access",
  "tcc",
  "sip",
  "real_hardware",
]);

const manualExecutionSchema = z.object({
  reviewed_steps: z.array(z.string().min(1).max(4_000)).min(1).max(100),
  evidence_requirements: z.array(z.string().min(1).max(1_000)).min(1).max(20),
  cleanup_steps: z.array(z.string().min(1).max(4_000)).max(100).optional(),
});

export const elasticAgentPlanSchema = z.object({
  stack_version: z.string().regex(/^\d+\.\d+\.\d+$/),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  kibana_url: z
    .string()
    .url()
    .refine((value) => {
      const parsed = new URL(value);
      return parsed.protocol === "https:" && !parsed.username && !parsed.password;
    }, {
      message: "Kibana URL must use HTTPS and must not contain credentials",
    }),
  fleet_url: z
    .string()
    .url()
    .refine((value) => {
      const parsed = new URL(value);
      return parsed.protocol === "https:" && !parsed.username && !parsed.password;
    }, {
      message: "Fleet URL must use HTTPS and must not contain credentials",
    }),
  fleet_server_host_id: z.string().min(1),
  agent_policy_id: z.string().min(1),
  agent_policy_name: z.string().min(1),
  agent_policy_revision: z.number().int().min(1),
  elastic_defend_package_policy_id: z.string().min(1),
  elastic_defend_package_version: z.string().min(1),
  elasticsearch_output_id: z.string().min(1),
  elasticsearch_url: z
    .string()
    .url()
    .refine((value) => {
      const parsed = new URL(value);
      return parsed.protocol === "https:" && !parsed.username && !parsed.password;
    }, {
      message: "Elasticsearch URL must use HTTPS and must not contain credentials",
    }),
  ca_sha256: z.string().regex(/^[0-9a-f]{64}$/i).optional(),
  insecure: z.boolean().default(false),
  health_timeout_seconds: z.number().int().min(30).max(900).default(300),
});

export const testPlanSchema = z.object({
  technique_id: z.string().regex(/^T\d{4}(?:\.\d{3})?$/),
  test_guid: z.string().uuid(),
  name: z.string().min(1),
  executor: z.string().min(1),
  execution_mode: z.enum(["runner", "operator"]),
  execution_adapter: z.enum(["bash_interactive"]).optional(),
  elevation_required: z.boolean(),
  required_capabilities: z.array(targetCapabilitySchema).max(20),
  definition_digest: z.string().regex(/^[0-9a-f]{64}$/i),
  inputs: z.record(z.string(), jsonScalarSchema),
  expected_outcome: z.string().min(1),
  success_criteria: z.array(successCriterionSchema).min(1).max(10),
  cleanup_expected: z.boolean(),
  risk_flags: z.array(z.string()),
  manual: manualExecutionSchema.optional(),
  fixtures: z.array(fixtureSchema).max(20).optional(),
  source_assets: z.array(sourceAssetSchema).max(500).optional(),
  telemetry: z
    .object({
      raw: queryPlanSchema.optional(),
      alerts: queryPlanSchema.optional(),
      correlation_fields: z.array(z.string()).optional(),
    })
    .optional(),
}).superRefine((test, context) => {
  const manualExecutor = test.executor.toLowerCase().includes("manual");
  if (
    test.execution_adapter === "bash_interactive" &&
    !["sh", "bash"].includes(test.executor.toLowerCase())
  ) {
    context.addIssue({
      code: "custom",
      path: ["execution_adapter"],
      message: "bash_interactive is allowed only for sh or bash executors",
    });
  }
  if (manualExecutor && test.execution_mode !== "operator") {
    context.addIssue({
      code: "custom",
      path: ["execution_mode"],
      message: "manual executors require execution_mode=operator",
    });
  }
  if (manualExecutor && !test.manual) {
    context.addIssue({
      code: "custom",
      path: ["manual"],
      message: "manual executors require reviewed operator steps",
    });
  }
  if (
    manualExecutor &&
    !test.success_criteria.some((criterion) => criterion.kind === "manual_evidence")
  ) {
    context.addIssue({
      code: "custom",
      path: ["success_criteria"],
      message: "manual executors require manual_evidence success criteria",
    });
  }
  if (manualExecutor && test.cleanup_expected && !test.manual?.cleanup_steps?.length) {
    context.addIssue({
      code: "custom",
      path: ["manual", "cleanup_steps"],
      message: "manual executors with cleanup_expected require cleanup steps",
    });
  }
  if (!manualExecutor && test.execution_mode !== "runner") {
    context.addIssue({
      code: "custom",
      path: ["execution_mode"],
      message: "automated executors require execution_mode=runner",
    });
  }
  if (!manualExecutor && test.manual) {
    context.addIssue({
      code: "custom",
      path: ["manual"],
      message: "manual procedure is allowed only for manual executors",
    });
  }
});

export const atomicPlanSchema = z.object({
  schema_version: z.literal(3),
  run_id: z.string().min(3),
  mode: z.enum(["atomic", "rule", "coverage", "regression"]),
  type: z.enum(["atomic", "micro", "full"]),
  source: z.object({
    kind: z.enum(["atomic-red-team", "rule", "gap", "baseline"]),
    reference: z.string().min(1),
    repository: z.string().min(1),
    revision: z.string().regex(/^[0-9a-f]{40}$/i),
    catalog_digest: z.string().regex(/^[0-9a-f]{64}$/i),
  }),
  runner: z.object({
    repository: z.string().min(1),
    revision: z.string().regex(/^[0-9a-f]{40}$/i),
  }),
  objective: z.string().min(8),
  scope: z.object({
    target_kind: z.enum(["tart", "ssh"]),
    target_id: z.string().min(2),
    target_profile: z.enum(["server", "desktop", "custom"]),
    execution_user: z.string().regex(/^[a-z_][a-z0-9_-]{0,31}$/),
    capabilities: z.array(targetCapabilitySchema).min(1).max(20),
    platform: z.literal("macos"),
    distro: z.string().regex(/^macos-(?:1[2345]|26)$/),
    architecture: z.enum(["arm64", "x86_64"]),
    target_image: z
      .string()
      .regex(/^ghcr\.io\/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$/i)
      .optional(),
    ssh_identity_file: z.string().min(1).max(4_096).optional(),
    classification: z.literal("owned-disposable-lab"),
    lifecycle: z.enum(["ephemeral", "existing"]),
    network: z.enum(["isolated", "egress-only", "custom"]),
  }),
  controls: z.object({
    ttl_minutes: z.number().int().min(1).max(10_080),
    allow_reboot: z.boolean(),
    allow_external_targets: z.boolean(),
    allow_destructive: z.boolean(),
    snapshot_before: z.boolean(),
    allow_setup_commands: z.boolean().default(false),
    allow_tcc_changes: z.boolean().default(false),
    allow_sip_changes: z.boolean().default(false),
  }),
  target_prerequisites: z
    .object({
      packages: z.array(approvedPackageSchema).min(1).max(100),
    })
    .optional(),
  setup_steps: z.array(setupStepSchema).min(1).max(20).optional(),
  instrumentation: z
    .object({
      elastic_agent: elasticAgentPlanSchema,
    })
    .optional(),
  tests: z.array(testPlanSchema).min(1),
}).superRefine((plan, context) => {
  if (plan.setup_steps?.length && !plan.controls.allow_setup_commands) {
    context.addIssue({
      code: "custom",
      path: ["setup_steps"],
      message:
        "setup_steps require controls.allow_setup_commands=true; approve the digest only after reviewing the exact commands",
    });
  }
  if (plan.scope.target_kind === "tart" && !plan.scope.target_image) {
    context.addIssue({
      code: "custom",
      path: ["scope", "target_image"],
      message: "Tart targets require an immutable target_image reference",
    });
  }
  if (plan.scope.target_kind === "ssh" && !plan.scope.ssh_identity_file) {
    context.addIssue({
      code: "custom",
      path: ["scope", "ssh_identity_file"],
      message: "SSH targets require an identity file",
    });
  }
});

export const resourceSchema = z.object({
  id: z.string().min(1),
  kind: z.string().min(1),
  origin: z.enum(["provisioned", "existing", "orphaned"]),
  cleaned: z.boolean(),
  notes: z.string().optional(),
});

export const executionRecordSchema = z.object({
  test_guid: z.string().uuid(),
  stage: z.enum(["prereq", "execute", "manual", "cleanup"]),
  status: z.enum(["passed", "failed", "skipped", "blocked"]),
  started_at: z.string().datetime(),
  ended_at: z.string().datetime(),
  exit_code: z.number().int().optional(),
  behavior_success: z.boolean().optional(),
  evidence_path: z.string().optional(),
  notes: z.string().optional(),
});

export const coverageRecordSchema = z.object({
  test_guid: z.string().uuid(),
  outcome: z.enum(["detected", "missed", "no_telemetry", "not_applicable"]),
  raw_event_count: z.number().int().min(0).optional(),
  alert_count: z.number().int().min(0).optional(),
  detector: z.string().optional(),
  evidence: z.string().optional(),
  reason: z.string().optional(),
}).superRefine((record, context) => {
  if (record.outcome === "not_applicable" && !record.reason?.trim()) {
    context.addIssue({
      code: "custom",
      path: ["reason"],
      message: "not_applicable coverage requires a reason",
    });
  }
});
