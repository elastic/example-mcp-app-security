/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { sha256 } from "../shared/json.js";
import {
  COMMIT_RE,
  GUID_RE,
  TECHNIQUE_ID_RE,
  assertSafeRunId,
  assertSafeTargetId,
} from "../shared/validation.js";

export const ATOMIC_PHASES = [
  "planning",
  "awaiting_approval",
  "approved",
  "provisioning",
  "executing",
  "verifying",
  "covering",
  "reporting",
  "cleaning",
  "completed",
  "completed_with_findings",
  "cleanup_failed",
  "blocked",
] as const;

export type AtomicPhase = (typeof ATOMIC_PHASES)[number];
export type AtomicMode = "atomic" | "rule" | "coverage" | "regression";
export type AtomicType = "atomic" | "micro" | "full";
export type TargetKind = "tart" | "ssh";
export type CoverageOutcome =
  | "pending"
  | "verified"
  | "gaps"
  | "no_telem"
  | "mixed"
  | "not_applicable";

const TERMINAL_PHASES = new Set<AtomicPhase>([
  "completed",
  "completed_with_findings",
  "cleanup_failed",
  "blocked",
]);

const ADVANCE: Partial<Record<AtomicPhase, AtomicPhase>> = {
  approved: "provisioning",
  provisioning: "executing",
  executing: "verifying",
  verifying: "covering",
  covering: "reporting",
  reporting: "cleaning",
};

const PHASE_READ: Partial<Record<AtomicPhase, string>> = {
  planning: "skills/macos-atomic-emulation/references/engagement-planning.md",
  awaiting_approval: "skills/macos-atomic-emulation/references/engagement-planning.md",
  approved: "skills/macos-atomic-emulation/references/execution-guide.md",
  provisioning: "skills/macos-atomic-emulation/references/execution-guide.md",
  executing: "skills/macos-atomic-emulation/references/execution-guide.md",
  verifying: "skills/macos-atomic-emulation/references/coverage-and-reporting.md",
  covering: "skills/macos-atomic-emulation/references/coverage-and-reporting.md",
  reporting: "skills/macos-atomic-emulation/references/coverage-and-reporting.md",
  cleaning: "skills/macos-atomic-emulation/references/execution-guide.md",
};

export type JsonScalar = string | number | boolean | null;
export type TargetCapability =
  | "shell"
  | "powershell"
  | "launchd"
  | "kernel"
  | "network"
  | "gui"
  | "browser"
  | "interactive"
  | "reboot"
  | "special_runtime"
  | "endpoint_security"
  | "full_disk_access"
  | "tcc"
  | "sip"
  | "real_hardware";

export type AtomicQueryPlan = {
  readonly indices: readonly string[];
  readonly query: Readonly<Record<string, unknown>>;
};

export type AtomicTestPlan = {
  readonly technique_id: string;
  readonly test_guid: string;
  readonly name: string;
  readonly executor: string;
  readonly execution_mode: "runner" | "operator";
  readonly execution_adapter?: "bash_interactive";
  readonly elevation_required: boolean;
  readonly required_capabilities: readonly TargetCapability[];
  readonly definition_digest: string;
  readonly inputs: Readonly<Record<string, JsonScalar>>;
  readonly expected_outcome: string;
  readonly success_criteria: readonly (
    | { readonly kind: "stdout_contains"; readonly value: string }
    | { readonly kind: "stderr_contains"; readonly value: string }
    | { readonly kind: "target_path_exists"; readonly path: string }
    | { readonly kind: "target_path_absent"; readonly path: string }
    | { readonly kind: "target_path_contains"; readonly path: string; readonly value: string }
    | { readonly kind: "target_path_not_contains"; readonly path: string; readonly value: string }
    | { readonly kind: "target_rebooted" }
    | { readonly kind: "target_stopped" }
    | { readonly kind: "manual_evidence"; readonly description: string }
  )[];
  readonly cleanup_expected: boolean;
  readonly risk_flags: readonly string[];
  readonly manual?: {
    readonly reviewed_steps: readonly string[];
    readonly evidence_requirements: readonly string[];
    readonly cleanup_steps?: readonly string[];
  };
  readonly fixtures?: readonly {
    readonly input_name: string;
    readonly content_base64: string;
    readonly sha256: string;
    readonly mode: "0644" | "0755";
    readonly description?: string;
  }[];
  readonly source_assets?: readonly {
    readonly path: string;
    readonly sha256: string;
    readonly size: number;
  }[];
  readonly telemetry?: {
    readonly raw?: AtomicQueryPlan;
    readonly alerts?: AtomicQueryPlan;
    readonly correlation_fields?: readonly string[];
  };
};

export type AtomicPlan = {
  readonly schema_version: 3;
  readonly run_id: string;
  readonly mode: AtomicMode;
  readonly type: AtomicType;
  readonly source: {
    readonly kind: "atomic-red-team" | "rule" | "gap" | "baseline";
    readonly reference: string;
    readonly repository: string;
    readonly revision: string;
    readonly catalog_digest: string;
  };
  readonly runner: {
    readonly repository: string;
    readonly revision: string;
  };
  readonly objective: string;
  readonly scope: {
    readonly target_kind: TargetKind;
    readonly target_id: string;
    readonly target_profile: "server" | "desktop" | "custom";
    readonly execution_user: string;
    readonly capabilities: readonly TargetCapability[];
    readonly platform: "macos";
    readonly distro: string;
    readonly architecture: "arm64" | "x86_64";
    readonly target_image?: string;
    readonly ssh_identity_file?: string;
    readonly classification: "owned-disposable-lab";
    readonly lifecycle: "ephemeral" | "existing";
    readonly network: "isolated" | "egress-only" | "custom";
  };
  readonly controls: {
    readonly ttl_minutes: number;
    readonly allow_reboot: boolean;
    readonly allow_external_targets: boolean;
    readonly allow_destructive: boolean;
    readonly snapshot_before: boolean;
    readonly allow_setup_commands?: boolean;
    readonly allow_tcc_changes?: boolean;
    readonly allow_sip_changes?: boolean;
  };
  readonly target_prerequisites?: {
    readonly packages: readonly {
      readonly manager: "brew";
      readonly name: string;
      readonly version?: string;
      readonly reason: string;
    }[];
  };
  readonly setup_steps?: readonly {
    readonly description: string;
    readonly command: readonly string[];
    readonly elevated?: boolean;
  }[];
  readonly instrumentation?: {
    readonly elastic_agent: {
      readonly stack_version: string;
      readonly version: string;
      readonly kibana_url: string;
      readonly fleet_url: string;
      readonly fleet_server_host_id: string;
      readonly agent_policy_id: string;
      readonly agent_policy_name: string;
      readonly agent_policy_revision: number;
      readonly elastic_defend_package_policy_id: string;
      readonly elastic_defend_package_version: string;
      readonly elasticsearch_output_id: string;
      readonly elasticsearch_url: string;
      readonly ca_sha256?: string;
      readonly insecure: boolean;
      readonly health_timeout_seconds: number;
    };
  };
  readonly tests: readonly AtomicTestPlan[];
};

export type AtomicResource = {
  readonly id: string;
  readonly kind: string;
  readonly origin: "provisioned" | "existing" | "orphaned";
  readonly cleaned: boolean;
  readonly notes?: string;
};

export type ExecutionStage = "prereq" | "execute" | "manual" | "cleanup";
export type ExecutionStatus = "passed" | "failed" | "skipped" | "blocked";

export type AtomicExecutionRecord = {
  readonly test_guid: string;
  readonly stage: ExecutionStage;
  readonly status: ExecutionStatus;
  readonly started_at: string;
  readonly ended_at: string;
  readonly exit_code?: number;
  readonly behavior_success?: boolean;
  readonly evidence_path?: string;
  readonly notes?: string;
};

export type AtomicCoverageRecord = {
  readonly test_guid: string;
  readonly outcome: "detected" | "missed" | "no_telemetry" | "not_applicable";
  readonly raw_event_count?: number;
  readonly alert_count?: number;
  readonly detector?: string;
  readonly evidence?: string;
  readonly reason?: string;
};

export type AtomicRunState = {
  readonly schema_version: 1;
  readonly run_id: string;
  readonly name: string;
  readonly phase: AtomicPhase;
  readonly created_at: string;
  readonly plan_digest?: string;
  readonly approved_at?: string;
  readonly terminal_at?: string;
  readonly coverage_outcome: CoverageOutcome;
  readonly residual_count?: number;
  readonly blocked_reason?: string;
};

export type AtomicRunSnapshot = {
  readonly ok: boolean;
  readonly error?: string;
  readonly phase: AtomicPhase;
  readonly run_id: string;
  readonly run_dir: string;
  readonly plan_digest?: string;
  readonly allowed_actions: readonly string[];
  readonly read?: string;
  readonly stop?: boolean;
  readonly stop_reason?: string;
  readonly coverage_outcome: CoverageOutcome;
  readonly residual_count?: number;
  readonly planned_test_count: number;
  readonly execution_count: number;
  readonly coverage_count: number;
  readonly resource_count: number;
};

export type LoadedRun = {
  dir: string;
  state: AtomicRunState;
  plan?: AtomicPlan;
  resources: AtomicResource[];
  executions: AtomicExecutionRecord[];
  coverage: AtomicCoverageRecord[];
};

export class AtomicRunError extends Error {
  constructor(
    message: string,
    readonly snapshot: AtomicRunSnapshot
  ) {
    super(message);
    this.name = "AtomicRunError";
  }
}

export function planDigest(plan: AtomicPlan): string {
  return sha256(plan);
}

export function createAtomicRunStore(
  options: { readonly baseDir?: string } = {}
) {
  const baseDir = path.resolve(
    options.baseDir ?? process.env.MACOS_ATOMIC_RUNS_DIR ?? path.join(process.cwd(), "macos-atomic-runs")
  );

  function runDirFor(runId: string): string {
    assertSafeRunId(runId);
    const dir = path.resolve(baseDir, runId);
    const relative = path.relative(baseDir, dir);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error("run_id resolves outside the macos-atomic-runs directory");
    }
    return dir;
  }

  function readJson<T>(file: string): T | undefined {
    if (!fs.existsSync(file)) return undefined;
    return JSON.parse(fs.readFileSync(file, "utf8")) as T;
  }

  function writeJson(file: string, value: unknown): void {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const temporary = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    fs.renameSync(temporary, file);
  }

  function load(runId: string): LoadedRun {
    const dir = runDirFor(runId);
    const state = readJson<AtomicRunState>(path.join(dir, "run.json"));
    if (!state) throw new Error(`No atomic run at ${dir}`);
    return {
      dir,
      state,
      plan: readJson<AtomicPlan>(path.join(dir, "plan.json")),
      resources: readJson<AtomicResource[]>(path.join(dir, "resources.json")) ?? [],
      executions:
        readJson<AtomicExecutionRecord[]>(path.join(dir, "executions.json")) ?? [],
      coverage: readJson<AtomicCoverageRecord[]>(path.join(dir, "coverage.json")) ?? [],
    };
  }

  function saveState(dir: string, state: AtomicRunState): void {
    writeJson(path.join(dir, "run.json"), state);
  }

  function snapshot(
    loaded: LoadedRun,
    extras: Partial<AtomicRunSnapshot> = {}
  ): AtomicRunSnapshot {
    const awaiting = loaded.state.phase === "awaiting_approval";
    return {
      ok: extras.ok ?? true,
      phase: loaded.state.phase,
      run_id: loaded.state.run_id,
      run_dir: loaded.dir,
      plan_digest:
        loaded.state.plan_digest ??
        (loaded.plan ? planDigest(loaded.plan) : undefined),
      allowed_actions: allowedActions(loaded.state.phase),
      read: PHASE_READ[loaded.state.phase],
      stop: extras.stop ?? awaiting,
      stop_reason:
        extras.stop_reason ??
        (awaiting
          ? "Present the exact plan and digest. Call approve only after the engineer explicitly approves it."
          : undefined),
      coverage_outcome: loaded.state.coverage_outcome,
      residual_count: loaded.state.residual_count,
      planned_test_count: loaded.plan?.tests.length ?? 0,
      execution_count: loaded.executions.length,
      coverage_count: loaded.coverage.length,
      resource_count: loaded.resources.length,
      ...extras,
    };
  }

  function reject(loaded: LoadedRun, error: string): never {
    throw new AtomicRunError(error, snapshot(loaded, { ok: false, error }));
  }

  function requirePhase(loaded: LoadedRun, phases: readonly AtomicPhase[]): void {
    if (!phases.includes(loaded.state.phase)) {
      reject(loaded, `Phase is ${loaded.state.phase}; allowed: ${phases.join(", ")}`);
    }
  }

  function requirePlan(loaded: LoadedRun): AtomicPlan {
    if (!loaded.plan) reject(loaded, "No approved plan is stored for this run");
    return loaded.plan;
  }

  function validatePlan(runId: string, plan: AtomicPlan, loaded: LoadedRun): void {
    if (plan.run_id !== runId) {
      reject(loaded, `plan.run_id ${plan.run_id} does not match run ${runId}`);
    }
    if (!plan.tests.length) reject(loaded, "plan.tests must contain at least one test");
    if (!COMMIT_RE.test(plan.source.revision)) {
      reject(loaded, "source.revision must be an immutable 40-character git commit");
    }
    if (!COMMIT_RE.test(plan.runner.revision)) {
      reject(loaded, "runner.revision must be an immutable 40-character git commit");
    }
    for (const [label, repository] of [
      ["source.repository", plan.source.repository],
      ["runner.repository", plan.runner.repository],
    ] as const) {
      try {
        const url = new URL(repository);
        if (url.protocol !== "https:" || url.username || url.password) {
          reject(loaded, `${label} must be a credential-free HTTPS URL`);
        }
      } catch (error) {
        if (error instanceof AtomicRunError) throw error;
        reject(loaded, `${label} must be a valid URL`);
      }
    }
    try {
      assertSafeTargetId(plan.scope.target_id);
    } catch (error) {
      reject(loaded, error instanceof Error ? error.message : String(error));
    }
    if (!/^[0-9a-f]{64}$/i.test(plan.source.catalog_digest)) {
      reject(loaded, "source.catalog_digest must be a SHA-256 digest");
    }
    if (
      plan.scope.target_profile === "desktop" &&
      plan.scope.lifecycle === "ephemeral" &&
      plan.scope.target_kind !== "tart"
    ) {
      reject(
        loaded,
        "an ephemeral desktop target_profile requires target_kind=tart"
      );
    }
    if (plan.scope.target_kind === "tart" && plan.scope.lifecycle !== "ephemeral") {
      reject(loaded, "Tart targets must be ephemeral");
    }
    if (plan.scope.target_kind === "tart" && !plan.scope.target_image?.trim()) {
      reject(loaded, "Tart targets require a digest-approved target_image");
    }
    if (
      plan.scope.target_kind === "ssh" &&
      (!plan.scope.ssh_identity_file || !path.isAbsolute(plan.scope.ssh_identity_file))
    ) {
      reject(loaded, "SSH targets require an absolute scope.ssh_identity_file");
    }
    if (
      plan.scope.ssh_identity_file &&
      !path.isAbsolute(plan.scope.ssh_identity_file)
    ) {
      reject(loaded, "scope.ssh_identity_file must be an absolute path when provided");
    }
    if (
      plan.scope.capabilities.some((capability) =>
        ["gui", "browser", "interactive"].includes(capability)
      ) &&
      plan.scope.target_profile !== "desktop" &&
      plan.scope.target_profile !== "custom"
    ) {
      reject(loaded, "GUI, browser, and interactive capabilities require a desktop/custom target");
    }
    if (
      plan.scope.capabilities.includes("interactive") &&
      plan.scope.lifecycle !== "existing" &&
      !(plan.scope.target_kind === "tart" && plan.scope.target_profile === "desktop")
    ) {
      reject(loaded, "Interactive operator access requires an existing target or a fresh Tart desktop");
    }
    const expectedKind: Record<AtomicMode, AtomicPlan["source"]["kind"]> = {
      atomic: "atomic-red-team",
      rule: "rule",
      coverage: "gap",
      regression: "baseline",
    };
    if (plan.source.kind !== expectedKind[plan.mode]) {
      reject(loaded, `${plan.mode} runs require source.kind=${expectedKind[plan.mode]}`);
    }
    const guids = new Set<string>();
    const packageNames = new Set<string>();
    const sourceAssets = new Map<string, { readonly sha256: string; readonly size: number }>();
    for (const approvedPackage of plan.target_prerequisites?.packages ?? []) {
      if (packageNames.has(approvedPackage.name)) {
        reject(loaded, `Duplicate approved package ${approvedPackage.name}`);
      }
      packageNames.add(approvedPackage.name);
      if (approvedPackage.manager !== "brew") {
        reject(loaded, "macOS package prerequisites require Homebrew");
      }
    }
    for (const test of plan.tests) {
      if (!TECHNIQUE_ID_RE.test(test.technique_id)) {
        reject(loaded, `Invalid technique_id ${test.technique_id}`);
      }
      if (!GUID_RE.test(test.test_guid)) reject(loaded, `Invalid test_guid ${test.test_guid}`);
      if (guids.has(test.test_guid)) reject(loaded, `Duplicate test_guid ${test.test_guid}`);
      guids.add(test.test_guid);
      if (!/^[0-9a-f]{64}$/i.test(test.definition_digest)) {
        reject(loaded, `Test ${test.test_guid} needs a definition_digest`);
      }
      if (!test.executor || !test.expected_outcome) {
        reject(loaded, `Test ${test.test_guid} needs executor and expected_outcome`);
      }
      const sourceAssetPaths = new Set<string>();
      for (const asset of test.source_assets ?? []) {
        if (
          !asset.path ||
          asset.path.length > 4_096 ||
          asset.path.startsWith("/") ||
          asset.path.includes("\\") ||
          asset.path.includes("\0") ||
          asset.path.includes("\r") ||
          asset.path.includes("\n") ||
          asset.path.split("/").some((part) => !part || part === "." || part === "..")
        ) {
          reject(loaded, `Test ${test.test_guid} has an unsafe source asset path ${asset.path}`);
        }
        if (!/^[0-9a-f]{64}$/i.test(asset.sha256)) {
          reject(loaded, `Test ${test.test_guid} source asset ${asset.path} needs a SHA-256 digest`);
        }
        if (!Number.isSafeInteger(asset.size) || asset.size < 0 || asset.size > 1_073_741_824) {
          reject(loaded, `Test ${test.test_guid} source asset ${asset.path} has an invalid size`);
        }
        if (sourceAssetPaths.has(asset.path)) {
          reject(loaded, `Test ${test.test_guid} repeats source asset ${asset.path}`);
        }
        sourceAssetPaths.add(asset.path);
        const existingAsset = sourceAssets.get(asset.path);
        if (
          existingAsset &&
          (existingAsset.sha256 !== asset.sha256 || existingAsset.size !== asset.size)
        ) {
          reject(loaded, `Conflicting approved metadata for source asset ${asset.path}`);
        }
        sourceAssets.set(asset.path, asset);
      }
      const missingCapabilities = test.required_capabilities.filter(
        (capability) => !plan.scope.capabilities.includes(capability)
      );
      if (missingCapabilities.length) {
        reject(
          loaded,
          `Test ${test.test_guid} requires missing target capabilities: ${missingCapabilities.join(", ")}`
        );
      }
      const manualExecutor = test.executor.toLowerCase().includes("manual");
      if (manualExecutor && (test.execution_mode !== "operator" || !test.manual)) {
        reject(loaded, `Manual test ${test.test_guid} requires an approved operator procedure`);
      }
      if (
        manualExecutor &&
        !test.success_criteria.some((criterion) => criterion.kind === "manual_evidence")
      ) {
        reject(loaded, `Manual test ${test.test_guid} requires manual_evidence success criteria`);
      }
      if (
        manualExecutor &&
        test.cleanup_expected &&
        !test.manual?.cleanup_steps?.length
      ) {
        reject(loaded, `Manual test ${test.test_guid} requires approved cleanup steps`);
      }
      if (
        manualExecutor &&
        test.required_capabilities.includes("browser") &&
        (test.source_assets?.length ?? 0) > 0
      ) {
        const reviewedSteps = test.manual?.reviewed_steps.join("\n") ?? "";
        if (reviewedSteps.includes("/opt/atomic-red-team/atomics/")) {
          reject(
            loaded,
            `Browser test ${test.test_guid} must use its confined-browser-safe staged source assets`
          );
        }
        const stagingPrefix = `AtomicRedTeamAssets/${plan.run_id}/`;
        if (!reviewedSteps.includes(stagingPrefix)) {
          reject(
            loaded,
            `Browser test ${test.test_guid} reviewed steps must reference ${stagingPrefix}`
          );
        }
      }
      if (!manualExecutor && test.execution_mode !== "runner") {
        reject(loaded, `Automated test ${test.test_guid} requires execution_mode=runner`);
      }
      if (
        test.execution_adapter === "bash_interactive" &&
        (plan.scope.platform !== "macos" ||
          !["sh", "bash"].includes(test.executor.toLowerCase()))
      ) {
        reject(
          loaded,
          `Test ${test.test_guid} uses bash_interactive outside a macOS sh/bash executor`
        );
      }
      if (!test.success_criteria?.length) {
        reject(loaded, `Test ${test.test_guid} needs at least one behavior success criterion`);
      }
      if (
        !test.executor.includes("manual") &&
        test.success_criteria.some((criterion) => criterion.kind === "manual_evidence")
      ) {
        reject(loaded, `Automated test ${test.test_guid} cannot use manual_evidence`);
      }
      if (test.risk_flags.includes("destructive") && !plan.controls.allow_destructive) {
        reject(
          loaded,
          `Test ${test.test_guid} is destructive but controls.allow_destructive is false`
        );
      }
      if (test.risk_flags.includes("reboot") && !plan.controls.allow_reboot) {
        reject(loaded, `Test ${test.test_guid} may reboot but allow_reboot is false`);
      }
      if (test.risk_flags.includes("tcc") && !plan.controls.allow_tcc_changes) {
        reject(loaded, `Test ${test.test_guid} may change TCC state but allow_tcc_changes is false`);
      }
      if (test.risk_flags.includes("sip") && !plan.controls.allow_sip_changes) {
        reject(loaded, `Test ${test.test_guid} may change SIP state but allow_sip_changes is false`);
      }
      if (
        test.risk_flags.includes("real_hardware") &&
        !plan.scope.capabilities.includes("real_hardware")
      ) {
        reject(loaded, `Test ${test.test_guid} requires a real-hardware macOS target`);
      }
      if (
        test.risk_flags.includes("external_target") &&
        !plan.controls.allow_external_targets
      ) {
        reject(
          loaded,
          `Test ${test.test_guid} references an external target but allow_external_targets is false`
        );
      }
    }
  }

  return {
    init(input: { readonly name: string; readonly run_id?: string }): AtomicRunSnapshot {
      fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });
      const slug =
        input.name
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, "")
          .slice(0, 40) || "atomic";
      const runId = input.run_id ?? `${slug}-${randomBytes(3).toString("hex")}`;
      const dir = runDirFor(runId);
      if (fs.existsSync(path.join(dir, "run.json"))) {
        throw new Error(`Run ${runId} already exists`);
      }
      const state: AtomicRunState = {
        schema_version: 1,
        run_id: runId,
        name: input.name,
        phase: "planning",
        created_at: new Date().toISOString(),
        coverage_outcome: "pending",
      };
      saveState(dir, state);
      writeJson(path.join(dir, "resources.json"), []);
      writeJson(path.join(dir, "executions.json"), []);
      writeJson(path.join(dir, "coverage.json"), []);
      return snapshot({ dir, state, resources: [], executions: [], coverage: [] });
    },

    status(runId: string): AtomicRunSnapshot {
      return snapshot(load(runId));
    },

    getLoaded(runId: string): Readonly<LoadedRun> {
      return load(runId);
    },

    getApprovedTest(runId: string, testGuid: string): AtomicTestPlan {
      const loaded = load(runId);
      const plan = requirePlan(loaded);
      const test = plan.tests.find((candidate) => candidate.test_guid === testGuid);
      if (!test) reject(loaded, `Test ${testGuid} is not in the digest-approved plan`);
      return test;
    },

    assertPhase(runId: string, phases: readonly AtomicPhase[]): AtomicRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, phases);
      return snapshot(loaded);
    },

    setPlan(runId: string, plan: AtomicPlan): AtomicRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["planning", "awaiting_approval"]);
      validatePlan(runId, plan, loaded);
      const digest = planDigest(plan);
      writeJson(path.join(loaded.dir, "plan.json"), plan);
      const state: AtomicRunState = {
        ...loaded.state,
        phase: "awaiting_approval",
        plan_digest: digest,
        approved_at: undefined,
      };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state, plan });
    },

    approve(runId: string, digest: string): AtomicRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["awaiting_approval"]);
      if (!loaded.state.plan_digest || digest !== loaded.state.plan_digest) {
        reject(
          loaded,
          "plan_digest does not match the stored plan. Call set_plan again if anything changed."
        );
      }
      const state: AtomicRunState = {
        ...loaded.state,
        phase: "approved",
        approved_at: new Date().toISOString(),
      };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state });
    },

    advance(runId: string): AtomicRunSnapshot {
      const loaded = load(runId);
      const next = ADVANCE[loaded.state.phase];
      if (!next) reject(loaded, `Cannot advance from ${loaded.state.phase}`);
      const plan = requirePlan(loaded);
      if (loaded.state.phase === "provisioning") {
        const liveTarget = loaded.resources.some(
          (resource) => resource.kind === "target" && !resource.cleaned
        );
        if (!liveTarget) reject(loaded, "Record a verified target before execution");
      }
      if (loaded.state.phase === "executing") {
        const accounted = new Set(
          loaded.executions
            .filter((record) => record.stage === "execute" || record.stage === "manual")
            .map((record) => record.test_guid)
        );
        const missing = plan.tests.filter((test) => !accounted.has(test.test_guid));
        if (missing.length) {
          reject(
            loaded,
            `Execution is not accounted for: ${missing.map((test) => test.test_guid).join(", ")}`
          );
        }
      }
      if (loaded.state.phase === "covering") {
        if (loaded.state.coverage_outcome === "pending") {
          reject(loaded, "Call set_coverage_outcome before reporting");
        }
        const covered = new Set(loaded.coverage.map((record) => record.test_guid));
        const missing = plan.tests.filter((test) => !covered.has(test.test_guid));
        if (missing.length) {
          reject(
            loaded,
            `Coverage is not accounted for: ${missing.map((test) => test.test_guid).join(", ")}`
          );
        }
        const allNotApplicable = loaded.coverage.every(
          (record) => record.outcome === "not_applicable"
        );
        if (allNotApplicable && loaded.state.coverage_outcome !== "not_applicable") {
          reject(loaded, "Run coverage must be not_applicable when every test is not applicable");
        }
        if (
          loaded.state.coverage_outcome === "not_applicable" &&
          !allNotApplicable
        ) {
          reject(loaded, "Run coverage cannot be not_applicable when an applicable result exists");
        }
      }
      const state: AtomicRunState = { ...loaded.state, phase: next };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state });
    },

    recordResource(runId: string, resource: AtomicResource): AtomicRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["provisioning", "executing", "cleaning"]);
      const resources = [
        ...loaded.resources.filter((candidate) => candidate.id !== resource.id),
        resource,
      ];
      writeJson(path.join(loaded.dir, "resources.json"), resources);
      return snapshot({ ...loaded, resources });
    },

    recordExecution(
      runId: string,
      record: AtomicExecutionRecord
    ): AtomicRunSnapshot {
      const loaded = load(runId);
      const phasesForStage: Record<ExecutionStage, readonly AtomicPhase[]> = {
        prereq: ["provisioning", "executing"],
        execute: ["executing"],
        manual: ["executing"],
        cleanup: ["cleaning"],
      };
      requirePhase(loaded, phasesForStage[record.stage]);
      if (
        record.stage === "prereq" &&
        loaded.state.phase === "executing" &&
        loaded.executions.some(
          (execution) => execution.stage === "execute" || execution.stage === "manual"
        )
      ) {
        reject(loaded, "Prerequisite records cannot be added after behavior execution");
      }
      const plan = requirePlan(loaded);
      if (!plan.tests.some((test) => test.test_guid === record.test_guid)) {
        reject(loaded, `Test ${record.test_guid} is not in the digest-approved plan`);
      }
      if (record.stage === "execute" || record.stage === "manual") {
        if (record.status === "passed" && record.behavior_success !== true) {
          reject(loaded, "Passed execution requires behavior_success=true");
        }
        if (record.status !== "passed" && record.behavior_success === true) {
          reject(loaded, "Only a passed execution may set behavior_success=true");
        }
        if (
          record.stage === "manual" &&
          record.status === "passed" &&
          !record.evidence_path
        ) {
          reject(loaded, "Passed manual execution requires an evidence_path");
        }
        if (record.stage === "manual" && record.status === "passed") {
          const evidenceRoot = path.resolve(loaded.dir, "evidence");
          const evidencePath = path.resolve(record.evidence_path!);
          const relative = path.relative(evidenceRoot, evidencePath);
          if (
            relative.startsWith("..") ||
            path.isAbsolute(relative) ||
            !fs.existsSync(evidencePath)
          ) {
            reject(
              loaded,
              "Passed manual execution evidence must exist beneath the run evidence directory"
            );
          }
        }
      }
      const executions = [
        ...loaded.executions.filter(
          (candidate) =>
            !(
              candidate.test_guid === record.test_guid &&
              candidate.stage === record.stage
            )
        ),
        record,
      ];
      writeJson(path.join(loaded.dir, "executions.json"), executions);
      return snapshot({ ...loaded, executions });
    },

    recordCoverage(
      runId: string,
      record: AtomicCoverageRecord
    ): AtomicRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["covering", "reporting"]);
      const plan = requirePlan(loaded);
      if (!plan.tests.some((test) => test.test_guid === record.test_guid)) {
        reject(loaded, `Test ${record.test_guid} is not in the digest-approved plan`);
      }
      const execution = loaded.executions.find(
        (candidate) =>
          candidate.test_guid === record.test_guid &&
          (candidate.stage === "execute" || candidate.stage === "manual")
      );
      if (
        (!execution || execution.status !== "passed" || execution.behavior_success !== true) &&
        record.outcome !== "not_applicable"
      ) {
        reject(
          loaded,
          `Coverage for ${record.test_guid} must be not_applicable because behavior success was not confirmed`
        );
      }
      const coverage = [
        ...loaded.coverage.filter(
          (candidate) => candidate.test_guid !== record.test_guid
        ),
        record,
      ];
      writeJson(path.join(loaded.dir, "coverage.json"), coverage);
      return snapshot({ ...loaded, coverage });
    },

    setCoverageOutcome(
      runId: string,
      coverageOutcome: CoverageOutcome
    ): AtomicRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["covering", "reporting"]);
      if (coverageOutcome === "pending") {
        reject(loaded, "Coverage outcome must be final before reporting");
      }
      if (
        loaded.coverage.length > 0 &&
        loaded.coverage.every((record) => record.outcome === "not_applicable") &&
        coverageOutcome !== "not_applicable"
      ) {
        reject(loaded, "Run coverage must be not_applicable when every test is not applicable");
      }
      if (
        coverageOutcome === "not_applicable" &&
        loaded.coverage.some((record) => record.outcome !== "not_applicable")
      ) {
        reject(loaded, "Run coverage cannot be not_applicable when an applicable result exists");
      }
      const state = { ...loaded.state, coverage_outcome: coverageOutcome };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state });
    },

    finalize(
      runId: string,
      input: { readonly residual_count: number }
    ): AtomicRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["cleaning"]);
      const plan = requirePlan(loaded);
      if (loaded.state.coverage_outcome === "pending") {
        reject(loaded, "Coverage must be scored before finalize");
      }
      const requiredCleanup = plan.tests.filter((test) => {
        if (!test.cleanup_expected) return false;
        return loaded.executions.some(
          (record) =>
            record.test_guid === test.test_guid &&
            (record.stage === "execute" || record.stage === "manual") &&
            record.status !== "skipped" &&
            record.status !== "blocked"
        );
      });
      const cleanedGuids = new Set(
        loaded.executions
          .filter((record) => record.stage === "cleanup")
          .map((record) => record.test_guid)
      );
      const missingCleanup = requiredCleanup.filter(
        (test) => !cleanedGuids.has(test.test_guid)
      );
      if (missingCleanup.length) {
        reject(
          loaded,
          `Cleanup is not accounted for: ${missingCleanup.map((test) => test.test_guid).join(", ")}`
        );
      }
      const unclean = loaded.resources.filter((resource) => !resource.cleaned);
      if (input.residual_count === 0 && unclean.length) {
        reject(
          loaded,
          `residual_count is 0 but ${unclean.length} ledger entries are not cleaned`
        );
      }
      const executionFindings = loaded.executions.some(
        (record) => record.status !== "passed"
      );
      const coverageFindings = ["gaps", "no_telem", "mixed", "not_applicable"].includes(
        loaded.state.coverage_outcome
      );
      const phase: AtomicPhase =
        input.residual_count > 0
          ? "cleanup_failed"
          : executionFindings || coverageFindings
            ? "completed_with_findings"
            : "completed";
      const state: AtomicRunState = {
        ...loaded.state,
        phase,
        residual_count: input.residual_count,
        terminal_at: new Date().toISOString(),
      };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state });
    },

    block(runId: string, reason: string): AtomicRunSnapshot {
      const loaded = load(runId);
      if (TERMINAL_PHASES.has(loaded.state.phase)) {
        reject(loaded, `Run already terminal (${loaded.state.phase})`);
      }
      const state: AtomicRunState = {
        ...loaded.state,
        phase: "blocked",
        blocked_reason: reason,
        terminal_at: new Date().toISOString(),
      };
      saveState(loaded.dir, state);
      return snapshot(
        { ...loaded, state },
        { stop: true, stop_reason: reason }
      );
    },
  };
}

export type AtomicRunStore = ReturnType<typeof createAtomicRunStore>;

function allowedActions(phase: AtomicPhase): string[] {
  if (TERMINAL_PHASES.has(phase)) return ["status"];
  const actions = ["status"];
  if (phase === "planning" || phase === "awaiting_approval") actions.push("set_plan");
  if (phase === "awaiting_approval") actions.push("approve");
  if (ADVANCE[phase]) actions.push("advance");
  if (["provisioning", "executing", "cleaning"].includes(phase)) {
    actions.push("record_resource");
  }
  if (["provisioning", "executing", "cleaning"].includes(phase)) {
    actions.push("record_execution");
  }
  if (phase === "covering" || phase === "reporting") {
    actions.push("record_coverage", "set_coverage_outcome");
  }
  if (phase === "cleaning") actions.push("finalize");
  actions.push("block");
  return actions;
}
