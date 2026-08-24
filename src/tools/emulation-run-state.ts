/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const EMULATION_PHASES = [
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

export type EmulationPhase = (typeof EMULATION_PHASES)[number];

export const EMULATION_MODES = [
  "intelligence",
  "rule",
  "coverage",
  "conceptual",
  "tool",
] as const;

export const EMULATION_TYPES = ["atomic", "micro", "full"] as const;

const TERMINAL_PHASES = new Set<EmulationPhase>([
  "completed",
  "completed_with_findings",
  "cleanup_failed",
  "blocked",
]);

const ADVANCE: Record<string, EmulationPhase> = {
  approved: "provisioning",
  provisioning: "executing",
  executing: "verifying",
  verifying: "covering",
  covering: "reporting",
  reporting: "cleaning",
};

const PHASE_READ: Partial<Record<EmulationPhase, string>> = {
  planning: "skills/cloud-threat-emulation/references/engagement-planning.md",
  awaiting_approval: "skills/cloud-threat-emulation/references/engagement-planning.md",
  approved: "skills/cloud-threat-emulation/references/cloud-emulation-guide.md",
  provisioning: "skills/cloud-threat-emulation/references/cloud-emulation-guide.md",
  executing: "skills/cloud-threat-emulation/references/cloud-emulation-guide.md",
  verifying: "skills/cloud-threat-emulation/SKILL.md",
  covering: "skills/cloud-threat-emulation/references/cloud-emulation-guide.md",
  reporting: "skills/cloud-threat-emulation/references/engagement-planning.md",
  cleaning: "skills/cloud-threat-emulation/references/cloud-emulation-guide.md",
};

export type EmulationBehavior = {
  readonly id: string;
  readonly api: string;
  readonly actor: string;
  readonly target: string;
  readonly expected_outcome: string;
  readonly mitre?: string;
  readonly result?: string;
};

export type EmulationResource = {
  readonly id: string;
  readonly kind: string;
  readonly origin: "provisioned" | "orphaned";
  readonly cleaned: boolean;
};

export type EmulationPlan = {
  readonly schema_version: 1;
  readonly run_id: string;
  readonly mode: (typeof EMULATION_MODES)[number];
  readonly type: (typeof EMULATION_TYPES)[number];
  readonly source: {
    readonly reference: string;
    readonly kind: "published-url" | "rule" | "gap" | "conceptual" | "tool";
  };
  readonly objective: string;
  readonly scope: {
    readonly provider: "aws" | "azure" | "gcp";
    readonly scope_id: string;
    readonly region: string;
  };
  readonly behaviors: readonly EmulationBehavior[];
};

export type EmulationRunState = {
  readonly schema_version: 1;
  readonly run_id: string;
  readonly name: string;
  readonly phase: EmulationPhase;
  readonly created_at: string;
  readonly plan_digest?: string;
  readonly approved_at?: string;
  readonly detection_outcome?: "pending" | "verified" | "gaps" | "no_telem";
  readonly residual_count?: number;
};

export type EmulationRunSnapshot = {
  readonly ok: boolean;
  readonly error?: string;
  readonly phase: EmulationPhase;
  readonly run_id: string;
  readonly run_dir: string;
  readonly plan_digest?: string;
  readonly allowed_actions: readonly string[];
  readonly read?: string;
  readonly stop?: boolean;
  readonly stop_reason?: string;
  readonly detection_outcome?: EmulationRunState["detection_outcome"];
  readonly residual_count?: number;
  readonly behavior_count?: number;
  readonly resource_count?: number;
};

export class EmulationRunError extends Error {
  constructor(
    message: string,
    readonly snapshot: EmulationRunSnapshot
  ) {
    super(message);
    this.name = "EmulationRunError";
  }
}

export function planDigest(plan: EmulationPlan): string {
  return createHash("sha256").update(stableStringify(plan)).digest("hex");
}

export function createEmulationRunStore(options: {
  readonly baseDir?: string;
} = {}) {
  const baseDir = path.resolve(options.baseDir ?? path.join(process.cwd(), "emulation-runs"));

  function runDirFor(runId: string): string {
    if (!/^[a-z0-9][a-z0-9-]{2,80}$/.test(runId)) {
      throw new Error(`Invalid run_id "${runId}"`);
    }
    const dir = path.resolve(baseDir, runId);
    const relative = path.relative(baseDir, dir);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      throw new Error("run_id resolves outside the emulation-runs directory");
    }
    return dir;
  }

  function readJson<T>(file: string): T | undefined {
    if (!fs.existsSync(file)) {
      return undefined;
    }
    return JSON.parse(fs.readFileSync(file, "utf8")) as T;
  }

  function writeJson(file: string, value: unknown): void {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  }

  function load(runId: string): {
    dir: string;
    state: EmulationRunState;
    plan?: EmulationPlan;
    resources: EmulationResource[];
    recordedBehaviors: EmulationBehavior[];
  } {
    const dir = runDirFor(runId);
    const state = readJson<EmulationRunState>(path.join(dir, "run.json"));
    if (!state) {
      throw new Error(`No emulation run at ${dir}`);
    }
    return {
      dir,
      state,
      plan: readJson<EmulationPlan>(path.join(dir, "plan.json")),
      resources: readJson<EmulationResource[]>(path.join(dir, "resources.json")) ?? [],
      recordedBehaviors:
        readJson<EmulationBehavior[]>(path.join(dir, "behaviors.json")) ?? [],
    };
  }

  function snapshot(
    loaded: ReturnType<typeof load>,
    extras: Partial<EmulationRunSnapshot> = {}
  ): EmulationRunSnapshot {
    const { state, dir, plan } = loaded;
    const allowed = allowedActions(state.phase);
    const awaiting = state.phase === "awaiting_approval";
    const awaitingReason =
      "Present the plan to the engineer. Call action=approve only after they explicitly approve.";
    return {
      ok: extras.ok ?? true,
      phase: state.phase,
      run_id: state.run_id,
      run_dir: dir,
      plan_digest: state.plan_digest ?? (plan ? planDigest(plan) : undefined),
      allowed_actions: allowed,
      read: PHASE_READ[state.phase],
      stop: extras.stop ?? awaiting,
      stop_reason: extras.stop_reason ?? (awaiting ? awaitingReason : undefined),
      detection_outcome: state.detection_outcome,
      residual_count: state.residual_count,
      behavior_count: loaded.recordedBehaviors.length,
      resource_count: loaded.resources.length,
      ...extras,
    };
  }

  function saveState(dir: string, state: EmulationRunState): void {
    writeJson(path.join(dir, "run.json"), state);
  }

  function reject(loaded: ReturnType<typeof load>, error: string): never {
    throw new EmulationRunError(error, snapshot(loaded, { ok: false, error }));
  }

  function requirePhase(
    loaded: ReturnType<typeof load>,
    allowed: EmulationPhase[]
  ): void {
    if (!allowed.includes(loaded.state.phase)) {
      reject(
        loaded,
        `Phase is ${loaded.state.phase}; allowed: ${allowed.join(", ")}`
      );
    }
  }

  return {
    init(input: {
      readonly name: string;
      readonly run_id?: string;
    }): EmulationRunSnapshot {
      fs.mkdirSync(baseDir, { recursive: true });
      const suffix = randomBytes(3).toString("hex");
      const slug = input.name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 40) || "emul";
      const runId = input.run_id ?? `${slug}-${suffix}`;
      const dir = runDirFor(runId);
      if (fs.existsSync(path.join(dir, "run.json"))) {
        throw new Error(`Run ${runId} already exists`);
      }
      const state: EmulationRunState = {
        schema_version: 1,
        run_id: runId,
        name: input.name,
        phase: "planning",
        created_at: new Date().toISOString(),
        detection_outcome: "pending",
      };
      saveState(dir, state);
      writeJson(path.join(dir, "resources.json"), []);
      writeJson(path.join(dir, "behaviors.json"), []);
      return snapshot({ dir, state, resources: [], recordedBehaviors: [] });
    },

    status(runId: string): EmulationRunSnapshot {
      return snapshot(load(runId));
    },

    setPlan(runId: string, plan: EmulationPlan): EmulationRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["planning", "awaiting_approval"]);
      if (plan.run_id !== runId) {
        reject(loaded, `plan.run_id ${plan.run_id} does not match run ${runId}`);
      }
      if (plan.behaviors.length < 1) {
        reject(loaded, "plan.behaviors must contain at least one concrete behavior");
      }
      for (const behavior of plan.behaviors) {
        if (!behavior.api || !behavior.actor || !behavior.target || !behavior.expected_outcome) {
          reject(
            loaded,
            "Each behavior needs api, actor, target, and expected_outcome (not an ATT&CK id alone)"
          );
        }
      }
      const expectedKind: Record<EmulationPlan["mode"], EmulationPlan["source"]["kind"]> = {
        intelligence: "published-url",
        rule: "rule",
        coverage: "gap",
        conceptual: "conceptual",
        tool: "tool",
      };
      if (plan.source.kind !== expectedKind[plan.mode]) {
        reject(
          loaded,
          `${plan.mode} runs require source.kind=${expectedKind[plan.mode]}`
        );
      }
      if (
        plan.source.kind === "published-url" &&
        !/^https?:\/\//i.test(plan.source.reference)
      ) {
        reject(loaded, "intelligence-driven runs require source.reference to be an http(s) URL");
      }
      const digest = planDigest(plan);
      writeJson(path.join(loaded.dir, "plan.json"), plan);
      const state: EmulationRunState = {
        ...loaded.state,
        phase: "awaiting_approval",
        plan_digest: digest,
        approved_at: undefined,
      };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state, plan });
    },

    approve(runId: string, digest: string): EmulationRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["awaiting_approval"]);
      if (!loaded.state.plan_digest || digest !== loaded.state.plan_digest) {
        reject(
          loaded,
          "plan_digest does not match the stored plan. Call set_plan again if the plan changed."
        );
      }
      const state: EmulationRunState = {
        ...loaded.state,
        phase: "approved",
        approved_at: new Date().toISOString(),
      };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state });
    },

    advance(runId: string): EmulationRunSnapshot {
      const loaded = load(runId);
      const next = ADVANCE[loaded.state.phase];
      if (!next) {
        reject(loaded, `Cannot advance from ${loaded.state.phase}`);
      }
      const state: EmulationRunState = { ...loaded.state, phase: next };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state });
    },

    recordBehavior(runId: string, behavior: EmulationBehavior): EmulationRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["executing"]);
      const recordedBehaviors = [...loaded.recordedBehaviors, behavior];
      writeJson(path.join(loaded.dir, "behaviors.json"), recordedBehaviors);
      return snapshot({ ...loaded, recordedBehaviors });
    },

    recordResource(runId: string, resource: EmulationResource): EmulationRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["provisioning", "executing", "cleaning"]);
      const resources = [
        ...loaded.resources.filter((existing) => existing.id !== resource.id),
        resource,
      ];
      writeJson(path.join(loaded.dir, "resources.json"), resources);
      return snapshot({ ...loaded, resources });
    },

    setDetectionOutcome(
      runId: string,
      detection_outcome: NonNullable<EmulationRunState["detection_outcome"]>
    ): EmulationRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["covering", "reporting"]);
      const state: EmulationRunState = { ...loaded.state, detection_outcome };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state });
    },

    finalize(
      runId: string,
      input: { readonly residual_count: number }
    ): EmulationRunSnapshot {
      const loaded = load(runId);
      requirePhase(loaded, ["cleaning"]);
      if (
        loaded.state.detection_outcome === undefined ||
        loaded.state.detection_outcome === "pending"
      ) {
        reject(
          loaded,
          "Call set_detection_outcome before finalize (cleanup success is independent of detection gaps)"
        );
      }
      const unclean = loaded.resources.filter((resource) => !resource.cleaned);
      if (input.residual_count === 0 && unclean.length > 0) {
        reject(
          loaded,
          `residual_count is 0 but ${unclean.length} ledger entries are not cleaned`
        );
      }
      const failed = input.residual_count > 0;
      const gaps =
        loaded.state.detection_outcome === "gaps" ||
        loaded.state.detection_outcome === "no_telem";
      const phase: EmulationPhase = failed
        ? "cleanup_failed"
        : gaps
          ? "completed_with_findings"
          : "completed";
      const state: EmulationRunState = {
        ...loaded.state,
        phase,
        residual_count: input.residual_count,
      };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state });
    },

    block(runId: string, reason: string): EmulationRunSnapshot {
      const loaded = load(runId);
      if (TERMINAL_PHASES.has(loaded.state.phase)) {
        reject(loaded, `Run already terminal (${loaded.state.phase})`);
      }
      const state: EmulationRunState = { ...loaded.state, phase: "blocked" };
      saveState(loaded.dir, state);
      return snapshot({ ...loaded, state }, { stop: true, stop_reason: reason });
    },
  };
}

export type EmulationRunStore = ReturnType<typeof createEmulationRunStore>;

function allowedActions(phase: EmulationPhase): string[] {
  if (TERMINAL_PHASES.has(phase)) {
    return ["status"];
  }
  const actions = ["status"];
  if (phase === "planning" || phase === "awaiting_approval") {
    actions.push("set_plan");
  }
  if (phase === "awaiting_approval") {
    actions.push("approve");
  }
  if (ADVANCE[phase]) {
    actions.push("advance");
  }
  if (phase === "executing") {
    actions.push("record_behavior");
  }
  if (phase === "provisioning" || phase === "executing" || phase === "cleaning") {
    actions.push("record_resource");
  }
  if (phase === "covering" || phase === "reporting") {
    actions.push("set_detection_outcome");
  }
  if (phase === "cleaning") {
    actions.push("finalize");
  }
  actions.push("block");
  return actions;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",")}}`;
}
