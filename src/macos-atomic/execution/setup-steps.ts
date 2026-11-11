/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { runOnTarget } from "./target.js";

export type SetupStep = NonNullable<AtomicPlan["setup_steps"]>[number];

export type SetupStepResult = {
  readonly description: string;
  readonly command: readonly string[];
  readonly elevated: boolean;
  readonly exit_code: number | null;
  readonly timed_out: boolean;
  readonly ok: boolean;
  readonly stderr: string;
};

/**
 * Runs the digest-approved setup_steps on a freshly provisioned target, in order, after
 * approved packages. Each step is an exact argv array (no shell), so approval of the plan
 * digest is approval of the exact commands. Elevated steps run via sudo; others run as the
 * approved execution user. The first failure stops the sequence and fails provisioning.
 */
export async function runSetupSteps(
  scope: AtomicPlan["scope"],
  steps: readonly SetupStep[],
  timeoutMs = 10 * 60_000,
  runner: typeof runOnTarget = runOnTarget
): Promise<{ readonly ok: boolean; readonly steps: readonly SetupStepResult[] }> {
  const results: SetupStepResult[] = [];
  for (const step of steps) {
    const elevated = step.elevated === true;
    const prefix = elevated
      ? ["sudo"]
      : ["sudo", "-H", "-u", scope.execution_user, "--"];
    const result = await runner(scope, [...prefix, ...step.command], timeoutMs);
    const ok = result.exitCode === 0 && !result.timedOut;
    results.push({
      description: step.description,
      command: step.command,
      elevated,
      exit_code: result.exitCode,
      timed_out: result.timedOut,
      ok,
      stderr: result.stderr.slice(0, 4_096),
    });
    if (!ok) return { ok: false, steps: results };
  }
  return { ok: true, steps: results };
}
