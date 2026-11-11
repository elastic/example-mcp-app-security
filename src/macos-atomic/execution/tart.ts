/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { spawn } from "node:child_process";
import { assertSafeTargetId } from "../shared/validation.js";
import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { runProcess, type ProcessResult } from "./process.js";
import { runOnTarget } from "./target.js";

export async function cloneAndStartTartTarget(
  scope: AtomicPlan["scope"]
): Promise<{ readonly clone: ProcessResult; readonly transport: "tart-exec" }> {
  if (scope.target_kind !== "tart" || scope.lifecycle !== "ephemeral") {
    throw new Error("Tart provisioning requires an ephemeral tart target");
  }
  if (!scope.target_image) throw new Error("Tart target_image is required");
  assertSafeTargetId(scope.target_id);
  if (await tartTargetExists(scope.target_id)) {
    throw new Error(`Refusing to overwrite existing Tart VM ${scope.target_id}`);
  }
  const clone = await runProcess(
    "tart",
    ["clone", scope.target_image, scope.target_id],
    { timeoutMs: 30 * 60_000 }
  );
  if (clone.exitCode !== 0 || clone.timedOut) return { clone, transport: "tart-exec" };

  const child = spawn("tart", tartRunArgs(scope), {
    detached: true,
    stdio: "ignore",
    shell: false,
  });
  child.unref();
  const deadline = Date.now() + 5 * 60_000;
  let lastError = "Tart guest agent is not ready";
  while (Date.now() < deadline) {
    try {
      const probe = await runOnTarget(scope, ["true"], 20_000);
      if (probe.exitCode === 0 && !probe.timedOut) {
        return { clone, transport: "tart-exec" };
      }
      lastError = probe.stderr || `tart exec exit ${probe.exitCode}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  throw new Error(`Timed out waiting for Tart VM ${scope.target_id}: ${lastError}`);
}

export function tartRunArgs(scope: AtomicPlan["scope"]): string[] {
  return scope.target_profile === "desktop"
    ? ["run", scope.target_id]
    : ["run", "--no-graphics", scope.target_id];
}

export async function stopAndDeleteTartTarget(
  targetId: string
): Promise<{ readonly stopped: ProcessResult; readonly deleted: ProcessResult }> {
  assertSafeTargetId(targetId);
  const stopped = await runProcess("tart", ["stop", targetId], { timeoutMs: 60_000 });
  const deleted = await runProcess("tart", ["delete", targetId], { timeoutMs: 60_000 });
  return { stopped, deleted };
}

export async function tartTargetExists(targetId: string): Promise<boolean> {
  assertSafeTargetId(targetId);
  const result = await runProcess("tart", ["list", "--format", "json"], {
    timeoutMs: 15_000,
  });
  if (result.exitCode !== 0 || result.timedOut) {
    throw new Error(`Could not inspect Tart VMs: ${result.stderr}`);
  }
  return tartListContains(result.stdout, targetId);
}

export function tartListContains(output: string, targetId: string): boolean {
  try {
    const parsed: unknown = JSON.parse(output);
    const rows = Array.isArray(parsed)
      ? parsed
      : parsed && typeof parsed === "object"
        ? Object.values(parsed as Record<string, unknown>).flat()
        : [];
    return rows.some(
      (row) =>
        row !== null &&
        typeof row === "object" &&
        String((row as Record<string, unknown>).Name ?? (row as Record<string, unknown>).name) ===
          targetId
    );
  } catch {
    return false;
  }
}
