/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { verifyStagedOperatorSourceAssets } from "../execution/source-assets.js";
import { runProcess } from "../execution/process.js";
import { runOnTarget } from "../execution/target.js";
import {
  createAtomicRunStore,
  type AtomicPhase,
  type AtomicPlan,
} from "./atomic-run-state.js";
import { textResult } from "./atomic-run.js";

const execSchema = z.object({
  action: z.enum([
    "show_details",
    "stage_fixtures",
    "check_prereqs",
    "get_prereqs",
    "execute",
    "manual_instructions",
    "record_manual",
    "cleanup",
    "manual_cleanup_instructions",
    "record_manual_cleanup",
  ]),
  run_id: z.string().min(1),
  test_guid: z.string().uuid(),
  timeout_seconds: z.number().int().min(1).max(3_600).optional(),
  operator_outcome: z.enum(["completed", "failed", "blocked"]).optional(),
  operator_attestation: z.string().min(8).max(4_000).optional(),
  operator_started_at: z.string().datetime().optional(),
  operator_ended_at: z.string().datetime().optional(),
  observations: z.string().max(8_000).optional(),
});

const POWERSHELL_RUNNER = String.raw`$ErrorActionPreference = 'Stop'
Import-Module /opt/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 -Force
$decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:ATOMIC_INPUTS_B64))
$inputArgs = @{}
if ($decoded -and $decoded -ne '{}') {
  $parsed = ConvertFrom-Json $decoded
  foreach ($property in $parsed.PSObject.Properties) { $inputArgs[$property.Name] = $property.Value }
}
$logDir = "/var/tmp/macos-atomic-runs/$($env:ATOMIC_RUN_ID)"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logPath = "$logDir/$($env:ATOMIC_TEST_GUID)-$($env:ATOMIC_ACTION).csv"
$params = @{
  AtomicTechnique = $env:ATOMIC_TECHNIQUE
  TestGuids = @($env:ATOMIC_TEST_GUID)
  PathToAtomicsFolder = '/opt/atomic-red-team/atomics'
  InputArgs = $inputArgs
  TimeoutSeconds = [int]$env:ATOMIC_TIMEOUT_SECONDS
  ExecutionLogPath = $logPath
  Force = $true
}
switch ($env:ATOMIC_ACTION) {
  'show_details' { $params.ShowDetails = $true }
  'check_prereqs' { $params.CheckPrereqs = $true }
  'get_prereqs' { $params.GetPrereqs = $true }
  'cleanup' { $params.Cleanup = $true }
  'execute' { }
  default { throw "Unsupported action $($env:ATOMIC_ACTION)" }
}
$captured = @(& { Invoke-AtomicTest @params } 6>&1)
$captured | ForEach-Object { Write-Output $_ }
$capturedText = ($captured | Out-String)
if ($env:ATOMIC_ACTION -eq 'check_prereqs' -and $capturedText -match 'Prerequisites not met:') {
  throw 'One or more Atomic prerequisites are not satisfied'
}
if ($env:ATOMIC_ACTION -eq 'get_prereqs' -and $capturedText -match 'Failed to meet prereq:') {
  throw 'One or more Atomic prerequisites remain unsatisfied after acquisition'
}
if (Test-Path $logPath) {
  Write-Output '---ATOMIC-EXECUTION-LOG---'
  Get-Content -Raw $logPath
}
`;

// Some macOS Atomics model prompt hooks or other behavior that exists only in
// an interactive Bash read/evaluate/prompt loop. Invoke-AtomicRedTeam executes
// sh/bash commands non-interactively, so a digest-approved test may opt into
// this exact-GUID adapter. It resolves the immutable Atomic YAML and approved
// inputs, then feeds the unmodified command (or cleanup command) to `bash -i`.
export const BASH_INTERACTIVE_RUNNER = String.raw`$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Import-Module powershell-yaml -RequiredVersion 0.4.12 -Force
$root = '/opt/atomic-red-team/atomics'
$definition = Join-Path (Join-Path $root $env:ATOMIC_TECHNIQUE) "$($env:ATOMIC_TECHNIQUE).yaml"
$yamlObject = ConvertFrom-Yaml -Yaml (Get-Content -Raw $definition)
$document = $yamlObject | ConvertTo-Json -Depth 100 | ConvertFrom-Json
if ($document.attack_technique -ne $env:ATOMIC_TECHNIQUE) {
  throw 'technique identifier does not match the pinned definition'
}
$matches = @($document.atomic_tests | Where-Object { $_.auto_generated_guid -eq $env:ATOMIC_TEST_GUID })
if ($matches.Count -ne 1) {
  throw 'the pinned definition must contain exactly one requested GUID'
}
$test = $matches[0]
$executor = $test.executor
$executorName = ([string]$executor.name).ToLowerInvariant()
if ($executorName -notin @('sh', 'bash')) {
  throw "bash_interactive does not support executor $executorName"
}
$decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:ATOMIC_INPUTS_B64))
$approvedInputs = @{}
if ($decoded -and $decoded -ne '{}') {
  $parsed = ConvertFrom-Json $decoded
  foreach ($property in $parsed.PSObject.Properties) {
    $approvedInputs[$property.Name] = $property.Value
  }
}
$values = @{}
if ($test.input_arguments) {
  foreach ($property in $test.input_arguments.PSObject.Properties) {
    $values[$property.Name] = $property.Value.default
  }
}
foreach ($name in $approvedInputs.Keys) {
  if (-not $values.ContainsKey($name)) {
    throw "approved input is not declared by the Atomic: $name"
  }
  $values[$name] = $approvedInputs[$name]
}
function Expand-AtomicCommand([string]$text) {
  $expanded = ([string]$text).Replace('PathToAtomicsFolder', $root)
  foreach ($name in $values.Keys) {
    $expanded = $expanded.Replace("#{$name}", [string]$values[$name])
  }
  if ($expanded.Contains('#{')) {
    throw 'an unresolved Atomic input remains in the command'
  }
  return $expanded
}
switch ($env:ATOMIC_ACTION) {
  'execute' { $command = Expand-AtomicCommand ([string]$executor.command) }
  'cleanup' { $command = Expand-AtomicCommand ([string]$executor.cleanup_command) }
  default { throw "bash_interactive does not support action $($env:ATOMIC_ACTION)" }
}
if (-not $command.Trim()) { exit 0 }
$env:SHELL = '/bin/bash'
if (-not $env:HISTFILE) { $env:HISTFILE = "$($env:HOME)/.bash_history" }
$historyEvidence = if ($env:ATOMIC_ACTION -eq 'execute') {
  "history > '/var/tmp/atomic-bash-history-$($env:ATOMIC_TEST_GUID).txt'" + [Environment]::NewLine +
  "set -o | grep '^history' > '/var/tmp/atomic-bash-history-option-$($env:ATOMIC_TEST_GUID).txt'"
} else {
  ''
}
$payload = $command + [Environment]::NewLine + $historyEvidence + [Environment]::NewLine + 'exit' + [Environment]::NewLine
$captured = @($payload | & /bin/bash --noprofile --norc -i 2>&1)
$status = $LASTEXITCODE
$captured | ForEach-Object { Write-Output $_ }
exit $status
`;

const FIXTURE_WRITER = String.raw`import base64, hashlib, os
p = os.environ["ATOMIC_FIXTURE_PATH"]
data = base64.b64decode(os.environ["ATOMIC_FIXTURE_B64"], validate=True)
expected = os.environ["ATOMIC_FIXTURE_SHA256"]
if hashlib.sha256(data).hexdigest() != expected:
    raise RuntimeError("fixture digest mismatch")
flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(p, flags, int(os.environ["ATOMIC_FIXTURE_MODE"], 8))
try:
    os.write(fd, data)
    os.fchmod(fd, int(os.environ["ATOMIC_FIXTURE_MODE"], 8))
finally:
    os.close(fd)
print(hashlib.sha256(data).hexdigest())
`;

const BEHAVIOR_PATH_CHECKER = String.raw`import os, sys
expected = sys.argv[1]
exists = os.path.exists(sys.argv[2])
sys.exit(0 if (expected == "exists") == exists else 1)
`;

const BEHAVIOR_PATH_CONTENT_CHECKER = String.raw`import os, sys
expected = sys.argv[1]
path = sys.argv[2]
needle = sys.argv[3].encode("utf-8")
matches = os.path.isfile(path) and needle in open(path, "rb").read()
sys.exit(0 if os.path.isfile(path) and ((expected == "contains") == matches) else 1)
`;

type BehaviorValidation = {
  readonly ok: boolean;
  readonly checks: readonly Record<string, unknown>[];
};

export function hasBehaviorExecution(
  executions: readonly { readonly stage: string }[]
): boolean {
  return executions.some(
    (execution) => execution.stage === "execute" || execution.stage === "manual"
  );
}

export function registerAtomicExecTool(
  server: McpServer,
  store = createAtomicRunStore()
): void {
  server.registerTool(
    "macos-atomic-exec",
    {
      title: "Execute Approved macOS Atomic",
      description:
        "Stages optional digest-approved benign fixtures, runs approved macOS atomics through pinned Invoke-AtomicRedTeam, and coordinates approved manual procedures. Inputs, elevation, cleanup, capabilities, and behavior-success criteria come only from the approved plan.",
      inputSchema: execSchema,
      annotations: { destructiveHint: true },
    },
    async (input) => {
      try {
        const loaded = store.getLoaded(input.run_id);
        if (!loaded.plan) return textResult({ error: "No approved plan is stored" }, true);
        const plan = loaded.plan;
        const test = store.getApprovedTest(input.run_id, input.test_guid);
        const allowedPhase: Record<typeof input.action, readonly AtomicPhase[]> = {
          show_details: ["approved", "provisioning", "executing"],
          stage_fixtures: ["provisioning", "executing"],
          check_prereqs: ["provisioning", "executing"],
          get_prereqs: ["provisioning", "executing"],
          execute: ["executing"],
          manual_instructions: ["executing"],
          record_manual: ["executing"],
          cleanup: ["cleaning"],
          manual_cleanup_instructions: ["cleaning"],
          record_manual_cleanup: ["cleaning"],
        };
        store.assertPhase(input.run_id, allowedPhase[input.action]);
        if (
          loaded.state.phase === "executing" &&
          ["stage_fixtures", "check_prereqs", "get_prereqs"].includes(input.action) &&
          hasBehaviorExecution(loaded.executions)
        ) {
          return textResult(
            {
              error:
                "Prerequisite actions are allowed in executing only before the behavior has run",
              test_guid: test.test_guid,
            },
            true
          );
        }
        const operatorMode = test.execution_mode === "operator";
        if (operatorMode && input.action === "manual_instructions") {
          const stagedSourceAssets = await verifyStagedOperatorSourceAssets(
            plan.scope,
            input.run_id,
            [test]
          );
          if (!stagedSourceAssets.ok) {
            return textResult(
              {
                error:
                  "Digest-approved operator assets are missing or changed in the execution user's home",
                test_guid: test.test_guid,
                staged_source_assets: stagedSourceAssets,
              },
              true
            );
          }
          const operatorWindowStartedAt = new Date().toISOString();
          return textResult({
            ok: true,
            stop: true,
            stop_reason: "The approved manual procedure requires operator action on the target",
            test_guid: test.test_guid,
            target_id: plan.scope.target_id,
            target_profile: plan.scope.target_profile,
            execution_user: plan.scope.execution_user,
            elevation_required: test.elevation_required,
            required_capabilities: test.required_capabilities,
            reviewed_steps: test.manual?.reviewed_steps,
            staged_source_assets: stagedSourceAssets,
            evidence_requirements: test.manual?.evidence_requirements,
            operator_window_started_at: operatorWindowStartedAt,
          });
        }
        if (operatorMode && input.action === "manual_cleanup_instructions") {
          const operatorWindowStartedAt = new Date().toISOString();
          return textResult({
            ok: true,
            stop: true,
            stop_reason: "The approved manual cleanup requires operator action on the target",
            test_guid: test.test_guid,
            target_id: plan.scope.target_id,
            cleanup_steps: test.manual?.cleanup_steps ?? [],
            operator_window_started_at: operatorWindowStartedAt,
          });
        }
        if (
          operatorMode &&
          (input.action === "record_manual" || input.action === "record_manual_cleanup")
        ) {
          if (
            !input.operator_outcome ||
            !input.operator_attestation ||
            !input.operator_started_at
          ) {
            return textResult(
              {
                error:
                  "operator_outcome, operator_attestation, and the operator_started_at returned by the instruction action are required",
              },
              true
            );
          }
          const operatorEndedAt = input.operator_ended_at ?? new Date().toISOString();
          if (Date.parse(operatorEndedAt) < Date.parse(input.operator_started_at)) {
            return textResult({ error: "operator_ended_at precedes operator_started_at" }, true);
          }
          const manualStage = input.action === "record_manual" ? "manual" : "cleanup";
          if (
            manualStage === "cleanup" &&
            test.cleanup_expected &&
            !(test.manual?.cleanup_steps?.length)
          ) {
            return textResult(
              { error: "Approved manual cleanup steps are missing; replan before cleanup" },
              true
            );
          }
          const status =
            input.operator_outcome === "completed"
              ? "passed"
              : input.operator_outcome === "failed"
                ? "failed"
                : "blocked";
          const evidencePath = writeManualEvidence(loaded.dir, test, {
            stage: manualStage,
            outcome: input.operator_outcome,
            operator_attestation: input.operator_attestation,
            started_at: input.operator_started_at,
            ended_at: operatorEndedAt,
            observations: input.observations,
          });
          const snapshot = store.recordExecution(input.run_id, {
            test_guid: test.test_guid,
            stage: manualStage,
            status,
            behavior_success: manualStage === "manual" ? status === "passed" : undefined,
            started_at: input.operator_started_at,
            ended_at: operatorEndedAt,
            evidence_path: evidencePath,
            notes: input.observations,
          });
          return textResult({
            ok: status === "passed",
            test_guid: test.test_guid,
            action: input.action,
            status,
            behavior_success: manualStage === "manual" ? status === "passed" : undefined,
            evidence_path: evidencePath,
            run: snapshot,
          }, status !== "passed");
        }
        if (operatorMode && input.action !== "stage_fixtures") {
          return textResult(
            {
              error:
                "Manual atomics use manual_instructions/record_manual and their cleanup counterparts; the runner path is disabled.",
              test_guid: test.test_guid,
            },
            true
          );
        }
        if (
          !operatorMode &&
          [
            "manual_instructions",
            "record_manual",
            "manual_cleanup_instructions",
            "record_manual_cleanup",
          ].includes(input.action)
        ) {
          return textResult({ error: "This approved test uses the automated runner" }, true);
        }
        if (input.action === "stage_fixtures") {
          const result = await stageFixtures(loaded.dir, plan.scope, input.run_id, test);
          const snapshot = store.recordExecution(input.run_id, {
            test_guid: test.test_guid,
            stage: "prereq",
            status: result.ok ? "passed" : "failed",
            started_at: result.startedAt,
            ended_at: result.endedAt,
            exit_code: result.ok ? 0 : 1,
            evidence_path: result.evidencePath,
            notes: result.ok
              ? `Staged ${result.fixtureCount} digest-approved fixtures`
              : result.error,
          });
          return textResult(
            {
              ok: result.ok,
              test_guid: test.test_guid,
              action: input.action,
              fixture_count: result.fixtureCount,
              evidence_path: result.evidencePath,
              error: result.error,
              run: snapshot,
            },
            !result.ok
          );
        }
        const timeoutSeconds =
          input.timeout_seconds ??
          Number(process.env.MACOS_ATOMIC_DEFAULT_TIMEOUT_SECONDS ?? 180);
        const inputsB64 = Buffer.from(JSON.stringify(test.inputs), "utf8").toString("base64");
        const privilegePrefix = approvedPrivilegePrefix(
          plan.scope,
          test.elevation_required
        );
        const useInteractiveBash =
          plan.scope.platform === "macos" &&
          test.execution_adapter === "bash_interactive" &&
          (input.action === "execute" || input.action === "cleanup");
        const runner = [
          "pwsh",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          useInteractiveBash ? BASH_INTERACTIVE_RUNNER : POWERSHELL_RUNNER,
        ];
        const logDirectory = await runOnTarget(
          plan.scope,
          runnerLogDirectoryCommand(plan.scope, input.run_id),
          30_000
        );
        if (logDirectory.exitCode !== 0 || logDirectory.timedOut) {
          throw new Error(
            `Could not prepare the runner evidence directory for ${plan.scope.execution_user}: ${
              logDirectory.stderr.trim() || logDirectory.stdout.trim() || "unknown error"
            }`
          );
        }
        const result = await runOnTarget(
          plan.scope,
          [
            ...privilegePrefix,
            "env",
            `ATOMIC_ACTION=${input.action}`,
            `ATOMIC_RUN_ID=${input.run_id}`,
            `ATOMIC_TECHNIQUE=${test.technique_id}`,
            `ATOMIC_TEST_GUID=${test.test_guid}`,
            `ATOMIC_TIMEOUT_SECONDS=${timeoutSeconds}`,
            `ATOMIC_INPUTS_B64=${inputsB64}`,
            ...runner,
          ],
          (timeoutSeconds + 30) * 1_000
        );
        const behaviorValidation =
          input.action === "execute"
            ? await validateBehaviorSuccess(
                plan.scope,
                test,
                result.stdout,
                result.stderr,
                result.startedAt
              )
            : undefined;
        const evidencePath = writeEvidence(
          loaded.dir,
          test.test_guid,
          input.action,
          result,
          behaviorValidation
        );
        if (input.action === "show_details") {
          return textResult({
            ok: result.exitCode === 0 && !result.timedOut,
            test_guid: test.test_guid,
            exit_code: result.exitCode,
            timed_out: result.timedOut,
            truncated: result.truncated,
            evidence_path: evidencePath,
            stdout: result.stdout,
            stderr: result.stderr,
          }, result.exitCode !== 0 || result.timedOut);
        }
        const stage =
          input.action === "execute"
            ? "execute"
            : input.action === "cleanup"
              ? "cleanup"
              : "prereq";
        const lifecycleAssertionPassed =
          input.action === "execute" &&
          test.success_criteria.some(
            (criterion) =>
              criterion.kind === "target_rebooted" || criterion.kind === "target_stopped"
          ) &&
          behaviorValidation?.ok === true;
        const runnerPassed =
          (result.exitCode === 0 && !result.timedOut) || lifecycleAssertionPassed;
        const behaviorPassed = input.action !== "execute" || behaviorValidation?.ok === true;
        const status = runnerPassed && behaviorPassed ? "passed" : "failed";
        const behaviorFailure =
          input.action === "execute" && !behaviorValidation?.ok
            ? "One or more digest-approved behavior success criteria failed"
            : undefined;
        const snapshot = store.recordExecution(input.run_id, {
          test_guid: test.test_guid,
          stage,
          status,
          started_at: result.startedAt,
          ended_at: result.endedAt,
          exit_code: result.exitCode ?? undefined,
          behavior_success:
            input.action === "execute" ? runnerPassed && behaviorPassed : undefined,
          evidence_path: evidencePath,
          notes: result.timedOut
            ? "Process timed out"
            : behaviorFailure
              ? behaviorFailure
              : lifecycleAssertionPassed && result.exitCode !== 0
                ? "Target lifecycle assertion confirmed the approved reboot/shutdown despite transport disconnect"
              : result.truncated
              ? "Tool response was truncated; full captured evidence is capped by MACOS_ATOMIC_MAX_OUTPUT_BYTES"
              : undefined,
        });
        return textResult(
          {
            ok: status === "passed",
            test_guid: test.test_guid,
            action: input.action,
            status,
            exit_code: result.exitCode,
            timed_out: result.timedOut,
            truncated: result.truncated,
            behavior_validation: behaviorValidation,
            evidence_path: evidencePath,
            stdout: result.stdout,
            stderr: result.stderr,
            run: snapshot,
          },
          status !== "passed"
        );
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    }
  );
}

export async function validateBehaviorSuccess(
  scope: AtomicPlan["scope"],
  test: AtomicPlan["tests"][number],
  stdout: string,
  stderr: string,
  executionStartedAt?: string
): Promise<BehaviorValidation> {
  const checks: Record<string, unknown>[] = [];
  for (const criterion of test.success_criteria) {
    if (criterion.kind === "stdout_contains" || criterion.kind === "stderr_contains") {
      const stream = criterion.kind === "stdout_contains" ? stdout : stderr;
      checks.push({ ...criterion, ok: stream.includes(criterion.value) });
      continue;
    }
    if (criterion.kind === "manual_evidence") {
      checks.push({ ...criterion, ok: false, error: "manual_evidence cannot validate an automated execution" });
      continue;
    }
    if (criterion.kind === "target_stopped") {
      if (scope.target_kind === "tart") {
        checks.push({ ...criterion, ...(await verifyTartStopped(scope)) });
      } else {
        checks.push({
          ...criterion,
          ok: false,
          supported: false,
          error: "target_stopped is only machine-verifiable for Tart targets",
        });
      }
      continue;
    }
    if (criterion.kind === "target_rebooted") {
      let result: Record<string, unknown> & { readonly ok: boolean };
      if (!executionStartedAt) {
        result = { ok: false, error: "target_rebooted requires the execution start time" };
      } else if (scope.target_kind === "tart" || scope.target_kind === "ssh") {
        result = await verifyMacosReboot(scope, executionStartedAt);
      } else {
        result = {
          ok: false,
          error: `target_rebooted is not supported for ${scope.platform} on ${scope.target_kind} targets`,
        };
      }
      checks.push({ ...criterion, ...result });
      continue;
    }
    if (
      criterion.kind === "target_path_contains" ||
      criterion.kind === "target_path_not_contains"
    ) {
      const result = await runOnTarget(
        scope,
        [
          "sudo",
          "python3",
          "-c",
          BEHAVIOR_PATH_CONTENT_CHECKER,
          criterion.kind === "target_path_contains" ? "contains" : "not_contains",
          criterion.path,
          criterion.value,
        ],
        30_000
      );
      checks.push({
        ...criterion,
        ok: result.exitCode === 0 && !result.timedOut,
        exit_code: result.exitCode,
        timed_out: result.timedOut,
        stderr: result.stderr,
      });
      continue;
    }
    const expected = criterion.kind === "target_path_exists" ? "exists" : "absent";
    const result = await runOnTarget(
      scope,
      ["sudo", "python3", "-c", BEHAVIOR_PATH_CHECKER, expected, criterion.path],
      30_000
    );
    checks.push({
      ...criterion,
      ok: result.exitCode === 0 && !result.timedOut,
      exit_code: result.exitCode,
      timed_out: result.timedOut,
      stderr: result.stderr,
    });
  }
  return { ok: checks.length > 0 && checks.every((check) => check.ok === true), checks };
}

type LifecycleProbeDeps = {
  readonly runOnTarget: typeof runOnTarget;
  readonly runProcess: typeof runProcess;
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
  readonly timeoutMs: number;
  readonly intervalMs: number;
};

const defaultLifecycleProbeDeps: LifecycleProbeDeps = {
  runOnTarget,
  runProcess,
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  timeoutMs: 180_000,
  intervalMs: 3_000,
};

/** Epoch seconds from `sysctl -n kern.boottime`, or undefined when unparseable. */
export function parseMacosBootEpochSeconds(stdout: string): number | undefined {
  const match = /sec\s*=\s*(\d+)/.exec(stdout);
  if (!match?.[1]) return undefined;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) ? seconds : undefined;
}

/** Running state from `tart list --format json`, or undefined when unparseable. */
export function parseTartRunning(stdout: string, targetId: string): boolean | undefined {
  try {
    const parsed = JSON.parse(stdout) as unknown;
    const records = Array.isArray(parsed)
      ? parsed
      : typeof parsed === "object" && parsed !== null && "vms" in parsed
        ? (parsed as { vms?: unknown }).vms
        : [];
    if (!Array.isArray(records)) return undefined;
    const record = records.find((value) => {
      if (typeof value !== "object" || value === null) return false;
      const candidate = value as Record<string, unknown>;
      return candidate.Name === targetId || candidate.name === targetId;
    }) as Record<string, unknown> | undefined;
    if (!record) return false;
    const running = record.Running ?? record.running;
    if (typeof running === "boolean") return running;
    const state = record.State ?? record.state;
    if (typeof state === "string") return state.toLowerCase() === "running";
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * A macOS guest has rebooted after the approved execution started when the kernel boot timestamp
 * is at or after that start. Transport failures during the restart are expected and retried.
 */
export async function verifyMacosReboot(
  scope: AtomicPlan["scope"],
  executionStartedAt: string,
  deps: LifecycleProbeDeps = defaultLifecycleProbeDeps
): Promise<Record<string, unknown> & { readonly ok: boolean }> {
  const started = Date.parse(executionStartedAt);
  if (!Number.isFinite(started)) return { ok: false, error: "invalid execution start time" };
  const deadline = deps.now() + deps.timeoutMs;
  let lastError = "target has not returned";
  while (deps.now() < deadline) {
    try {
      const result = await deps.runOnTarget(scope, ["sysctl", "-n", "kern.boottime"], 10_000);
      const bootEpochSeconds = parseMacosBootEpochSeconds(result.stdout);
      if (result.exitCode === 0 && bootEpochSeconds !== undefined) {
        const bootEpochMs = bootEpochSeconds * 1_000;
        if (bootEpochMs >= started - 2_000) {
          return {
            ok: true,
            boot_time: new Date(bootEpochMs).toISOString(),
            execution_started_at: executionStartedAt,
          };
        }
        lastError = "kernel boot time predates the approved execution start";
      } else {
        lastError = result.stderr.trim() || result.stdout.trim() || "kernel boot time unavailable";
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await deps.sleep(deps.intervalMs);
  }
  return { ok: false, error: lastError, execution_started_at: executionStartedAt };
}

/** A Tart instance has stopped when `tart list --format json` reports it not running. */
export async function verifyTartStopped(
  scope: AtomicPlan["scope"],
  deps: LifecycleProbeDeps = defaultLifecycleProbeDeps
): Promise<Record<string, unknown> & { readonly ok: boolean }> {
  const deadline = deps.now() + deps.timeoutMs;
  let running: boolean | undefined;
  while (deps.now() < deadline) {
    try {
      const result = await deps.runProcess(
        "tart",
        ["list", "--format", "json"],
        { timeoutMs: 15_000 }
      );
      const parsed = result.exitCode === 0 ? parseTartRunning(result.stdout, scope.target_id) : undefined;
      if (parsed !== undefined) {
        running = parsed;
        if (!parsed) return { ok: true, supported: true, running };
      }
    } catch {
      // keep polling until the deadline
    }
    await deps.sleep(deps.intervalMs);
  }
  return {
    ok: false,
    supported: true,
    running,
    error: "instance did not reach the stopped state",
  };
}

export function approvedPrivilegePrefix(
  scope: AtomicPlan["scope"],
  elevationRequired: boolean
): string[] {
  return elevationRequired
    ? ["sudo"]
    : ["sudo", "-H", "-u", scope.execution_user, "--"];
}

export function runnerLogDirectoryCommand(
  scope: AtomicPlan["scope"],
  runId: string
): string[] {
  return [
    "sudo",
    "install",
    "-d",
    "-m",
    "0700",
    "-o",
    scope.execution_user,
    "-g",
    scope.execution_user,
    `/var/tmp/macos-atomic-runs/${runId}`,
  ];
}

async function stageFixtures(
  runDir: string,
  scope: AtomicPlan["scope"],
  runId: string,
  test: AtomicPlan["tests"][number]
): Promise<{
  ok: boolean;
  fixtureCount: number;
  startedAt: string;
  endedAt: string;
  evidencePath: string;
  error?: string;
}> {
  const startedAt = new Date().toISOString();
  const fixtures = test.fixtures ?? [];
  const fixtureRoot = `/var/tmp/macos-atomic-runs/${runId}/fixtures`;
  const evidence: Array<Record<string, unknown>> = [];
  let error: string | undefined;

  if (fixtures.length === 0) {
    error = "No digest-approved fixtures are defined for this test";
  }

  for (const fixture of fixtures) {
    if (error) break;
    const configuredPath = test.inputs[fixture.input_name];
    if (typeof configuredPath !== "string") {
      error = `Fixture input ${fixture.input_name} must reference a string path`;
      break;
    }
    const normalizedPath = path.posix.normalize(configuredPath);
    if (
      normalizedPath !== configuredPath ||
      !normalizedPath.startsWith(`${fixtureRoot}/`)
    ) {
      error = `Fixture path must be beneath ${fixtureRoot}`;
      break;
    }
    const content = Buffer.from(fixture.content_base64, "base64");
    const actualDigest = createHash("sha256").update(content).digest("hex");
    if (actualDigest !== fixture.sha256.toLowerCase()) {
      error = `Fixture digest mismatch for ${fixture.input_name}`;
      break;
    }
    const install = await runOnTarget(
      scope,
      ["sudo", "install", "-d", "-m", "0700", path.posix.dirname(normalizedPath)],
      30_000
    );
    if (install.exitCode !== 0 || install.timedOut) {
      evidence.push({ input_name: fixture.input_name, path: normalizedPath, install });
      error = `Could not create fixture directory for ${fixture.input_name}`;
      break;
    }
    const write = await runOnTarget(
      scope,
      [
        "sudo",
        "env",
        `ATOMIC_FIXTURE_PATH=${normalizedPath}`,
        `ATOMIC_FIXTURE_B64=${fixture.content_base64}`,
        `ATOMIC_FIXTURE_SHA256=${fixture.sha256.toLowerCase()}`,
        `ATOMIC_FIXTURE_MODE=${fixture.mode}`,
        "python3",
        "-c",
        FIXTURE_WRITER,
      ],
      30_000
    );
    evidence.push({
      input_name: fixture.input_name,
      path: normalizedPath,
      sha256: fixture.sha256.toLowerCase(),
      mode: fixture.mode,
      install_exit_code: install.exitCode,
      write_exit_code: write.exitCode,
      write_stdout: write.stdout,
      write_stderr: write.stderr,
      timed_out: write.timedOut,
    });
    if (
      write.exitCode !== 0 ||
      write.timedOut ||
      write.stdout.trim() !== fixture.sha256.toLowerCase()
    ) {
      error = `Could not verify fixture ${fixture.input_name}`;
      break;
    }
    const ownership = await runOnTarget(
      scope,
      [
        "sudo",
        "chown",
        "-R",
        scope.execution_user,
        `/var/tmp/macos-atomic-runs/${runId}`,
      ],
      30_000
    );
    if (ownership.exitCode !== 0 || ownership.timedOut) {
      error = `Could not assign fixture ownership to ${scope.execution_user}`;
      break;
    }
  }

  const endedAt = new Date().toISOString();
  const evidenceDir = path.join(runDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const timestamp = startedAt.replace(/[:.]/g, "-");
  const evidencePath = path.join(
    evidenceDir,
    `${timestamp}-${test.test_guid}-stage_fixtures.json`
  );
  fs.writeFileSync(
    evidencePath,
    `${JSON.stringify({ started_at: startedAt, ended_at: endedAt, fixtures: evidence, error }, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 }
  );
  return {
    ok: !error,
    fixtureCount: evidence.length,
    startedAt,
    endedAt,
    evidencePath,
    error,
  };
}

function writeManualEvidence(
  runDir: string,
  test: AtomicPlan["tests"][number],
  value: {
    readonly stage: "manual" | "cleanup";
    readonly outcome: "completed" | "failed" | "blocked";
    readonly operator_attestation: string;
    readonly started_at: string;
    readonly ended_at: string;
    readonly observations?: string;
  }
): string {
  const evidenceDir = path.join(runDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const timestamp = new Date().toISOString();
  const file = path.join(
    evidenceDir,
    `${timestamp.replace(/[:.]/g, "-")}-${test.test_guid}-${value.stage}.json`
  );
  fs.writeFileSync(
    file,
    `${JSON.stringify({
      recorded_at: timestamp,
      started_at: value.started_at,
      ended_at: value.ended_at,
      test_guid: test.test_guid,
      stage: value.stage,
      outcome: value.outcome,
      reviewed_steps:
        value.stage === "manual" ? test.manual?.reviewed_steps : test.manual?.cleanup_steps,
      evidence_requirements: test.manual?.evidence_requirements,
      operator_attestation: value.operator_attestation,
      observations: value.observations,
    }, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 }
  );
  return file;
}

function writeEvidence(
  runDir: string,
  testGuid: string,
  action: string,
  result: { stdout: string; stderr: string; exitCode: number | null; timedOut: boolean; startedAt: string; endedAt: string },
  behaviorValidation?: BehaviorValidation
): string {
  const evidenceDir = path.join(runDir, "evidence");
  fs.mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  const timestamp = result.startedAt.replace(/[:.]/g, "-");
  const file = path.join(evidenceDir, `${timestamp}-${testGuid}-${action}.log`);
  const body = [
    `started_at=${result.startedAt}`,
    `ended_at=${result.endedAt}`,
    `exit_code=${result.exitCode ?? "null"}`,
    `timed_out=${result.timedOut}`,
    "",
    "[stdout]",
    result.stdout,
    "",
    "[stderr]",
    result.stderr,
    ...(behaviorValidation
      ? ["", "[behavior_validation]", JSON.stringify(behaviorValidation, null, 2)]
      : []),
    "",
  ].join("\n");
  fs.writeFileSync(file, body, { encoding: "utf8", mode: 0o600 });
  return file;
}
