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
import {
  getElasticAgentStatus,
  installAndVerifyElasticAgent,
  isElasticAgentHealthy,
} from "../execution/elastic-agent.js";
import {
  createEphemeralEnrollmentToken,
  revokeEnrollmentToken,
  validateApprovedElasticConfiguration,
} from "../execution/elastic-fleet.js";
import {
  installApprovedPackages,
} from "../execution/approved-packages.js";
import { runSetupSteps } from "../execution/setup-steps.js";
import {
  verifyApprovedPackages,
} from "../execution/approved-packages.js";
import { installDesktopProfile } from "../execution/desktop-profile.js";
import { runProcess } from "../execution/process.js";
import {
  destroyFreeBsdQemu,
  isQemuTargetRunning,
  provisionFreeBsdQemu,
  resumeFreeBsdQemuProvisioning,
  runOnQemuTarget,
} from "../execution/qemu-freebsd.js";
import {
  stageApprovedOperatorSourceAssets,
  verifyApprovedSourceAssets,
} from "../execution/source-assets.js";
import { runOnTarget } from "../execution/target.js";
import { verifyTargetCapabilities } from "../execution/target-capabilities.js";
import { assertSafeTargetId } from "../shared/validation.js";
import { createAtomicRunStore } from "./atomic-run-state.js";
import { textResult } from "./atomic-run.js";

const targetSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("doctor") }),
  z.object({ action: z.literal("status"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("instrumentation_status"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("register"), run_id: z.string().min(1) }),
  z.object({
    action: z.literal("provision"),
    run_id: z.string().min(1),
    image: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.:/_-]{1,80}$/).optional(),
    cpus: z.number().int().min(1).max(32).default(2),
    memory: z.string().regex(/^\d+(?:M|G)$/i).default("4G"),
    disk: z.string().regex(/^\d+(?:M|G)$/i).default("20G"),
  }),
  z.object({ action: z.literal("destroy"), run_id: z.string().min(1) }),
]);

const targetToolSchema = z.object({
  action: z.enum([
    "doctor",
    "status",
    "instrumentation_status",
    "register",
    "provision",
    "destroy",
  ]),
  run_id: z.string().min(1).optional(),
  image: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.:/_-]{1,80}$/).optional(),
  cpus: z.number().int().min(1).max(32).default(2),
  memory: z.string().regex(/^\d+(?:M|G)$/i).default("4G"),
  disk: z.string().regex(/^\d+(?:M|G)$/i).default("20G"),
});

export const BOOTSTRAP_SCRIPT = `set -euo pipefail
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl git snapd
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y ca-certificates curl git openssl sudo
  if ! command -v snap >/dev/null 2>&1; then
    dnf install -y epel-release
    dnf install -y snapd
  fi
  systemctl enable --now snapd.socket
  ln -sfn /var/lib/snapd/snap /snap
  snap wait system seed.loaded
else
  echo 'unsupported Linux package manager for Atomic bootstrap' >&2
  exit 1
fi
ensure_local_pwsh_launcher() {
  if snap list powershell >/dev/null 2>&1; then
    if [ -L /usr/local/bin/pwsh ]; then unlink /usr/local/bin/pwsh; fi
    printf '%s\n' '#!/bin/sh' 'exec /usr/bin/snap run powershell "$@"' > /usr/local/bin/pwsh
    chmod 0755 /usr/local/bin/pwsh
    if [ -L /usr/bin/pwsh ]; then unlink /usr/bin/pwsh; fi
    printf '%s\n' '#!/bin/sh' 'exec /usr/bin/snap run powershell "$@"' > /usr/bin/pwsh
    chmod 0755 /usr/bin/pwsh
  fi
}
ensure_local_pwsh_launcher
if ! command -v pwsh >/dev/null 2>&1; then
  cached_core="$(find /var/tmp/atomic-bootstrap-cache -maxdepth 1 -type f -name 'core*.snap' -print -quit 2>/dev/null || true)"
  cached_powershell="$(find /var/tmp/atomic-bootstrap-cache -maxdepth 1 -type f -name 'powershell*.snap' -print -quit 2>/dev/null || true)"
  if [ -n "$cached_core" ] && [ -n "$cached_powershell" ]; then
    snap install --dangerous "$cached_core"
    snap install --dangerous --classic "$cached_powershell"
  else
    snap install powershell --classic
  fi
fi
ensure_local_pwsh_launcher
pwsh -NoProfile -NonInteractive -Command \
  "if (-not (Get-Module -ListAvailable powershell-yaml | Where-Object Version -eq '0.4.12')) { Install-Module powershell-yaml -RequiredVersion 0.4.12 -Repository PSGallery -Scope AllUsers -Force }"
install_pinned_repo() {
  destination="$1"
  repository="$2"
  revision="$3"
  rm -rf "$destination"
  mkdir -p "$destination"
  git -C "$destination" init
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch --depth 1 origin "$revision"
  git -C "$destination" checkout --detach FETCH_HEAD
}
install_pinned_repo /opt/atomic-red-team "$ART_REPOSITORY" "$ART_REVISION"
install_pinned_repo /opt/invoke-atomicredteam "$INVOKE_REPOSITORY" "$INVOKE_REVISION"
pwsh -NoProfile -NonInteractive -Command 'Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; Install-Module powershell-yaml -Scope AllUsers -Force -AllowClobber'
install -d -m 1777 /var/tmp/atomic-runs
`;

export function registerAtomicTargetTool(
  server: McpServer,
  store = createAtomicRunStore()
): void {
  server.registerTool(
    "atomic-target",
    {
      title: "Linux Atomic Target",
      description:
        "Provision, verify, instrument, or destroy the digest-approved target. Linux uses a distro-bound Multipass image and optional Fleet enrollment; FreeBSD-only variants use an official checksum-verified QEMU guest and results-only Elastic output. Only KIBANA_URL and ELASTIC_API_KEY come from the MCP environment.",
      inputSchema: targetToolSchema,
      annotations: { destructiveHint: true },
    },
    async (input) => {
      try {
        const parsed = targetSchema.parse(input);
        if (parsed.action === "doctor") return textResult(await doctor());
        const loaded = store.getLoaded(parsed.run_id);
        if (!loaded.plan) return textResult({ error: "No plan is stored" }, true);
        const plan = loaded.plan;
        assertSafeTargetId(plan.scope.target_id);

        if (parsed.action === "status") {
          const result = await targetStatus(plan.scope.target_kind, plan.scope.target_id);
          return textResult(result, result.exitCode !== 0);
        }

        if (parsed.action === "instrumentation_status") {
          if (!plan.instrumentation?.elastic_agent) {
            return textResult({ error: "The approved plan has no Elastic Agent instrumentation" }, true);
          }
          if (plan.scope.platform === "freebsd") {
            return textResult({
              ok: true,
              mode: "results_only",
              reason:
                "Elastic Agent is not supported on FreeBSD; execution outcomes are still published to the approved Elasticsearch output",
            });
          }
          const status = await getElasticAgentStatus(plan.scope);
          const ok = isElasticAgentHealthy(status);
          return textResult({ ok, status }, !ok);
        }

        if (parsed.action === "register") {
          store.assertPhase(parsed.run_id, ["provisioning"]);
          const executionUser = await runOnTarget(
            plan.scope,
            ["sudo", "id", "-u", plan.scope.execution_user],
            30_000
          );
          if (executionUser.exitCode !== 0 || executionUser.timedOut) {
            return textResult(
              {
                ok: false,
                execution_user: executionUser,
              },
              true
            );
          }
          const needsRunner = plan.tests.some((test) => test.execution_mode === "runner");
          const needsSource = plan.tests.some((test) => (test.source_assets?.length ?? 0) > 0);
          let runnerVerification;
          let sourceRevision;
          if (needsRunner || needsSource) {
            sourceRevision = await runOnTarget(
              plan.scope,
              ["sudo", "git", "-C", "/opt/atomic-red-team", "rev-parse", "HEAD"],
              30_000
            );
            if (sourceRevision.exitCode !== 0 || sourceRevision.timedOut) {
              return textResult({ ok: false, source_revision: sourceRevision }, true);
            }
            if (sourceRevision.stdout.trim() !== plan.source.revision) {
              return textResult(
                {
                  error: "Target source repository revision does not match the digest-approved plan",
                  expected_source_revision: plan.source.revision,
                  actual_source_revision: sourceRevision.stdout.trim(),
                },
                true
              );
            }
          }
          if (needsRunner) {
            const [probe, runnerRevision] = await Promise.all([
              runOnTarget(
                plan.scope,
                [
                  "sudo",
                  "pwsh",
                  "-NoProfile",
                  "-NonInteractive",
                  "-Command",
                  "$PSVersionTable.PSVersion.ToString()",
                ],
                30_000
              ),
              runOnTarget(
                plan.scope,
                ["sudo", "git", "-C", "/opt/invoke-atomicredteam", "rev-parse", "HEAD"],
                30_000
              ),
            ]);
            if (
              probe.exitCode !== 0 ||
              runnerRevision.exitCode !== 0
            ) {
              return textResult(
                { ok: false, probe, source_revision: sourceRevision, runner_revision: runnerRevision },
                true
              );
            }
            if (
              runnerRevision.stdout.trim() !== plan.runner.revision
            ) {
              return textResult(
                {
                  error: "Target repository revisions do not match the digest-approved plan",
                  expected_source_revision: plan.source.revision,
                  actual_source_revision: sourceRevision?.stdout.trim(),
                  expected_runner_revision: plan.runner.revision,
                  actual_runner_revision: runnerRevision.stdout.trim(),
                },
                true
              );
            }
            runnerVerification = {
              required: true,
              powershell_version: probe.stdout.trim(),
              source_revision: sourceRevision?.stdout.trim(),
              runner_revision: runnerRevision.stdout.trim(),
            };
          } else {
            runnerVerification = {
              required: false,
              reason: "Every approved test uses the operator workflow",
              source_revision: sourceRevision?.stdout.trim(),
            };
          }
          const approvedSourceAssets = await verifyApprovedSourceAssets(plan.scope, plan.tests);
          if (!approvedSourceAssets.ok) {
            return textResult(
              {
                error: "Existing target does not match digest-approved Atomic support files",
                approved_source_assets: approvedSourceAssets,
              },
              true
            );
          }
          const approvedPackages = await verifyApprovedPackages(
            plan.scope,
            plan.target_prerequisites?.packages ?? []
          );
          if (!approvedPackages.ok) {
            return textResult(
              {
                error: "Existing target does not satisfy digest-approved package prerequisites",
                approved_packages: approvedPackages,
              },
              true
            );
          }
          const capabilities = await verifyTargetCapabilities(plan.scope);
          if (!capabilities.ok) {
            return textResult(
              {
                error: "Existing target does not satisfy digest-approved capabilities",
                capabilities,
              },
              true
            );
          }
          let instrumentation;
          if (plan.instrumentation?.elastic_agent) {
            instrumentation = await getElasticAgentStatus(plan.scope);
            if (!isElasticAgentHealthy(instrumentation)) {
              return textResult(
                {
                  error: "Existing target does not satisfy approved Elastic Agent instrumentation",
                  instrumentation,
                },
                true
              );
            }
          }
          const stagedSourceAssets = await stageApprovedOperatorSourceAssets(
            plan.scope,
            parsed.run_id,
            plan.tests
          );
          if (!stagedSourceAssets.ok) {
            return textResult(
              {
                error:
                  "Could not stage digest-approved operator assets inside the execution user's home",
                staged_source_assets: stagedSourceAssets,
              },
              true
            );
          }
          const snapshot = store.recordResource(parsed.run_id, {
            id: plan.scope.target_id,
            kind: "target",
            origin: plan.scope.lifecycle === "existing" ? "existing" : "provisioned",
            cleaned: false,
            notes: `${plan.scope.target_kind}:${plan.scope.distro}`,
          });
          return textResult({
            ok: true,
            execution_user: executionUser.stdout.trim(),
            capabilities,
            runner_verification: runnerVerification,
            approved_source_assets: approvedSourceAssets,
            staged_source_assets: stagedSourceAssets,
            approved_packages: approvedPackages,
            instrumentation,
            run: snapshot,
          });
        }

        if (parsed.action === "provision") {
          store.assertPhase(parsed.run_id, ["provisioning"]);
          if (
            plan.scope.target_kind === "qemu" &&
            plan.scope.platform === "freebsd" &&
            plan.scope.lifecycle === "ephemeral"
          ) {
            let elasticConfiguration;
            if (plan.instrumentation?.elastic_agent) {
              elasticConfiguration = await validateApprovedElasticConfiguration(
                plan.instrumentation.elastic_agent
              );
            }
            let qemu;
            try {
              let resumable = false;
              try {
                resumable = isQemuTargetRunning(plan.scope.target_id);
              } catch {
                // No retained target metadata: start a fresh disposable guest.
              }
              qemu = resumable
                ? await resumeFreeBsdQemuProvisioning(plan)
                : await provisionFreeBsdQemu(plan, {
                    cpus: parsed.cpus,
                    memory: parsed.memory,
                    disk: parsed.disk,
                  });
            } catch (error) {
              return textResult(
                { error: error instanceof Error ? error.message : String(error) },
                true
              );
            }
            const failQemuProvisioning = (notes: string, detail: Record<string, unknown>) => {
              store.recordResource(parsed.run_id, {
                id: plan.scope.target_id,
                kind: "target",
                origin: "orphaned",
                cleaned: false,
                notes,
              });
              return textResult({ ok: false, qemu, ...detail }, true);
            };
            const approvedSourceAssets = await verifyApprovedSourceAssets(plan.scope, plan.tests);
            if (!approvedSourceAssets.ok) {
              return failQemuProvisioning(
                "FreeBSD bootstrap succeeded but Atomic support-file verification failed",
                { approved_source_assets: approvedSourceAssets }
              );
            }
            const [sourceRevision, runnerRevision] = await Promise.all([
              runOnQemuTarget(
                plan.scope.target_id,
                ["sudo", "git", "-C", "/opt/atomic-red-team", "rev-parse", "HEAD"],
                30_000
              ),
              runOnQemuTarget(
                plan.scope.target_id,
                ["sudo", "git", "-C", "/opt/invoke-atomicredteam", "rev-parse", "HEAD"],
                30_000
              ),
            ]);
            if (
              sourceRevision.exitCode !== 0 ||
              runnerRevision.exitCode !== 0 ||
              sourceRevision.stdout.trim() !== plan.source.revision ||
              runnerRevision.stdout.trim() !== plan.runner.revision
            ) {
              return failQemuProvisioning(
                "FreeBSD bootstrap did not preserve the approved source revisions",
                { source_revision: sourceRevision, runner_revision: runnerRevision }
              );
            }
            const approvedPackages = await installApprovedPackages(
              plan.scope,
              plan.target_prerequisites?.packages ?? []
            );
            if (!approvedPackages.ok) {
              return failQemuProvisioning(
                "FreeBSD bootstrap succeeded but approved package installation failed",
                { approved_packages: approvedPackages }
              );
            }
            const setupSteps =
              plan.setup_steps && plan.setup_steps.length > 0
                ? await runSetupSteps(plan.scope, plan.setup_steps)
                : { ok: true, steps: [] as const };
            if (!setupSteps.ok) {
              return failQemuProvisioning(
                "FreeBSD bootstrap succeeded but an approved setup_step failed",
                { approved_packages: approvedPackages, setup_steps: setupSteps }
              );
            }
            const executionUser = await runOnQemuTarget(
              plan.scope.target_id,
              ["sudo", "id", "-u", plan.scope.execution_user],
              30_000
            );
            if (executionUser.exitCode !== 0 || executionUser.timedOut) {
              return failQemuProvisioning(
                "FreeBSD bootstrap succeeded but the approved execution user is unavailable",
                { execution_user: executionUser }
              );
            }
            const stagedSourceAssets = await stageApprovedOperatorSourceAssets(
              plan.scope,
              parsed.run_id,
              plan.tests
            );
            if (!stagedSourceAssets.ok) {
              return failQemuProvisioning(
                "FreeBSD bootstrap succeeded but approved operator assets could not be staged",
                { staged_source_assets: stagedSourceAssets }
              );
            }
            const capabilities = await verifyTargetCapabilities(plan.scope);
            if (!capabilities.ok) {
              return failQemuProvisioning(
                "FreeBSD bootstrap succeeded but target capabilities failed verification",
                { capabilities }
              );
            }
            const instrumentation = plan.instrumentation?.elastic_agent
              ? {
                  ok: true,
                  mode: "results_only",
                  reason:
                    "Elastic Agent is unsupported on FreeBSD; raw endpoint coverage must be recorded as no_telemetry while normalized results use the approved Elasticsearch output",
                }
              : undefined;
            const snapshot = store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "provisioned",
              cleaned: false,
              notes: `FreeBSD 15.1 QEMU; ART ${plan.source.revision}; internal digest-bound FreeBSD runner`,
            });
            return textResult({
              ok: true,
              qemu,
              approved_source_assets: approvedSourceAssets,
              source_revision: sourceRevision.stdout.trim(),
              runner_revision: runnerRevision.stdout.trim(),
              staged_source_assets: stagedSourceAssets,
              approved_packages: approvedPackages,
              setup_steps: setupSteps,
              execution_user: executionUser.stdout.trim(),
              capabilities,
              elastic_configuration: elasticConfiguration,
              instrumentation,
              run: snapshot,
            });
          }
          if (plan.scope.target_kind !== "multipass" || plan.scope.lifecycle !== "ephemeral") {
            return textResult(
              { error: "Provision supports only an ephemeral Multipass target from the approved plan" },
              true
            );
          }
          const expectedImage = multipassImageForDistro(plan.scope.distro);
          if (parsed.image !== undefined && parsed.image !== expectedImage) {
            return textResult(
              {
                error: "Multipass image does not match the digest-approved distro",
                expected_image: expectedImage,
                requested_image: parsed.image,
              },
              true
            );
          }
          const image = expectedImage;
          const elasticAgentPlan = plan.instrumentation?.elastic_agent;
          let elasticConfiguration;
          if (elasticAgentPlan) {
            elasticConfiguration = await validateApprovedElasticConfiguration(elasticAgentPlan);
          }
          const existing = await runProcess(
            "multipass",
            ["info", plan.scope.target_id, "--format", "json"],
            { timeoutMs: 15_000 }
          );
          const resumableOrphan = canResumeOrphanedMultipassTarget(
            loaded.state.phase,
            loaded.resources,
            plan.scope.target_id
          );
          let launch;
          if (existing.exitCode === 0) {
            if (!resumableOrphan) {
              return textResult(
                {
                  error: `Target ${plan.scope.target_id} already exists; use register or choose a fresh run`,
                },
                true
              );
            }
            const existingState = multipassStateFromInfo(
              existing.stdout,
              plan.scope.target_id
            );
            if (!existingState || !["Running", "Stopped"].includes(existingState)) {
              return textResult(
                {
                  error: `Orphaned target ${plan.scope.target_id} has an unsupported Multipass state`,
                  existing_state: existingState ?? "unknown",
                },
                true
              );
            }
            const resumeStart =
              existingState === "Stopped"
                ? await runProcess("multipass", ["start", plan.scope.target_id], {
                    timeoutMs: 5 * 60_000,
                  })
                : undefined;
            if (resumeStart && resumeStart.exitCode !== 0) {
              return textResult(
                {
                  ok: false,
                  error: `Could not restart orphaned target ${plan.scope.target_id}`,
                  resume_start: resumeStart,
                },
                true
              );
            }
            launch = {
              ...existing,
              resumed: true,
              previous_state: existingState,
              resume_start: resumeStart,
            };
          } else {
            launch = await runProcess(
              "multipass",
              [
                "launch",
                image,
                "--name",
                plan.scope.target_id,
                "--cpus",
                String(parsed.cpus),
                "--memory",
                parsed.memory,
                "--disk",
                parsed.disk,
              ],
              { timeoutMs: 10 * 60_000 }
            );
          }
          if (launch.exitCode !== 0) return textResult({ ok: false, launch }, true);
          const bootstrapCache = await seedCachedPowerShellSnaps(plan.scope);
          const bootstrap = await runOnTarget(
            plan.scope,
            [
              "sudo",
              "env",
              `ART_REPOSITORY=${plan.source.repository}`,
              `ART_REVISION=${plan.source.revision}`,
              `INVOKE_REPOSITORY=${plan.runner.repository}`,
              `INVOKE_REVISION=${plan.runner.revision}`,
              "bash",
              "-c",
              BOOTSTRAP_SCRIPT,
            ],
            40 * 60_000
          );
          if (bootstrap.exitCode !== 0) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "Multipass launch succeeded but bootstrap failed",
            });
            return textResult({ ok: false, launch, bootstrap_cache: bootstrapCache, bootstrap }, true);
          }
          const approvedSourceAssets = await verifyApprovedSourceAssets(plan.scope, plan.tests);
          if (!approvedSourceAssets.ok) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "Multipass bootstrap succeeded but Atomic support-file verification failed",
            });
            return textResult(
              { ok: false, launch, bootstrap, approved_source_assets: approvedSourceAssets },
              true
            );
          }
          const approvedPackages = await installApprovedPackages(
            plan.scope,
            plan.target_prerequisites?.packages ?? []
          );
          if (!approvedPackages.ok) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "Multipass bootstrap succeeded but approved package installation failed",
            });
            return textResult(
              { ok: false, launch, bootstrap, approved_packages: approvedPackages },
              true
            );
          }
          const setupSteps =
            plan.setup_steps && plan.setup_steps.length > 0
              ? await runSetupSteps(plan.scope, plan.setup_steps)
              : { ok: true, steps: [] as const };
          if (!setupSteps.ok) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "Multipass bootstrap succeeded but an approved setup_step failed",
            });
            return textResult(
              { ok: false, launch, bootstrap, approved_packages: approvedPackages, setup_steps: setupSteps },
              true
            );
          }
          const executionUser = await runOnTarget(
            plan.scope,
            ["sudo", "id", "-u", plan.scope.execution_user],
            30_000
          );
          if (executionUser.exitCode !== 0 || executionUser.timedOut) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "Multipass bootstrap succeeded but the approved execution user is unavailable",
            });
            return textResult(
              {
                ok: false,
                launch,
                bootstrap,
                approved_source_assets: approvedSourceAssets,
                approved_packages: approvedPackages,
                execution_user: executionUser,
              },
              true
            );
          }
          const stagedSourceAssets = await stageApprovedOperatorSourceAssets(
            plan.scope,
            parsed.run_id,
            plan.tests
          );
          if (!stagedSourceAssets.ok) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes:
                "Multipass bootstrap succeeded but approved operator support files could not be staged",
            });
            return textResult(
              {
                ok: false,
                launch,
                bootstrap,
                approved_source_assets: approvedSourceAssets,
                staged_source_assets: stagedSourceAssets,
                approved_packages: approvedPackages,
                execution_user: executionUser,
              },
              true
            );
          }
          const desktop =
            plan.scope.target_profile === "desktop"
              ? await installDesktopProfile(plan.scope, parsed.run_id)
              : undefined;
          if (desktop && !desktop.ok) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "Multipass bootstrap succeeded but the approved browser desktop failed to start",
            });
            return textResult(
              {
                ok: false,
                launch,
                bootstrap,
                approved_source_assets: approvedSourceAssets,
                staged_source_assets: stagedSourceAssets,
                approved_packages: approvedPackages,
                desktop,
              },
              true
            );
          }
          const capabilities = await verifyTargetCapabilities(plan.scope);
          if (!capabilities.ok) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "Multipass bootstrap succeeded but execution user or capabilities failed verification",
            });
            return textResult(
              {
                ok: false,
                launch,
                bootstrap,
                approved_source_assets: approvedSourceAssets,
                staged_source_assets: stagedSourceAssets,
                approved_packages: approvedPackages,
                execution_user: executionUser,
                capabilities,
                desktop,
              },
              true
            );
          }
          let instrumentation;
          let enrollment;
          let enrollmentCleanup;
          if (elasticAgentPlan) {
            try {
              enrollment = await createEphemeralEnrollmentToken(elasticAgentPlan, parsed.run_id);
            } catch (error) {
              store.recordResource(parsed.run_id, {
                id: plan.scope.target_id,
                kind: "target",
                origin: "orphaned",
                cleaned: false,
                notes: "Multipass bootstrap succeeded but Fleet enrollment token creation failed",
              });
              return textResult(
                {
                  ok: false,
                  launch,
                  bootstrap,
                  elastic_configuration: elasticConfiguration,
                  error: error instanceof Error ? error.message : String(error),
                },
                true
              );
            }
            try {
              instrumentation = await installAndVerifyElasticAgent(
                plan.scope,
                elasticAgentPlan,
                enrollment.token
              );
            } catch (error) {
              instrumentation = {
                ok: false,
                installation: {
                  error: error instanceof Error ? error.message : String(error),
                },
                status: { exitCode: null, timedOut: false, stdout: "", stderr: "" },
              };
            } finally {
              try {
                enrollmentCleanup = await revokeEnrollmentToken(enrollment.id);
              } catch (error) {
                enrollmentCleanup = {
                  ok: false,
                  id: enrollment.id,
                  error: error instanceof Error ? error.message : String(error),
                };
              }
            }
            if (enrollmentCleanup.ok !== true) {
              store.recordResource(parsed.run_id, {
                id: `fleet-enrollment-token:${enrollment.id}`,
                kind: "elastic-fleet-enrollment-token",
                origin: "orphaned",
                cleaned: false,
                notes: `Temporary enrollment token for policy ${elasticAgentPlan.agent_policy_id}`,
              });
              store.recordResource(parsed.run_id, {
                id: plan.scope.target_id,
                kind: "target",
                origin: "orphaned",
                cleaned: false,
                notes: "Elastic Agent provisioning completed but enrollment-token cleanup failed",
              });
              return textResult(
                {
                  ok: false,
                  launch,
                  bootstrap,
                  elastic_configuration: elasticConfiguration,
                  enrollment: {
                    id: enrollment.id,
                    policy_id: enrollment.policyId,
                    expires_in: enrollment.expiresIn,
                  },
                  enrollment_cleanup: enrollmentCleanup,
                  instrumentation,
                },
                true
              );
            }
            if (!instrumentation.ok) {
              store.recordResource(parsed.run_id, {
                id: plan.scope.target_id,
                kind: "target",
                origin: "orphaned",
                cleaned: false,
                notes: "Multipass bootstrap succeeded but Elastic Agent enrollment or health verification failed",
              });
              return textResult(
                {
                  ok: false,
                  launch,
                  bootstrap,
                  elastic_configuration: elasticConfiguration,
                  enrollment: {
                    id: enrollment.id,
                    policy_id: enrollment.policyId,
                    expires_in: enrollment.expiresIn,
                  },
                  enrollment_cleanup: enrollmentCleanup,
                  instrumentation,
                },
                true
              );
            }
          }
          const snapshot = store.recordResource(parsed.run_id, {
            id: plan.scope.target_id,
            kind: "target",
            origin: "provisioned",
            cleaned: false,
            notes: `${image}; ART ${plan.source.revision}; Invoke-AtomicRedTeam ${plan.runner.revision}${approvedPackages.packages.length ? `; packages ${approvedPackages.packages.map((item) => `${item.name}@${item.installed_version ?? "unknown"}`).join(",")}` : ""}${desktop ? "; browser desktop" : ""}${elasticAgentPlan ? `; Elastic Agent ${elasticAgentPlan.version}` : ""}`,
          });
          return textResult({
            ok: true,
            launch,
            bootstrap_cache: bootstrapCache,
            bootstrap,
            approved_source_assets: approvedSourceAssets,
            staged_source_assets: stagedSourceAssets,
            approved_packages: approvedPackages,
            execution_user: executionUser.stdout.trim(),
            capabilities,
            desktop_access: desktop?.access,
            elastic_configuration: elasticConfiguration,
            enrollment: enrollment
              ? {
                  id: enrollment.id,
                  policy_id: enrollment.policyId,
                  expires_in: enrollment.expiresIn,
                }
              : undefined,
            enrollment_cleanup: enrollmentCleanup,
            instrumentation,
            run: snapshot,
          });
        }

        const orphanedProvisioningTarget =
          loaded.state.phase === "provisioning" &&
          loaded.resources.some(
            (resource) =>
              resource.id === plan.scope.target_id &&
              resource.kind === "target" &&
              resource.origin === "orphaned" &&
              !resource.cleaned
          );
        if (!orphanedProvisioningTarget) {
          store.assertPhase(parsed.run_id, ["cleaning"]);
        }
        if (
          !["multipass", "qemu"].includes(plan.scope.target_kind) ||
          plan.scope.lifecycle !== "ephemeral"
        ) {
          return textResult(
            { error: "Automatic destroy is limited to approved ephemeral Multipass/QEMU targets" },
            true
          );
        }
        const pendingEnrollmentTokens = loaded.resources.filter(
          (resource) =>
            resource.kind === "elastic-fleet-enrollment-token" &&
            resource.id.startsWith("fleet-enrollment-token:") &&
            !resource.cleaned
        );
        const enrollmentCleanup = [];
        for (const resource of pendingEnrollmentTokens) {
          const tokenId = resource.id.slice("fleet-enrollment-token:".length);
          try {
            const cleanup = await revokeEnrollmentToken(tokenId);
            enrollmentCleanup.push(cleanup);
            store.recordResource(parsed.run_id, { ...resource, cleaned: true });
          } catch (error) {
            return textResult(
              {
                ok: false,
                error: `Could not revoke orphaned Fleet enrollment token ${tokenId}: ${
                  error instanceof Error ? error.message : String(error)
                }`,
                enrollment_cleanup: enrollmentCleanup,
              },
              true
            );
          }
        }
        const destroyed = plan.scope.target_kind === "qemu"
          ? await destroyFreeBsdQemu(plan.scope.target_id)
          : await runProcess(
              "multipass",
              ["delete", "--purge", plan.scope.target_id],
              { timeoutMs: 5 * 60_000 }
            );
        if ("exitCode" in destroyed && destroyed.exitCode !== 0) {
          return textResult({ ok: false, destroyed }, true);
        }
        const snapshot = store.recordResource(parsed.run_id, {
          id: plan.scope.target_id,
          kind: "target",
          origin: "provisioned",
          cleaned: true,
          notes:
            plan.scope.target_kind === "qemu"
              ? "QEMU process stopped and private target directory removed"
              : "Multipass instance deleted with --purge",
        });
        return textResult({ ok: true, enrollment_cleanup: enrollmentCleanup, destroyed, run: snapshot });
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    }
  );
}

async function doctor() {
  const commands = [
    ["multipass", ["version"]],
    ["docker", ["version", "--format", "{{.Server.Version}}"]],
    ["ssh", ["-V"]],
    [process.arch === "arm64" ? "qemu-system-aarch64" : "qemu-system-x86_64", ["--version"]],
    ["qemu-img", ["--version"]],
    ["xz", ["--version"]],
    ["hdiutil", ["info"]],
  ] as const;
  const results = await Promise.all(
    commands.map(async ([command, args]) => {
      try {
        const result = await runProcess(command, args, { timeoutMs: 10_000 });
        return { command, available: result.exitCode === 0, stdout: result.stdout, stderr: result.stderr };
      } catch (error) {
        return { command, available: false, error: error instanceof Error ? error.message : String(error) };
      }
    })
  );
  return {
    ok: true,
    adapters: results,
    elastic_minimal_input_configured: Boolean(
      process.env.KIBANA_URL?.trim() && process.env.ELASTIC_API_KEY?.trim()
    ),
  };
}

type VerifiedSnapCacheFile = {
  role: "base" | "powershell";
  name: string;
  size: number;
  sha256: string;
  path: string;
};

async function seedCachedPowerShellSnaps(
  scope: Parameters<typeof runOnTarget>[0]
): Promise<Record<string, unknown>> {
  const installed = await runOnTarget(
    scope,
    ["sh", "-c", "command -v pwsh >/dev/null 2>&1"],
    10_000
  );
  if (installed.exitCode === 0) {
    return { ok: true, used: false, reason: "powershell_already_installed" };
  }
  const cache = await loadVerifiedPowerShellSnapCache();
  if (!cache.ok || !cache.files) return cache;

  const transfers = [];
  for (const file of cache.files) {
    const uploadPath = `/var/tmp/atomic-bootstrap-${file.name}`;
    const transfer = await runProcess(
      "multipass",
      ["transfer", file.path, `${scope.target_id}:${uploadPath}`],
      { timeoutMs: 5 * 60_000 }
    );
    transfers.push({ role: file.role, name: file.name, result: transfer });
    if (transfer.exitCode !== 0) {
      return {
        ok: false,
        used: false,
        reason: "cache_transfer_failed; falling back to the Snap store",
        transfers,
      };
    }
  }

  const quotedNames = cache.files.map((file) => file.name);
  const stage = await runOnTarget(
    scope,
    [
      "sudo",
      "bash",
      "-c",
      [
        "set -euo pipefail",
        "install -d -m 0700 /var/tmp/atomic-bootstrap-cache",
        ...quotedNames.map(
          (name) =>
            `install -o root -g root -m 0600 /var/tmp/atomic-bootstrap-${name} /var/tmp/atomic-bootstrap-cache/${name}`
        ),
      ].join("\n"),
    ],
    2 * 60_000
  );
  if (stage.exitCode !== 0 || stage.timedOut) {
    return {
      ok: false,
      used: false,
      reason: "cache_staging_failed; falling back to the Snap store",
      transfers,
      stage,
    };
  }
  return {
    ok: true,
    used: true,
    manifest_path: cache.manifest_path,
    files: cache.files.map(({ role, name, size, sha256 }) => ({ role, name, size, sha256 })),
    transfers,
    stage,
  };
}

async function loadVerifiedPowerShellSnapCache(): Promise<{
  ok: boolean;
  used: false;
  reason?: string;
  manifest_path?: string;
  files?: VerifiedSnapCacheFile[];
}> {
  const architecture = process.arch === "arm64" ? "arm64" : process.arch === "x64" ? "x86_64" : undefined;
  if (!architecture) {
    return { ok: true, used: false, reason: `no cache mapping for host architecture ${process.arch}` };
  }
  const cacheDir = path.resolve(process.cwd(), ".atomic-cache", "snap", architecture);
  const manifestPath = path.join(cacheDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    return { ok: true, used: false, reason: "verified PowerShell snap cache is not configured" };
  }
  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
      schema_version?: unknown;
      architecture?: unknown;
      files?: unknown;
    };
    if (
      manifest.schema_version !== 1 ||
      manifest.architecture !== architecture ||
      !Array.isArray(manifest.files)
    ) {
      return {
        ok: false,
        used: false,
        reason: "PowerShell snap cache manifest metadata is invalid; falling back to the Snap store",
        manifest_path: manifestPath,
      };
    }
    const files: VerifiedSnapCacheFile[] = [];
    for (const role of ["base", "powershell"] as const) {
      const entry = manifest.files.find(
        (candidate): candidate is Record<string, unknown> =>
          typeof candidate === "object" && candidate !== null && candidate.role === role
      );
      if (
        !entry ||
        typeof entry.name !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{1,127}\.snap$/.test(entry.name) ||
        typeof entry.size !== "number" ||
        !Number.isSafeInteger(entry.size) ||
        entry.size <= 0 ||
        typeof entry.sha256 !== "string" ||
        !/^[0-9a-f]{64}$/i.test(entry.sha256)
      ) {
        return {
          ok: false,
          used: false,
          reason: `PowerShell snap cache ${role} entry is invalid; falling back to the Snap store`,
          manifest_path: manifestPath,
        };
      }
      const filePath = path.join(cacheDir, entry.name);
      const stat = fs.statSync(filePath);
      const digest = await sha256File(filePath);
      if (stat.size !== entry.size || digest !== entry.sha256.toLowerCase()) {
        return {
          ok: false,
          used: false,
          reason: `PowerShell snap cache ${role} digest or size mismatch; falling back to the Snap store`,
          manifest_path: manifestPath,
        };
      }
      files.push({
        role,
        name: entry.name,
        size: entry.size,
        sha256: digest,
        path: filePath,
      });
    }
    return {
      ok: true,
      used: false,
      manifest_path: manifestPath,
      files,
    };
  } catch (error) {
    return {
      ok: false,
      used: false,
      reason: `PowerShell snap cache validation failed; falling back to the Snap store: ${
        error instanceof Error ? error.message : String(error)
      }`,
      manifest_path: manifestPath,
    };
  }
}

async function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

async function targetStatus(kind: "multipass" | "docker" | "ssh" | "qemu", id: string) {
  switch (kind) {
    case "multipass":
      return runProcess("multipass", ["info", id, "--format", "json"], { timeoutMs: 15_000 });
    case "docker":
      return runProcess("docker", ["inspect", id, "--format", "{{json .State}}"], { timeoutMs: 15_000 });
    case "ssh":
      return runProcess("ssh", ["-o", "BatchMode=yes", "--", id, "uname", "-a"], { timeoutMs: 15_000 });
    case "qemu":
      return runOnQemuTarget(id, ["uname", "-a"], 15_000);
  }
}

export function canResumeOrphanedMultipassTarget(
  phase: string,
  resources: readonly {
    id: string;
    kind: string;
    origin: string;
    cleaned: boolean;
  }[],
  targetId: string
): boolean {
  return (
    phase === "provisioning" &&
    resources.some(
      (resource) =>
        resource.id === targetId &&
        resource.kind === "target" &&
        resource.origin === "orphaned" &&
        !resource.cleaned
    )
  );
}

export function multipassStateFromInfo(stdout: string, targetId: string): string | undefined {
  try {
    const parsed = JSON.parse(stdout) as {
      info?: Record<string, { state?: unknown }>;
    };
    const state = parsed.info?.[targetId]?.state;
    return typeof state === "string" ? state : undefined;
  } catch {
    return undefined;
  }
}

export function multipassImageForDistro(distro: string): string {
  const match = /^ubuntu-(\d{2}\.\d{2})$/i.exec(distro.trim());
  if (match?.[1]) return match[1];
  if (distro.trim().toLowerCase() === "rhel-9") {
    return "https://download.rockylinux.org/pub/rocky/9/images/aarch64/Rocky-9-GenericCloud-Base-9.8-20260525.0.aarch64.qcow2";
  }
  throw new Error(`Automatic Multipass provisioning does not recognize distro ${distro}`);
}
