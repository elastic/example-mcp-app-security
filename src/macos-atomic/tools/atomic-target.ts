/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  getElasticAgentStatus,
  getElasticEndpointReadiness,
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
  verifyApprovedPackages,
} from "../execution/approved-packages.js";
import { runSetupSteps } from "../execution/setup-steps.js";
import {
  stageApprovedOperatorSourceAssets,
  verifyApprovedSourceAssets,
} from "../execution/source-assets.js";
import { runProcess } from "../execution/process.js";
import {
  cloneAndStartTartTarget,
  stopAndDeleteTartTarget,
  tartTargetExists,
} from "../execution/tart.js";
import { runOnTarget } from "../execution/target.js";
import { verifyTargetCapabilities } from "../execution/target-capabilities.js";
import { assertSafeTargetId } from "../shared/validation.js";
import {
  createAtomicRunStore,
  type AtomicPlan,
  type AtomicRunStore,
} from "./atomic-run-state.js";
import { textResult } from "./atomic-run.js";

const targetSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("doctor") }),
  z.object({ action: z.literal("status"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("instrumentation_status"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("register"), run_id: z.string().min(1) }),
  z.object({ action: z.literal("provision"), run_id: z.string().min(1) }),
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
});

export const BOOTSTRAP_SCRIPT = `set -eu
for command in git python3 curl sudo; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "missing required base-image command: $command" >&2
    exit 1
  }
done
sudo -n true
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
install -d -m 1777 /var/tmp/macos-atomic-runs
`;

export const RUNNER_BOOTSTRAP_SCRIPT = `set -eu
command -v pwsh >/dev/null 2>&1 || {
  echo "missing pwsh after approved setup steps" >&2
  exit 1
}
pwsh -NoProfile -NonInteractive -Command "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; if (-not (Get-Module -ListAvailable powershell-yaml)) { Install-Module powershell-yaml -Scope AllUsers -Force -AllowClobber }"
`;

export function pinnedRepositoryRevisionArgs(repositoryPath: string): string[] {
  return ["sudo", "git", "-C", repositoryPath, "rev-parse", "HEAD"];
}

export function registerMacosAtomicTargetTool(
  server: McpServer,
  store: AtomicRunStore = createAtomicRunStore()
): void {
  server.registerTool(
    "macos-atomic-target",
    {
      title: "macOS Atomic Target",
      description:
        "Provision, register, verify, instrument, or destroy only the digest-approved macOS Tart/SSH target. Tart images must be OCI digest pinned. Elastic enrollment reuses the app default cluster credentials and requires a base image or MDM profile with the macOS Endpoint Security, network-filter, and Full Disk Access approvals.",
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
          return textResult(await targetStatus(plan));
        }
        if (parsed.action === "instrumentation_status") {
          if (!plan.instrumentation?.elastic_agent) {
            return textResult({ error: "The approved plan has no Elastic Agent instrumentation" }, true);
          }
          const status = await getElasticAgentStatus(plan.scope);
          const endpointReadiness = await getElasticEndpointReadiness(plan.scope, status);
          return textResult(
            { ok: endpointReadiness.ok, status, endpoint_readiness: endpointReadiness },
            !endpointReadiness.ok
          );
        }
        if (parsed.action === "register") {
          store.assertPhase(parsed.run_id, ["provisioning"]);
          return textResult(await registerTarget(store, parsed.run_id, plan));
        }
        if (parsed.action === "provision") {
          store.assertPhase(parsed.run_id, ["provisioning"]);
          if (plan.scope.target_kind !== "tart" || plan.scope.lifecycle !== "ephemeral") {
            return textResult(
              { error: "provision is allowed only for an approved ephemeral Tart target" },
              true
            );
          }
          if (plan.instrumentation?.elastic_agent) {
            await validateApprovedElasticConfiguration(
              plan.instrumentation.elastic_agent
            );
          }
          let launched: Awaited<ReturnType<typeof cloneAndStartTartTarget>>;
          try {
            launched = await cloneAndStartTartTarget(
              plan.scope,
              plan.controls.ttl_minutes
            );
          } catch (error) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: error instanceof Error ? error.message : String(error),
            });
            throw error;
          }
          if (launched.clone.exitCode !== 0 || launched.clone.timedOut) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "Tart clone failed or timed out",
            });
            return textResult({ ok: false, tart: launched }, true);
          }
          const bootstrap = await runOnTarget(
            plan.scope,
            [
              "sudo",
              "env",
              `ART_REPOSITORY=${plan.source.repository}`,
              `ART_REVISION=${plan.source.revision}`,
              `INVOKE_REPOSITORY=${plan.runner.repository}`,
              `INVOKE_REVISION=${plan.runner.revision}`,
              "/bin/sh",
              "-s",
            ],
            20 * 60_000,
            { input: BOOTSTRAP_SCRIPT }
          );
          if (bootstrap.exitCode !== 0 || bootstrap.timedOut) {
            store.recordResource(parsed.run_id, {
              id: plan.scope.target_id,
              kind: "target",
              origin: "orphaned",
              cleaned: false,
              notes: "macOS bootstrap failed",
            });
            return textResult({ ok: false, tart: launched, bootstrap }, true);
          }
          const packages = await installApprovedPackages(
            plan.scope,
            plan.target_prerequisites?.packages ?? []
          );
          if (!packages.ok) {
            return textResult({ ok: false, tart: launched, packages }, true);
          }
          const setup = await runSetupSteps(plan.scope, plan.setup_steps ?? []);
          if (!setup.ok) return textResult({ ok: false, tart: launched, setup }, true);
          const runnerBootstrap = await runOnTarget(
            plan.scope,
            ["sudo", "/bin/sh", "-s"],
            10 * 60_000,
            { input: RUNNER_BOOTSTRAP_SCRIPT }
          );
          if (runnerBootstrap.exitCode !== 0 || runnerBootstrap.timedOut) {
            return textResult(
              { ok: false, tart: launched, setup, runner_bootstrap: runnerBootstrap },
              true
            );
          }
          const registered = await registerTarget(store, parsed.run_id, plan);
          return textResult({
            ...registered,
            tart: launched,
            bootstrap,
            packages,
            setup,
            runner_bootstrap: runnerBootstrap,
          });
        }

        store.assertPhase(parsed.run_id, ["cleaning"]);
        if (plan.scope.lifecycle === "existing" || plan.scope.target_kind !== "tart") {
          return textResult(
            { error: "Automatic destruction is refused for existing SSH targets" },
            true
          );
        }
        for (const resource of loaded.resources) {
          if (
            resource.kind === "elastic-fleet-enrollment-token" &&
            !resource.cleaned &&
            resource.id.startsWith("fleet-enrollment-token:")
          ) {
            await revokeEnrollmentToken(resource.id.slice("fleet-enrollment-token:".length));
            store.recordResource(parsed.run_id, { ...resource, cleaned: true });
          }
        }
        const destroyed = await stopAndDeleteTartTarget(plan.scope.target_id);
        const absent = !(await tartTargetExists(plan.scope.target_id));
        if (!absent || destroyed.deleted.exitCode !== 0) {
          return textResult({ ok: false, destroyed, absent }, true);
        }
        const refreshed = store.getLoaded(parsed.run_id);
        for (const resource of refreshed.resources) {
          if (resource.id === plan.scope.target_id && resource.kind === "target") {
            store.recordResource(parsed.run_id, { ...resource, cleaned: true });
          }
        }
        return textResult({ ok: true, destroyed, target_absent: absent });
      } catch (error) {
        return textResult(
          { error: error instanceof Error ? error.message : String(error) },
          true
        );
      }
    }
  );
}

async function registerTarget(
  store: AtomicRunStore,
  runId: string,
  plan: AtomicPlan
): Promise<Record<string, unknown>> {
  const [user, version, architecture] = await Promise.all([
    runOnTarget(plan.scope, ["id", "-u", plan.scope.execution_user], 30_000),
    runOnTarget(plan.scope, ["sw_vers", "-productVersion"], 30_000),
    runOnTarget(plan.scope, ["uname", "-m"], 30_000),
  ]);
  if ([user, version, architecture].some((result) => result.exitCode !== 0 || result.timedOut)) {
    throw new Error("Target identity, macOS version, or architecture verification failed");
  }
  const actualMajor = version.stdout.trim().split(".", 1)[0];
  if (plan.scope.distro !== `macos-${actualMajor}`) {
    throw new Error(
      `Target macOS version ${version.stdout.trim()} does not match approved ${plan.scope.distro}`
    );
  }
  const actualArchitecture = normalizeArchitecture(architecture.stdout.trim());
  if (actualArchitecture !== plan.scope.architecture) {
    throw new Error(
      `Target architecture ${actualArchitecture} does not match approved ${plan.scope.architecture}`
    );
  }
  const [sourceRevision, runnerRevision, powershell, sourceAssets, packages, capabilities] =
    await Promise.all([
      runOnTarget(
        plan.scope,
        pinnedRepositoryRevisionArgs("/opt/atomic-red-team"),
        30_000
      ),
      runOnTarget(
        plan.scope,
        pinnedRepositoryRevisionArgs("/opt/invoke-atomicredteam"),
        30_000
      ),
      runOnTarget(plan.scope, ["pwsh", "--version"], 30_000),
      verifyApprovedSourceAssets(plan.scope, plan.tests),
      verifyApprovedPackages(plan.scope, plan.target_prerequisites?.packages ?? []),
      verifyTargetCapabilities(plan.scope),
    ]);
  if (
    sourceRevision.stdout.trim() !== plan.source.revision ||
    runnerRevision.stdout.trim() !== plan.runner.revision ||
    powershell.exitCode !== 0 ||
    !sourceAssets.ok ||
    !packages.ok ||
    !capabilities.ok
  ) {
    throw new Error("Target does not satisfy the digest-approved runtime and capability checks");
  }
  const stagedSourceAssets = await stageApprovedOperatorSourceAssets(
    plan.scope,
    runId,
    plan.tests
  );
  if (!stagedSourceAssets.ok) throw new Error("Approved operator assets could not be staged");

  let instrumentation: unknown;
  if (plan.instrumentation?.elastic_agent) {
    await validateApprovedElasticConfiguration(plan.instrumentation.elastic_agent);
    let status = await getElasticAgentStatus(plan.scope);
    if (!isElasticAgentHealthy(status)) {
      const enrollment = await createEphemeralEnrollmentToken(
        plan.instrumentation.elastic_agent,
        runId
      );
      store.recordResource(runId, {
        id: `fleet-enrollment-token:${enrollment.id}`,
        kind: "elastic-fleet-enrollment-token",
        origin: "provisioned",
        cleaned: false,
        notes: `Temporary token for policy ${enrollment.policyId}`,
      });
      try {
        instrumentation = await installAndVerifyElasticAgent(
          plan.scope,
          plan.instrumentation.elastic_agent,
          enrollment.token
        );
      } finally {
        await revokeEnrollmentToken(enrollment.id);
        store.recordResource(runId, {
          id: `fleet-enrollment-token:${enrollment.id}`,
          kind: "elastic-fleet-enrollment-token",
          origin: "provisioned",
          cleaned: true,
          notes: `Revoked temporary token for policy ${enrollment.policyId}`,
        });
      }
      if (!(instrumentation as { ok?: boolean }).ok) {
        throw new Error(
          "Elastic Agent did not become healthy; verify the base image or MDM profile grants Endpoint Security, network-filter, and Full Disk Access approvals"
        );
      }
      status = await getElasticAgentStatus(plan.scope);
    }
    if (!isElasticAgentHealthy(status)) throw new Error("Elastic Agent is not healthy");
    const endpointReadiness = await getElasticEndpointReadiness(plan.scope, status);
    if (!endpointReadiness.ok) {
      throw new Error(
        "Elastic Endpoint is not telemetry-ready; require an active and enabled co.elastic.systemextension plus successful Full Disk Access and network-filter install checks"
      );
    }
    instrumentation = instrumentation ?? { status, endpoint_readiness: endpointReadiness };
  }

  const snapshot = store.recordResource(runId, {
    id: plan.scope.target_id,
    kind: "target",
    origin: plan.scope.lifecycle === "existing" ? "existing" : "provisioned",
    cleaned: false,
    notes: `${plan.scope.target_kind}:${plan.scope.distro}:${plan.scope.architecture}`,
  });
  return {
    ok: true,
    macos_version: version.stdout.trim(),
    architecture: actualArchitecture,
    powershell: powershell.stdout.trim(),
    source_revision: sourceRevision.stdout.trim(),
    runner_revision: runnerRevision.stdout.trim(),
    source_assets: sourceAssets,
    staged_source_assets: stagedSourceAssets,
    packages,
    capabilities,
    instrumentation,
    run: snapshot,
  };
}

async function doctor(): Promise<Record<string, unknown>> {
  const checks = await Promise.all(
    [
      ["tart", ["--version"]],
      ["ssh", ["-V"]],
      ["git", ["--version"]],
    ].map(async ([command, args]) => {
      const result = await runProcess(command as string, args as string[], {
        timeoutMs: 15_000,
      });
      return {
        command,
        ok: result.exitCode === 0 && !result.timedOut,
        stdout: result.stdout.trim(),
        stderr: result.stderr.trim(),
      };
    })
  );
  return {
    ok: checks.every((check) => check.ok),
    host_platform: process.platform,
    host_architecture: process.arch,
    checks,
  };
}

async function targetStatus(plan: AtomicPlan): Promise<Record<string, unknown>> {
  if (plan.scope.target_kind === "tart") {
    const exists = await tartTargetExists(plan.scope.target_id);
    return { ok: exists, kind: "tart", target_id: plan.scope.target_id, exists };
  }
  const result = await runOnTarget(plan.scope, ["sw_vers", "-productVersion"], 30_000);
  return {
    ok: result.exitCode === 0 && !result.timedOut,
    kind: "ssh",
    target_id: plan.scope.target_id,
    macos_version: result.stdout.trim(),
    stderr: result.stderr.trim(),
  };
}

function normalizeArchitecture(value: string): "arm64" | "x86_64" {
  if (value === "arm64" || value === "aarch64") return "arm64";
  if (value === "x86_64" || value === "amd64") return "x86_64";
  throw new Error(`Unsupported macOS target architecture ${value}`);
}
