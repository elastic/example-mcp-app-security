/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  AtomicPlan,
  TargetCapability,
} from "../tools/atomic-run-state.js";
import { runOnTarget } from "./target.js";

type CapabilityResult = {
  readonly capability: TargetCapability;
  readonly ok: boolean;
  readonly evidence: string;
};

export async function verifyTargetCapabilities(
  scope: AtomicPlan["scope"]
): Promise<{ readonly ok: boolean; readonly results: readonly CapabilityResult[] }> {
  const results: CapabilityResult[] = [];
  for (const capability of scope.capabilities) {
    if (capability === "interactive") {
      const virtualDesktop =
        scope.lifecycle === "ephemeral" &&
        scope.target_kind === "multipass" &&
        scope.target_profile === "desktop";
      let ok =
        scope.lifecycle === "existing" &&
        ["desktop", "custom"].includes(scope.target_profile);
      let evidence = ok
        ? "Interactive access is plan-bound and requires operator attestation at execution"
        : "Interactive access requires an existing desktop/custom target or an active Multipass desktop";
      if (virtualDesktop) {
        const probe = await runOnTarget(
          scope,
          ["systemctl", "is-active", "atomic-desktop.service"],
          30_000
        );
        ok = probe.exitCode === 0 && !probe.timedOut && probe.stdout.trim() === "active";
        evidence = [probe.stdout.trim(), probe.stderr.trim()].filter(Boolean).join("\n");
      }
      results.push({
        capability,
        ok,
        evidence,
      });
      continue;
    }
    if (capability === "special_runtime") {
      const ok = scope.target_profile === "custom";
      results.push({
        capability,
        ok,
        evidence: ok
          ? "Custom runtime is plan-bound and must be evidenced by the test procedure"
          : "special_runtime requires target_profile=custom",
      });
      continue;
    }

    const commands: Partial<Record<TargetCapability, readonly string[][]>> = {
      shell: [["/bin/sh", "-c", "exit 0"]],
      powershell: [["pwsh", "--version"]],
      systemd: [["systemctl", "--version"]],
      kernel: [["uname", "-r"]],
      network: [["curl", "--version"]],
      container: [["test", "-f", "/.dockerenv"]],
      gui:
        scope.platform === "freebsd"
          ? [["test", "-S", "/tmp/.X11-unix/X99"]]
          : scope.target_kind === "multipass" && scope.target_profile === "desktop"
          ? [["systemctl", "is-active", "atomic-desktop.service"]]
          : [["systemctl", "get-default"]],
      browser: [
        ["sudo", "-u", scope.execution_user, "--", "firefox", "--version"],
        ["sudo", "-u", scope.execution_user, "--", "google-chrome", "--version"],
        ["sudo", "-u", scope.execution_user, "--", "chromium", "--version"],
        ["sudo", "-u", scope.execution_user, "--", "chromium-browser", "--version"],
      ],
      reboot:
        scope.platform === "freebsd"
          ? [["test", "-x", "/sbin/shutdown"]]
          : [["systemctl", "--version"]],
    };
    const candidates = commands[capability] ?? [];
    let evidence = "No compatible capability probe is defined";
    let ok = false;
    for (const command of candidates) {
      const probe = await runOnTarget(scope, command, 30_000);
      evidence = [probe.stdout.trim(), probe.stderr.trim()].filter(Boolean).join("\n");
      const graphical =
        capability !== "gui" ||
        probe.stdout.trim() === "graphical.target" ||
        probe.stdout.trim() === "active";
      if (probe.exitCode === 0 && !probe.timedOut && graphical) {
        ok = true;
        break;
      }
    }
    results.push({ capability, ok, evidence });
  }
  return { ok: results.every((result) => result.ok), results };
}
