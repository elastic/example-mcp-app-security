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
    if (["interactive", "tcc", "full_disk_access"].includes(capability)) {
      const ok = ["desktop", "custom"].includes(scope.target_profile);
      results.push({
        capability,
        ok,
        evidence: ok
          ? `${capability} is bound to a desktop/custom image and requires operator or MDM attestation`
          : `${capability} requires target_profile=desktop or custom`,
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
      launchd: [["sudo", "launchctl", "print", "system"]],
      kernel: [["uname", "-r"]],
      network: [["curl", "--version"]],
      gui: [["pgrep", "-x", "WindowServer"]],
      browser: [
        ["test", "-d", "/Applications/Safari.app"],
        ["test", "-d", "/Applications/Google Chrome.app"],
        ["test", "-d", "/Applications/Firefox.app"],
      ],
      reboot: [["test", "-x", "/sbin/shutdown"]],
      endpoint_security: [
        ["sudo", "systemextensionsctl", "list"],
      ],
      sip: [["csrutil", "status"]],
      real_hardware: [
        ["/bin/sh", "-c", "case \"$(sysctl -n hw.model)\" in VirtualMac*) exit 1;; *) exit 0;; esac"],
      ],
    };
    const candidates = commands[capability] ?? [];
    let evidence = "No compatible capability probe is defined";
    let ok = false;
    for (const command of candidates) {
      const probe = await runOnTarget(scope, command, 30_000);
      evidence = [probe.stdout.trim(), probe.stderr.trim()].filter(Boolean).join("\n");
      if (
        probe.exitCode === 0 &&
        !probe.timedOut &&
        (capability !== "endpoint_security" ||
          /ElasticEndpoint|co\.elastic\.systemextension/i.test(probe.stdout))
      ) {
        ok = true;
        break;
      }
    }
    results.push({ capability, ok, evidence });
  }
  return { ok: results.every((result) => result.ok), results };
}
