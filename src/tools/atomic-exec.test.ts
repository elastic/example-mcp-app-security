/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { ProcessResult } from "../execution/process.js";
import type { AtomicPlan } from "./atomic-run-state.js";
import {
  approvedPrivilegePrefix,
  BASH_INTERACTIVE_RUNNER,
  FREEBSD_RUNNER,
  hasBehaviorExecution,
  parseLinuxUptimeSeconds,
  parseMultipassState,
  runnerLogDirectoryCommand,
  validateBehaviorSuccess,
  verifyLinuxReboot,
  verifyMultipassStopped,
} from "./atomic-exec.js";

describe("interactive Bash runner", () => {
  it("resolves one exact pinned GUID and invokes a Bash prompt loop", () => {
    expect(BASH_INTERACTIVE_RUNNER).toContain("must contain exactly one requested GUID");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/bin/bash --noprofile --norc -i");
    expect(BASH_INTERACTIVE_RUNNER).toContain("approved input is not declared");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/var/tmp/atomic-bash-history-");
    expect(BASH_INTERACTIVE_RUNNER).toContain("/var/tmp/atomic-bash-history-option-");
    expect(BASH_INTERACTIVE_RUNNER).toContain("set -o | grep '^history'");
  });
});

const scope: AtomicPlan["scope"] = {
  target_kind: "multipass",
  target_id: "unused-for-output-checks",
  target_profile: "server",
  execution_user: "ubuntu",
  capabilities: ["shell", "powershell", "systemd", "kernel", "network"],
  platform: "linux",
  distro: "ubuntu-24.04",
  classification: "owned-disposable-lab",
  lifecycle: "ephemeral",
  network: "egress-only",
};

describe("prerequisite execution ordering", () => {
  it("distinguishes setup records from behavior execution", () => {
    expect(hasBehaviorExecution([{ stage: "prereq" }, { stage: "cleanup" }])).toBe(false);
    expect(hasBehaviorExecution([{ stage: "prereq" }, { stage: "execute" }])).toBe(true);
    expect(hasBehaviorExecution([{ stage: "manual" }])).toBe(true);
  });
});

const test = (value: string): AtomicPlan["tests"][number] => ({
  technique_id: "T1001.002",
  test_guid: "4ff61684-ad91-405c-9fbc-048354ff1d07",
  name: "Execute Embedded Script in Image via Steganography",
  executor: "sh",
  execution_mode: "runner",
  elevation_required: false,
  required_capabilities: ["shell"],
  definition_digest: "a".repeat(64),
  inputs: {},
  expected_outcome: "The extracted benign script emits its marker",
  success_criteria: [{ kind: "stdout_contains", value }],
  cleanup_expected: true,
  risk_flags: [],
});

describe("behavior success validation", () => {
  it("accepts an exact digest-approved stdout marker", async () => {
    const result = await validateBehaviorSuccess(
      scope,
      test("ATOMIC-STEG-e62dae"),
      "uid=0(root)\nATOMIC-STEG-e62dae\n",
      ""
    );
    expect(result.ok).toBe(true);
  });

  it("rejects runner output when the intended behavior marker is absent", async () => {
    const result = await validateBehaviorSuccess(
      scope,
      test("ATOMIC-STEG-e62dae"),
      "runner completed with exit code 0\n",
      ""
    );
    expect(result.ok).toBe(false);
  });
});

describe("approved elevation", () => {
  it("runs non-elevated atomics as the approved Linux user", () => {
    expect(approvedPrivilegePrefix(scope, false)).toEqual([
      "sudo",
      "-u",
      "ubuntu",
      "--",
    ]);
  });

  it("runs elevation-required atomics as root", () => {
    expect(approvedPrivilegePrefix(scope, true)).toEqual(["sudo"]);
  });

  it("assigns the run evidence directory to the approved execution user", () => {
    expect(runnerLogDirectoryCommand(scope, "linux-example-a1")).toEqual([
      "sudo",
      "install",
      "-d",
      "-m",
      "0700",
      "-o",
      "ubuntu",
      "-g",
      "ubuntu",
      "/var/tmp/atomic-runs/linux-example-a1",
    ]);
  });
});

describe("FreeBSD guest runner", () => {
  it("is valid Python source", () => {
    expect(() =>
      execFileSync(
        "python3",
        ["-c", "import sys; compile(sys.stdin.read(), '<freebsd-runner>', 'exec')"],
        { input: FREEBSD_RUNNER }
      )
    ).not.toThrow();
  });

  it("accepts a successful get-prereq command when exit 1 is the forced-acquisition sentinel", () => {
    const root = mkdtempSync(path.join(tmpdir(), "freebsd-runner-prereq-"));
    const technique = "T9999";
    const guid = "11111111-1111-4111-8111-111111111111";
    const marker = path.join(root, "compiled-payload");
    mkdirSync(path.join(root, technique));
    writeFileSync(
      path.join(root, technique, `${technique}.yaml`),
      `attack_technique: ${technique}
atomic_tests:
  - name: forced compilation
    auto_generated_guid: ${guid}
    dependencies:
      - prereq_command: exit 1
        get_prereq_command: touch ${marker}
    executor:
      name: sh
      elevation_required: false
      command: true
`,
      "utf8"
    );
    const runner = FREEBSD_RUNNER.replace(
      'root = pathlib.Path("/opt/atomic-red-team/atomics")',
      `root = pathlib.Path(${JSON.stringify(root)})`
    );
    try {
      expect(() =>
        execFileSync("python3", ["-c", runner], {
          env: {
            ...process.env,
            ATOMIC_TECHNIQUE: technique,
            ATOMIC_TEST_GUID: guid,
            ATOMIC_ACTION: "get_prereqs",
            ATOMIC_INPUTS_B64: Buffer.from("{}", "utf8").toString("base64"),
            ATOMIC_TIMEOUT_SECONDS: "30",
          },
        })
      ).not.toThrow();
      expect(existsSync(marker)).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("Linux and Multipass lifecycle verification", () => {
  const result = (stdout: string, exitCode: number | null = 0, stderr = ""): ProcessResult =>
    ({ stdout, stderr, exitCode, timedOut: false, truncated: false }) as unknown as ProcessResult;

  const clock = (startMs: number) => {
    let now = startMs;
    return {
      now: () => now,
      sleep: async (ms: number) => {
        now += ms;
      },
    };
  };

  it("parses /proc/uptime and multipass info output", () => {
    expect(parseLinuxUptimeSeconds("12.34 56.78\n")).toBe(12.34);
    expect(parseLinuxUptimeSeconds("garbage")).toBeUndefined();
    expect(
      parseMultipassState(
        JSON.stringify({ errors: [], info: { vm1: { state: "Stopped" } } }),
        "vm1"
      )
    ).toBe("Stopped");
    expect(parseMultipassState("not json", "vm1")).toBeUndefined();
    expect(parseMultipassState(JSON.stringify({ info: {} }), "vm1")).toBeUndefined();
  });

  it("accepts a Linux guest whose uptime is shorter than the time since execution started", async () => {
    const started = 1_000_000;
    const c = clock(started + 20_000);
    const verdict = await verifyLinuxReboot(scope, new Date(started).toISOString(), {
      runOnTarget: async () => result("9.50 30.00\n"),
      runProcess: async () => result(""),
      ...c,
      timeoutMs: 60_000,
      intervalMs: 1_000,
    });
    expect(verdict.ok).toBe(true);
  });

  it("waits through transport failures while the guest restarts, then succeeds", async () => {
    const started = 2_000_000;
    const c = clock(started + 5_000);
    let calls = 0;
    const verdict = await verifyLinuxReboot(scope, new Date(started).toISOString(), {
      runOnTarget: async () => {
        calls += 1;
        if (calls < 3) throw new Error("multipass exec: instance is not running");
        return result("4.00 8.00\n");
      },
      runProcess: async () => result(""),
      ...c,
      timeoutMs: 120_000,
      intervalMs: 3_000,
    });
    expect(calls).toBe(3);
    expect(verdict.ok).toBe(true);
  });

  it("rejects a guest that never rebooted because its uptime predates the execution", async () => {
    const started = 3_000_000;
    const c = clock(started + 2_000);
    const verdict = await verifyLinuxReboot(scope, new Date(started).toISOString(), {
      runOnTarget: async () => result("600.00 1200.00\n"),
      runProcess: async () => result(""),
      ...c,
      timeoutMs: 30_000,
      intervalMs: 3_000,
    });
    expect(verdict.ok).toBe(false);
    expect(String(verdict.error)).toContain("has not rebooted");
  });

  it("rejects an invalid execution start time", async () => {
    const verdict = await verifyLinuxReboot(scope, "not-a-date");
    expect(verdict.ok).toBe(false);
  });

  it("accepts a Multipass instance once it reports Stopped", async () => {
    const states = ["Running", "Running", "Stopped"];
    const c = clock(0);
    const verdict = await verifyMultipassStopped(scope, {
      runOnTarget: async () => result(""),
      runProcess: async () =>
        result(
          JSON.stringify({
            info: { [scope.target_id]: { state: states.shift() ?? "Stopped" } },
          })
        ),
      ...c,
      timeoutMs: 60_000,
      intervalMs: 3_000,
    });
    expect(verdict.ok).toBe(true);
    expect(verdict.state).toBe("Stopped");
  });

  it("rejects a Multipass instance that stays Running until the deadline", async () => {
    const c = clock(0);
    const verdict = await verifyMultipassStopped(scope, {
      runOnTarget: async () => result(""),
      runProcess: async () =>
        result(JSON.stringify({ info: { [scope.target_id]: { state: "Running" } } })),
      ...c,
      timeoutMs: 9_000,
      intervalMs: 3_000,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.state).toBe("Running");
  });

  it("routes target_rebooted and target_stopped criteria through the lifecycle checks", async () => {
    const stoppedTest: AtomicPlan["tests"][number] = {
      ...test("unused"),
      success_criteria: [{ kind: "target_rebooted" }],
    };
    const missingStart = await validateBehaviorSuccess(scope, stoppedTest, "", "");
    expect(missingStart.ok).toBe(false);
    const wrongPlatform = await validateBehaviorSuccess(
      { ...scope, target_kind: "docker" },
      stoppedTest,
      "",
      "",
      new Date().toISOString()
    );
    expect(wrongPlatform.ok).toBe(false);
  });
});
