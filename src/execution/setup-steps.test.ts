/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import type { ProcessResult } from "./process.js";
import type { AtomicPlan } from "../tools/atomic-run-state.js";
import { runSetupSteps } from "./setup-steps.js";

const scope: AtomicPlan["scope"] = {
  target_kind: "multipass",
  target_id: "art-lfc-setup",
  target_profile: "server",
  execution_user: "ubuntu",
  capabilities: ["shell"],
  platform: "linux",
  distro: "ubuntu-24.04",
  classification: "owned-disposable-lab",
  lifecycle: "ephemeral",
  network: "egress-only",
};

const ok = (): ProcessResult =>
  ({ stdout: "", stderr: "", exitCode: 0, timedOut: false, truncated: false }) as unknown as ProcessResult;
const fail = (): ProcessResult =>
  ({ stdout: "", stderr: "boom", exitCode: 1, timedOut: false, truncated: false }) as unknown as ProcessResult;

describe("runSetupSteps", () => {
  it("runs steps in order and prefixes sudo correctly", async () => {
    const seen: string[][] = [];
    const result = await runSetupSteps(
      scope,
      [
        { description: "enable linger", command: ["loginctl", "enable-linger", "ubuntu"], elevated: true },
        { description: "whoami as user", command: ["id", "-un"], elevated: false },
      ],
      1_000,
      async (_scope, args) => {
        seen.push([...args]);
        return ok();
      }
    );
    expect(result.ok).toBe(true);
    expect(result.steps).toHaveLength(2);
    expect(seen[0]).toEqual(["sudo", "loginctl", "enable-linger", "ubuntu"]);
    expect(seen[1]).toEqual(["sudo", "-u", "ubuntu", "--", "id", "-un"]);
  });

  it("stops at the first failing step and reports it", async () => {
    let calls = 0;
    const result = await runSetupSteps(
      scope,
      [
        { description: "first", command: ["true"], elevated: true },
        { description: "second fails", command: ["false"], elevated: true },
        { description: "third never runs", command: ["true"], elevated: true },
      ],
      1_000,
      async () => {
        calls += 1;
        return calls === 2 ? fail() : ok();
      }
    );
    expect(result.ok).toBe(false);
    expect(calls).toBe(2);
    expect(result.steps).toHaveLength(2);
    expect(result.steps[1]?.ok).toBe(false);
  });
});
