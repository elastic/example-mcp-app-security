/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it, vi } from "vitest";
import type { AtomicPlan } from "./atomic-run-state.js";
import {
  parseMacosBootEpochSeconds,
  parseTartRunning,
  verifyMacosReboot,
  verifyTartStopped,
} from "./atomic-exec.js";

const scope = {
  target_kind: "tart",
  target_id: "art-macos",
  target_profile: "server",
  execution_user: "admin",
  capabilities: ["shell", "powershell"],
  platform: "macos",
  distro: "macos-15",
  architecture: "arm64",
  target_image: `ghcr.io/example/macos@sha256:${"a".repeat(64)}`,
  ssh_identity_file: "/tmp/id_ed25519",
  classification: "owned-disposable-lab",
  lifecycle: "ephemeral",
  network: "egress-only",
} satisfies AtomicPlan["scope"];

describe("macOS lifecycle verification", () => {
  it("parses kernel boot time and Tart running state", () => {
    expect(parseMacosBootEpochSeconds("{ sec = 1790000000, usec = 0 }"))
      .toBe(1790000000);
    expect(parseTartRunning('[{"Name":"art-macos","Running":false}]', "art-macos"))
      .toBe(false);
    expect(parseTartRunning('[{"Name":"art-macos","State":"running"}]', "art-macos"))
      .toBe(true);
  });

  it("confirms a reboot from kern.boottime after transient transport failure", async () => {
    const started = Date.parse("2026-11-11T10:00:00.000Z");
    const runOnTarget = vi.fn()
      .mockRejectedValueOnce(new Error("connection reset"))
      .mockResolvedValueOnce({
        exitCode: 0,
        timedOut: false,
        stdout: `{ sec = ${started / 1000 + 1}, usec = 0 }`,
        stderr: "",
      });
    let now = started + 10_000;
    const result = await verifyMacosReboot(scope, new Date(started).toISOString(), {
      runOnTarget,
      runProcess: vi.fn(),
      now: () => now,
      sleep: async () => { now += 1_000; },
      timeoutMs: 30_000,
      intervalMs: 1_000,
    });
    expect(result.ok).toBe(true);
    expect(runOnTarget).toHaveBeenCalledTimes(2);
  });

  it("confirms Tart reached the stopped state", async () => {
    let now = 0;
    const runProcess = vi.fn().mockResolvedValue({
      exitCode: 0,
      timedOut: false,
      stdout: '[{"Name":"art-macos","Running":false}]',
      stderr: "",
    });
    const result = await verifyTartStopped(scope, {
      runOnTarget: vi.fn(),
      runProcess,
      now: () => now,
      sleep: async () => { now += 1; },
      timeoutMs: 10,
      intervalMs: 1,
    });
    expect(result).toMatchObject({ ok: true, running: false });
  });
});
