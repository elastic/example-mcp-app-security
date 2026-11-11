/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AtomicRunError, createAtomicRunStore, type AtomicPlan } from "./atomic-run-state.js";
import { atomicPlanSchema } from "./atomic-schemas.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function plan(runId: string): AtomicPlan {
  return {
    schema_version: 3,
    run_id: runId,
    mode: "atomic",
    type: "atomic",
    source: {
      kind: "atomic-red-team",
      reference: "T1000",
      repository: "https://github.com/redcanaryco/atomic-red-team.git",
      revision: "a".repeat(40),
      catalog_digest: "b".repeat(64),
    },
    runner: {
      repository: "https://github.com/redcanaryco/invoke-atomicredteam.git",
      revision: "c".repeat(40),
    },
    objective: "Execute one benign macOS Atomic test",
    scope: {
      target_kind: "tart",
      target_id: "art-macos",
      target_profile: "server",
      execution_user: "admin",
      capabilities: ["shell", "powershell"],
      platform: "macos",
      distro: "macos-15",
      architecture: "arm64",
      target_image: `ghcr.io/example/macos@sha256:${"d".repeat(64)}`,
      ssh_identity_file: "/tmp/id_ed25519",
      classification: "owned-disposable-lab",
      lifecycle: "ephemeral",
      network: "egress-only",
    },
    controls: {
      ttl_minutes: 120,
      allow_reboot: false,
      allow_external_targets: false,
      allow_destructive: false,
      snapshot_before: false,
      allow_setup_commands: false,
      allow_tcc_changes: false,
      allow_sip_changes: false,
    },
    tests: [{
      technique_id: "T1000",
      test_guid: "11111111-1111-4111-8111-111111111111",
      name: "Benign macOS test",
      executor: "sh",
      execution_mode: "runner",
      elevation_required: false,
      required_capabilities: ["shell"],
      definition_digest: "e".repeat(64),
      inputs: {},
      expected_outcome: "The command exits successfully",
      success_criteria: [{ kind: "stdout_contains", value: "ok" }],
      cleanup_expected: false,
      risk_flags: [],
    }],
  };
}

describe("digest-gated macOS run state", () => {
  it("validates and approves an immutable Tart plan", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "macos-atomic-run-"));
    roots.push(root);
    const store = createAtomicRunStore({ baseDir: root });
    store.init({ name: "macOS test", run_id: "macos-test" });
    const prepared = store.setPlan("macos-test", atomicPlanSchema.parse(plan("macos-test")));
    expect(prepared.phase).toBe("awaiting_approval");
    const approved = store.approve("macos-test", prepared.plan_digest!);
    expect(approved.phase).toBe("approved");
  });

  it("rejects TCC-changing behavior without explicit authority", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "macos-atomic-run-"));
    roots.push(root);
    const store = createAtomicRunStore({ baseDir: root });
    store.init({ name: "TCC test", run_id: "tcc-test" });
    const value = plan("tcc-test");
    const unsafe: AtomicPlan = {
      ...value,
      tests: [{ ...value.tests[0]!, risk_flags: ["tcc"] }],
    };
    expect(() => store.setPlan("tcc-test", unsafe)).toThrow(AtomicRunError);
  });

  it("requires an immutable Tart image digest", () => {
    const value = plan("image-test");
    const missing: AtomicPlan = { ...value, scope: { ...value.scope, target_image: undefined } };
    expect(atomicPlanSchema.safeParse(missing).success).toBe(false);
  });

  it("allows a blocked run to mark an existing orphaned resource as cleaned", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "macos-atomic-run-"));
    roots.push(root);
    const store = createAtomicRunStore({ baseDir: root });
    store.init({ name: "Blocked cleanup", run_id: "blocked-cleanup" });
    const prepared = store.setPlan("blocked-cleanup", plan("blocked-cleanup"));
    store.approve("blocked-cleanup", prepared.plan_digest!);
    store.advance("blocked-cleanup");
    store.recordResource("blocked-cleanup", {
      id: "art-macos",
      kind: "target",
      origin: "orphaned",
      cleaned: false,
    });
    store.block("blocked-cleanup", "Provisioning failed");

    const cleaned = store.recordResource("blocked-cleanup", {
      id: "art-macos",
      kind: "target",
      origin: "orphaned",
      cleaned: true,
    });

    expect(cleaned.allowed_actions).toEqual(["status", "record_resource"]);
    expect(store.getLoaded("blocked-cleanup").resources).toEqual([
      {
        id: "art-macos",
        kind: "target",
        origin: "orphaned",
        cleaned: true,
      },
    ]);
  });
});
