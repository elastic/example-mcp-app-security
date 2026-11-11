/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AtomicRunError,
  createAtomicRunStore,
  planDigest,
  type AtomicPlan,
} from "./atomic-run-state.js";

const TEST_GUID = "11111111-1111-4111-8111-111111111111";
const COMMIT = "a".repeat(40);
const DIGEST = "b".repeat(64);

function makePlan(runId: string, overrides: Partial<AtomicPlan> = {}): AtomicPlan {
  return {
    schema_version: 3,
    run_id: runId,
    mode: "atomic",
    type: "atomic",
    source: {
      kind: "atomic-red-team",
      reference: "T1057 Linux process discovery",
      repository: "https://github.com/redcanaryco/atomic-red-team.git",
      revision: COMMIT,
      catalog_digest: DIGEST,
    },
    runner: {
      repository: "https://github.com/redcanaryco/invoke-atomicredteam.git",
      revision: COMMIT,
    },
    objective: "Verify process discovery telemetry and detection on Linux",
    scope: {
      target_kind: "multipass",
      target_id: "art-test-vm",
      target_profile: "server",
      execution_user: "ubuntu",
      capabilities: ["shell", "powershell", "systemd", "kernel", "network"],
      platform: "linux",
      distro: "ubuntu-24.04",
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
    },
    tests: [
      {
        technique_id: "T1057",
        test_guid: TEST_GUID,
        name: "Process Discovery",
        executor: "sh",
        execution_mode: "runner",
        elevation_required: false,
        required_capabilities: ["shell"],
        definition_digest: DIGEST,
        inputs: {},
        expected_outcome: "process listing is produced",
        success_criteria: [{ kind: "stdout_contains", value: "PID" }],
        cleanup_expected: false,
        risk_flags: [],
      },
    ],
    ...overrides,
  };
}

describe("atomic run store", () => {
  const directories: string[] = [];

  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  function store() {
    const baseDir = mkdtempSync(path.join(tmpdir(), "atomic-run-"));
    directories.push(baseDir);
    return createAtomicRunStore({ baseDir });
  }

  function approvedRun() {
    const runs = store();
    const init = runs.init({ name: "process discovery", run_id: "process-discovery-a1b2c3" });
    const plan = makePlan(init.run_id);
    runs.setPlan(init.run_id, plan);
    runs.approve(init.run_id, planDigest(plan));
    return { runs, plan, runId: init.run_id };
  }

  it("stops after set_plan and accepts only the stored digest", () => {
    const runs = store();
    const init = runs.init({ name: "process discovery", run_id: "process-discovery-d4e5f6" });
    const plan = makePlan(init.run_id);
    const waiting = runs.setPlan(init.run_id, plan);
    expect(waiting.phase).toBe("awaiting_approval");
    expect(waiting.stop).toBe(true);
    expect(waiting.allowed_actions).toContain("approve");
    expect(() => runs.approve(init.run_id, "c".repeat(64))).toThrow(/plan_digest/);
    expect(runs.approve(init.run_id, planDigest(plan)).phase).toBe("approved");
  });

  it("fails plan validation closed for unapproved destructive risk", () => {
    const runs = store();
    const init = runs.init({ name: "destructive", run_id: "destructive-a1b2c3" });
    const base = makePlan(init.run_id);
    const plan = makePlan(init.run_id, {
      tests: [{ ...base.tests[0]!, risk_flags: ["destructive"] }],
    });
    expect(() => runs.setPlan(init.run_id, plan)).toThrow(/allow_destructive/);
  });

  it("fails closed when a test needs capabilities absent from the target", () => {
    const runs = store();
    const init = runs.init({ name: "gui", run_id: "gui-missing-a1b2c3" });
    const base = makePlan(init.run_id);
    const plan = makePlan(init.run_id, {
      tests: [
        {
          ...base.tests[0]!,
          required_capabilities: ["gui", "browser", "interactive"],
        },
      ],
    });
    expect(() => runs.setPlan(init.run_id, plan)).toThrow(/missing target capabilities/);
  });

  it("accepts a manual GUI procedure on an approved interactive desktop target", () => {
    const runs = store();
    const init = runs.init({ name: "firefox", run_id: "firefox-manual-a1b2c3" });
    const base = makePlan(init.run_id);
    const plan = makePlan(init.run_id, {
      scope: {
        ...base.scope,
        target_kind: "ssh",
        target_id: "firefox-lab",
        target_profile: "desktop",
        lifecycle: "existing",
        capabilities: [
          "shell",
          "powershell",
          "systemd",
          "kernel",
          "network",
          "gui",
          "browser",
          "interactive",
        ],
      },
      tests: [
        {
          ...base.tests[0]!,
          technique_id: "T1176",
          test_guid: "cb790029-17e6-4c43-b96f-002ce5f10938",
          name: "Firefox",
          executor: "manual",
          execution_mode: "operator",
          required_capabilities: ["gui", "browser", "interactive"],
          success_criteria: [
            {
              kind: "manual_evidence",
              description: "Operator confirms the extension is loaded",
            },
          ],
          manual: {
            reviewed_steps: ["Load the approved temporary add-on in about:debugging"],
            evidence_requirements: ["Confirm it appears under Temporary Extensions"],
            cleanup_steps: ["Remove the temporary extension"],
          },
          risk_flags: ["gui"],
        },
      ],
    });
    expect(runs.setPlan(init.run_id, plan).phase).toBe("awaiting_approval");
  });

  it("accepts a fresh Multipass desktop with digest-bound source assets", () => {
    const runs = store();
    const init = runs.init({ name: "firefox", run_id: "firefox-fresh-a1b2c3" });
    const base = makePlan(init.run_id);
    const plan = makePlan(init.run_id, {
      scope: {
        ...base.scope,
        target_profile: "desktop",
        capabilities: ["shell", "systemd", "network", "gui", "browser", "interactive"],
      },
      tests: [
        {
          ...base.tests[0]!,
          technique_id: "T1176",
          test_guid: "cb790029-17e6-4c43-b96f-002ce5f10938",
          name: "Firefox",
          executor: "manual",
          execution_mode: "operator",
          required_capabilities: ["gui", "browser", "interactive"],
          success_criteria: [
            { kind: "manual_evidence", description: "Temporary extension is visible" },
          ],
          manual: {
            reviewed_steps: [
              "From Home, load AtomicRedTeamAssets/firefox-fresh-a1b2c3/T1176/src/manifest.json",
            ],
            evidence_requirements: ["Confirm the Temporary Extensions entry"],
            cleanup_steps: ["Remove the extension and close Firefox"],
          },
          source_assets: [
            {
              path: "T1176/src/manifest.json",
              sha256: "c".repeat(64),
              size: 321,
            },
          ],
          risk_flags: ["gui"],
        },
      ],
    });
    expect(runs.setPlan(init.run_id, plan).phase).toBe("awaiting_approval");
  });

  it("requires a verified target before execution", () => {
    const { runs, runId } = approvedRun();
    expect(runs.advance(runId).phase).toBe("provisioning");
    expect(() => runs.advance(runId)).toThrow(/verified target/);
    runs.recordResource(runId, {
      id: "art-test-vm",
      kind: "target",
      origin: "provisioned",
      cleaned: false,
    });
    expect(runs.advance(runId).phase).toBe("executing");
  });

  it("does not leave execution until every approved GUID is accounted for", () => {
    const { runs, runId } = approvedRun();
    runs.advance(runId);
    runs.recordResource(runId, {
      id: "art-test-vm",
      kind: "target",
      origin: "provisioned",
      cleaned: false,
    });
    runs.advance(runId);
    expect(() => runs.advance(runId)).toThrow(/not accounted/);
    runs.recordExecution(runId, {
      test_guid: TEST_GUID,
      stage: "execute",
      status: "passed",
      behavior_success: true,
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
    });
    expect(runs.advance(runId).phase).toBe("verifying");
  });

  it("allows late prerequisite accounting only before behavior execution", () => {
    const { runs, runId } = approvedRun();
    runs.advance(runId);
    runs.recordResource(runId, {
      id: "art-test-vm",
      kind: "target",
      origin: "provisioned",
      cleaned: false,
    });
    runs.advance(runId);
    runs.recordExecution(runId, {
      test_guid: TEST_GUID,
      stage: "prereq",
      status: "passed",
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
    });
    runs.recordExecution(runId, {
      test_guid: TEST_GUID,
      stage: "execute",
      status: "passed",
      behavior_success: true,
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
    });
    expect(() =>
      runs.recordExecution(runId, {
        test_guid: TEST_GUID,
        stage: "prereq",
        status: "passed",
        started_at: new Date().toISOString(),
        ended_at: new Date().toISOString(),
      })
    ).toThrow(/after behavior execution/);
  });

  it("keeps cleanup success independent of a detection gap", () => {
    const { runs, runId } = approvedRun();
    runs.advance(runId);
    runs.recordResource(runId, {
      id: "art-test-vm",
      kind: "target",
      origin: "provisioned",
      cleaned: false,
    });
    runs.advance(runId);
    runs.recordExecution(runId, {
      test_guid: TEST_GUID,
      stage: "execute",
      status: "passed",
      behavior_success: true,
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
    });
    runs.advance(runId);
    runs.advance(runId);
    runs.recordCoverage(runId, { test_guid: TEST_GUID, outcome: "missed" });
    runs.setCoverageOutcome(runId, "gaps");
    runs.advance(runId);
    runs.advance(runId);
    runs.recordResource(runId, {
      id: "art-test-vm",
      kind: "target",
      origin: "provisioned",
      cleaned: true,
    });
    const done = runs.finalize(runId, { residual_count: 0 });
    expect(done.phase).toBe("completed_with_findings");
  });

  it("returns the current snapshot on illegal transitions", () => {
    const runs = store();
    const init = runs.init({ name: "illegal", run_id: "illegal-run-a1b2c3" });
    try {
      runs.recordExecution(init.run_id, {
        test_guid: TEST_GUID,
        stage: "execute",
        status: "passed",
        behavior_success: true,
        started_at: new Date().toISOString(),
        ended_at: new Date().toISOString(),
      });
      throw new Error("expected rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(AtomicRunError);
      expect((error as AtomicRunError).snapshot.phase).toBe("planning");
      expect((error as AtomicRunError).snapshot.ok).toBe(false);
    }
  });

  it("requires behavior success before applicable coverage can be recorded", () => {
    const { runs, runId } = approvedRun();
    runs.advance(runId);
    runs.recordResource(runId, {
      id: "art-test-vm",
      kind: "target",
      origin: "provisioned",
      cleaned: false,
    });
    runs.advance(runId);
    runs.recordExecution(runId, {
      test_guid: TEST_GUID,
      stage: "execute",
      status: "failed",
      behavior_success: false,
      started_at: new Date().toISOString(),
      ended_at: new Date().toISOString(),
    });
    runs.advance(runId);
    runs.advance(runId);
    runs.setCoverageOutcome(runId, "mixed");
    expect(() =>
      runs.recordCoverage(runId, { test_guid: TEST_GUID, outcome: "detected" })
    ).toThrow(/must be not_applicable/);
    runs.recordCoverage(runId, {
      test_guid: TEST_GUID,
      outcome: "not_applicable",
      reason: "The approved behavior assertion failed",
    });
    expect(() => runs.advance(runId)).toThrow(/must be not_applicable/);
    expect(() => runs.setCoverageOutcome(runId, "mixed")).toThrow(/must be not_applicable/);
    expect(runs.setCoverageOutcome(runId, "not_applicable").coverage_outcome).toBe(
      "not_applicable"
    );
  });

  it("rejects passed execution records without confirmed behavior", () => {
    const { runs, runId } = approvedRun();
    runs.advance(runId);
    runs.recordResource(runId, {
      id: "art-test-vm",
      kind: "target",
      origin: "provisioned",
      cleaned: false,
    });
    runs.advance(runId);
    expect(() =>
      runs.recordExecution(runId, {
        test_guid: TEST_GUID,
        stage: "execute",
        status: "passed",
        started_at: new Date().toISOString(),
        ended_at: new Date().toISOString(),
      })
    ).toThrow(/behavior_success=true/);
  });
});
