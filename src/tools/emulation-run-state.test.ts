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
  createEmulationRunStore,
  EmulationRunError,
  planDigest,
  type EmulationPlan,
} from "./emulation-run-state.js";

function makePlan(runId: string, overrides: Partial<EmulationPlan> = {}): EmulationPlan {
  return {
    schema_version: 1,
    run_id: runId,
    mode: "intelligence",
    type: "atomic",
    source: {
      reference: "https://example.invalid/research",
      kind: "published-url",
    },
    objective: "Does CreateAccessKey from a stolen user land in CloudTrail?",
    scope: {
      provider: "aws",
      scope_id: "123456789012",
      region: "us-east-1",
    },
    behaviors: [
      {
        id: "b1",
        api: "iam:CreateAccessKey",
        actor: "stolen IAM user",
        target: "emul-backdoor",
        expected_outcome: "access key created",
      },
    ],
    ...overrides,
  };
}

describe("emulation run store", () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const dir of dirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function store() {
    const baseDir = mkdtempSync(path.join(tmpdir(), "emul-run-"));
    dirs.push(baseDir);
    return createEmulationRunStore({ baseDir });
  }

  it("refuses execute-phase records before approval", () => {
    const runs = store();
    const init = runs.init({ name: "void-blizzard", run_id: "void-blizzard-aaa111" });
    expect(init.phase).toBe("planning");
    expect(init.stop).toBeFalsy();

    expect(() =>
      runs.recordBehavior(init.run_id, {
        id: "b1",
        api: "iam:CreateAccessKey",
        actor: "admin",
        target: "user",
        expected_outcome: "key",
      })
    ).toThrow(EmulationRunError);
  });

  it("stops after set_plan until approve matches the digest", () => {
    const runs = store();
    const { run_id } = runs.init({ name: "void-blizzard", run_id: "void-blizzard-bbb222" });
    const plan = makePlan(run_id);
    const pending = runs.setPlan(run_id, plan);
    expect(pending.phase).toBe("awaiting_approval");
    expect(pending.stop).toBe(true);
    expect(pending.allowed_actions).toContain("approve");

    expect(() => runs.approve(run_id, "deadbeefdeadbeef")).toThrow(/plan_digest/);

    const approved = runs.approve(run_id, planDigest(plan));
    expect(approved.phase).toBe("approved");
    expect(approved.stop).toBeFalsy();
  });

  it("keeps cleanup outcome independent of detection gaps", () => {
    const runs = store();
    const { run_id } = runs.init({ name: "void-blizzard", run_id: "void-blizzard-ccc333" });
    const plan = makePlan(run_id);
    runs.setPlan(run_id, plan);
    runs.approve(run_id, planDigest(plan));
    runs.advance(run_id); // provisioning
    runs.recordResource(run_id, {
      id: "arn:aws:iam::1:user/emul",
      kind: "iam_user",
      origin: "provisioned",
      cleaned: false,
    });
    runs.advance(run_id); // executing
    runs.recordBehavior(run_id, plan.behaviors[0]);
    runs.advance(run_id); // verifying
    runs.advance(run_id); // covering
    runs.setDetectionOutcome(run_id, "gaps");
    runs.advance(run_id); // reporting
    runs.advance(run_id); // cleaning
    runs.recordResource(run_id, {
      id: "arn:aws:iam::1:user/emul",
      kind: "iam_user",
      origin: "provisioned",
      cleaned: true,
    });
    const done = runs.finalize(run_id, { residual_count: 0 });
    expect(done.phase).toBe("completed_with_findings");
  });

  it("rejects intelligence mode without a published URL", () => {
    const runs = store();
    const { run_id } = runs.init({ name: "void-blizzard", run_id: "void-blizzard-eee555" });
    expect(() =>
      runs.setPlan(
        run_id,
        makePlan(run_id, {
          source: { reference: "local notes", kind: "conceptual" },
        })
      )
    ).toThrow(/published-url/);
  });

  it("refuses finalize until coverage is scored", () => {
    const runs = store();
    const { run_id } = runs.init({ name: "void-blizzard", run_id: "void-blizzard-fff666" });
    const plan = makePlan(run_id);
    runs.setPlan(run_id, plan);
    runs.approve(run_id, planDigest(plan));
    for (const _ of ["provisioning", "executing", "verifying", "covering", "reporting", "cleaning"]) {
      runs.advance(run_id);
    }
    expect(() => runs.finalize(run_id, { residual_count: 0 })).toThrow(/set_detection_outcome/);
  });

  it("fails closed when residual_count disagrees with the ledger", () => {
    const runs = store();
    const { run_id } = runs.init({ name: "void-blizzard", run_id: "void-blizzard-ddd444" });
    const plan = makePlan(run_id);
    runs.setPlan(run_id, plan);
    runs.approve(run_id, planDigest(plan));
    runs.advance(run_id); // provisioning
    runs.advance(run_id); // executing
    runs.advance(run_id); // verifying
    runs.advance(run_id); // covering
    runs.setDetectionOutcome(run_id, "verified");
    runs.advance(run_id); // reporting
    runs.advance(run_id); // cleaning
    runs.recordResource(run_id, {
      id: "arn:orphan",
      kind: "iam_user",
      origin: "orphaned",
      cleaned: false,
    });
    expect(() => runs.finalize(run_id, { residual_count: 0 })).toThrow(/ledger/);
  });
});
