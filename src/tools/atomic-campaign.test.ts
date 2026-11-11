/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  canReuseTerminalCampaignResult,
  createAtomicCampaignStore,
} from "./atomic-campaign.js";
import type { AtomicPlan, LoadedRun } from "./atomic-run-state.js";

describe("Linux Atomic campaigns", () => {
  const directories: string[] = [];

  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("reuses only behavior-valid, covered, clean terminal campaign results", () => {
    const reusable = {
      state: { phase: "completed_with_findings", residual_count: 0 },
      plan: { tests: [{ test_guid: "11111111-1111-4111-8111-111111111111" }] },
      resources: [{ id: "target", kind: "target", origin: "existing", cleaned: true }],
      executions: [{
        test_guid: "11111111-1111-4111-8111-111111111111",
        stage: "execute",
        status: "passed",
        behavior_success: true,
      }],
      coverage: [{
        test_guid: "11111111-1111-4111-8111-111111111111",
        outcome: "missed",
      }],
    } as unknown as LoadedRun;
    expect(canReuseTerminalCampaignResult(reusable)).toBe(true);
    expect(
      canReuseTerminalCampaignResult({
        ...reusable,
        coverage: [{
          test_guid: "11111111-1111-4111-8111-111111111111",
          outcome: "not_applicable",
        }],
      } as unknown as LoadedRun)
    ).toBe(false);
    expect(
      canReuseTerminalCampaignResult({
        ...reusable,
        resources: [{ id: "target", kind: "target", origin: "existing", cleaned: false }],
      } as unknown as LoadedRun)
    ).toBe(false);
  });

  it("pins every catalog test and routes compatible approval batches", () => {
    const root = mkdtempSync(path.join(tmpdir(), "atomic-campaign-catalog-"));
    const campaigns = mkdtempSync(path.join(tmpdir(), "atomic-campaign-state-"));
    directories.push(root, campaigns);
    mkdirSync(path.join(root, "T1057"), { recursive: true });
    mkdirSync(path.join(root, "T1176"), { recursive: true });
    writeFileSync(
      path.join(root, "T1057", "T1057.yaml"),
      `attack_technique: T1057
display_name: Process Discovery
atomic_tests:
  - name: Process Discovery
    auto_generated_guid: 11111111-1111-4111-8111-111111111111
    description: List processes
    supported_platforms: [linux]
    executor:
      name: sh
      elevation_required: false
      command: ps aux
  - name: Identity Discovery
    auto_generated_guid: 22222222-2222-4222-8222-222222222222
    description: Show the current identity
    supported_platforms: [linux]
    executor:
      name: sh
      elevation_required: false
      command: id
  - name: Stateful file creation
    auto_generated_guid: 33333333-3333-4333-8333-333333333333
    description: Create a persistent marker
    supported_platforms: [linux]
    executor:
      name: sh
      elevation_required: false
      command: touch /tmp/atomic-campaign-stateful
`,
      "utf8"
    );
    writeFileSync(
      path.join(root, "T1176", "T1176.yaml"),
      `attack_technique: T1176
display_name: Software Extensions
atomic_tests:
  - name: Firefox
    auto_generated_guid: cb790029-17e6-4c43-b96f-002ce5f10938
    description: Load a temporary extension
    supported_platforms: [linux]
    executor:
      name: manual
      steps: Open Firefox and load manifest.json
`,
      "utf8"
    );
    execFileSync("git", ["init", "-q", root]);
    execFileSync("git", ["-C", root, "add", "."]);
    execFileSync("git", [
      "-C", root,
      "-c", "user.name=Atomic Test",
      "-c", "user.email=atomic@example.invalid",
      "commit", "-qm", "catalog",
    ]);

    const store = createAtomicCampaignStore({ baseDir: campaigns });
    const created = store.create({
      name: "All Linux",
      campaign_id: "all-linux-a1b2c3",
      atomics_path: root,
    });
    expect(created).toMatchObject({
      phase: "awaiting_approval",
      total: 4,
      stop: true,
      by_route: { server_runner: 3, desktop_operator: 1 },
      by_approval_lane: { standard: 3, operator: 1 },
      by_vm_isolation: { shared_vm: 2, exclusive_vm: 2 },
    });
    const digest = String((created as Record<string, unknown>).plan_digest);
    expect(() => store.approve("all-linux-a1b2c3", "a".repeat(64))).toThrow(/digest/);
    expect(store.approve("all-linux-a1b2c3", digest)).toMatchObject({ phase: "active" });
    const campaign = store.load("all-linux-a1b2c3");
    const seedPlan = {
      source: {
        revision: campaign.source.revision,
        catalog_digest: campaign.source.catalog_digest,
      },
      runner: {
        repository: "https://github.com/redcanaryco/invoke-atomicredteam.git",
        revision: "a".repeat(40),
      },
      instrumentation: {
        elastic_agent: {
          stack_version: "9.7.0",
          version: "9.5.6",
          kibana_url: "https://kibana.example",
          fleet_url: "https://fleet.example",
          fleet_server_host_id: "fleet",
          agent_policy_id: "policy",
          agent_policy_name: "Policy",
          agent_policy_revision: 1,
          elastic_defend_package_policy_id: "defend",
          elastic_defend_package_version: "9.6.1",
          elasticsearch_output_id: "output",
          elasticsearch_url: "https://elasticsearch.example",
        },
      },
    } as unknown as AtomicPlan;
    const prepared = store.prepareBatchApproval("all-linux-a1b2c3", seedPlan);
    expect(prepared).toMatchObject({
      stop: true,
      batch_approval: { status: "awaiting_approval", test_count: 4 },
    });
    const batchDigest = String(
      (prepared.batch_approval as Record<string, unknown>).digest
    );
    expect(() => store.approveBatch("all-linux-a1b2c3", "b".repeat(64))).toThrow(
      /batch_digest/
    );
    expect(store.approveBatch("all-linux-a1b2c3", batchDigest)).toMatchObject({
      batch_approval: { status: "approved", test_count: 4 },
    });
    expect(store.next("all-linux-a1b2c3", 10)).toMatchObject({
      route: "server_runner",
      approval_lane: "standard",
      vm_isolation: "shared_vm",
      tests: [
        { test_guid: "11111111-1111-4111-8111-111111111111" },
        { test_guid: "22222222-2222-4222-8222-222222222222" },
      ],
    });
    const entries = store.list("all-linux-a1b2c3", 0, 20).entries;
    const stateful = entries.find(
      (entry) => entry.test_guid === "33333333-3333-4333-8333-333333333333"
    );
    expect(stateful).toMatchObject({
      vm_isolation: "exclusive_vm",
      isolation_reasons: ["risk:state_change", "unproven_shared_target_safety"],
    });
    expect(store.next("all-linux-a1b2c3", 10, stateful?.batch_key)).toMatchObject({
      vm_isolation: "exclusive_vm",
      tests: [{ test_guid: "33333333-3333-4333-8333-333333333333" }],
    });

    const published = store.load("all-linux-a1b2c3");
    store.save({
      ...published,
      entries: published.entries.map((entry) =>
        entry.test_guid === "11111111-1111-4111-8111-111111111111"
          ? {
              ...entry,
              status: "completed_with_findings" as const,
              run_id: "retry-run-a1b2c3",
              run_phase: "completed_with_findings",
              coverage_outcome: "not_applicable",
              result_published: true,
              result_document_id: "result-a1b2c3",
              result_schema_version: 2,
            }
          : entry
      ),
    });
    const loaded = {
      dir: "/tmp/retry-run-a1b2c3",
      state: {
        schema_version: 1,
        run_id: "retry-run-a1b2c3",
        name: "retry",
        phase: "completed_with_findings",
        created_at: new Date().toISOString(),
        coverage_outcome: "not_applicable",
        residual_count: 0,
      },
      plan: {
        source: {
          revision: published.source.revision,
          catalog_digest: published.source.catalog_digest,
        },
        tests: [{ test_guid: "11111111-1111-4111-8111-111111111111" }],
      },
      resources: [{ id: "target", kind: "target", origin: "provisioned", cleaned: true }],
      executions: [],
      coverage: [],
    } as unknown as LoadedRun;
    const beforeRequeue = store.load("all-linux-a1b2c3");
    expect(() =>
      store.requeueBatchFinding("all-linux-a1b2c3", {
        ...loaded,
        resources: [{ ...loaded.resources[0]!, cleaned: false }],
      })
    ).toThrow(/zero residuals/);
    expect(store.requeueBatchFinding("all-linux-a1b2c3", loaded)).toMatchObject({
      phase: "active",
      requeued_run_id: "retry-run-a1b2c3",
      requeued_test_guids: ["11111111-1111-4111-8111-111111111111"],
    });
    const afterRequeue = store.load("all-linux-a1b2c3");
    expect(afterRequeue.plan_digest).toBe(beforeRequeue.plan_digest);
    expect(afterRequeue.batch_approval?.digest).toBe(beforeRequeue.batch_approval?.digest);
    expect(
      afterRequeue.entries.find(
        (entry) => entry.test_guid === "11111111-1111-4111-8111-111111111111"
      )
    ).toMatchObject({ status: "pending" });

    const blockedState = store.load("all-linux-a1b2c3");
    store.save({
      ...blockedState,
      entries: blockedState.entries.map((entry) =>
        entry.test_guid === "11111111-1111-4111-8111-111111111111"
          ? {
              ...entry,
              status: "blocked" as const,
              run_id: "blocked-run-a1b2c3",
            }
          : entry
      ),
    });
    const blocked = {
      ...loaded,
      state: {
        ...loaded.state,
        run_id: "blocked-run-a1b2c3",
        phase: "blocked",
        coverage_outcome: "pending",
        residual_count: undefined,
      },
      executions: [],
      coverage: [],
    } as unknown as LoadedRun;
    expect(store.requeueBatchFinding("all-linux-a1b2c3", blocked)).toMatchObject({
      requeued_run_id: "blocked-run-a1b2c3",
      requeued_test_guids: ["11111111-1111-4111-8111-111111111111"],
    });
    expect(
      store
        .load("all-linux-a1b2c3")
        .entries.find(
          (entry) => entry.test_guid === "11111111-1111-4111-8111-111111111111"
        )
    ).toMatchObject({ status: "pending" });

    const compatibilityState = store.load("all-linux-a1b2c3");
    store.save({
      ...compatibilityState,
      entries: compatibilityState.entries.map((entry) =>
        entry.test_guid === "11111111-1111-4111-8111-111111111111"
          ? {
              ...entry,
              status: "skipped" as const,
              run_id: "compatibility-run-a1b2c3",
              run_phase: "skipped",
              coverage_outcome: "skipped",
              result_published: false,
            }
          : entry
      ),
    });
    const compatibilityBlocked = {
      ...loaded,
      state: {
        ...loaded.state,
        run_id: "compatibility-run-a1b2c3",
        phase: "blocked",
        coverage_outcome: "not_applicable",
        residual_count: undefined,
      },
      executions: [
        {
          test_guid: "11111111-1111-4111-8111-111111111111",
          stage: "execute",
          status: "failed",
          behavior_success: false,
        },
      ],
      coverage: [
        {
          test_guid: "11111111-1111-4111-8111-111111111111",
          outcome: "not_applicable",
        },
      ],
    } as unknown as LoadedRun;
    expect(
      store.requeueBatchFinding("all-linux-a1b2c3", compatibilityBlocked)
    ).toMatchObject({
      requeued_run_id: "compatibility-run-a1b2c3",
      requeued_test_guids: ["11111111-1111-4111-8111-111111111111"],
    });
    expect(
      store
        .load("all-linux-a1b2c3")
        .entries.find(
          (entry) => entry.test_guid === "11111111-1111-4111-8111-111111111111"
        )
    ).toMatchObject({ status: "pending" });
  });

  it("routes Python 2 tests and skips unsupported FreeBSD-only tests", () => {
    const root = mkdtempSync(path.join(tmpdir(), "atomic-campaign-compat-"));
    const campaigns = mkdtempSync(path.join(tmpdir(), "atomic-campaign-state-"));
    directories.push(root, campaigns);
    mkdirSync(path.join(root, "T1003.007"), { recursive: true });
    writeFileSync(
      path.join(root, "T1003.007", "T1003.007.yaml"),
      `attack_technique: T1003.007
display_name: OS Credential Dumping
atomic_tests:
  - name: Capture Passwords with MimiPenguin
    auto_generated_guid: a27418de-bdce-4ebd-b655-38f04842bf0c
    description: Requires the legacy Python runtime
    supported_platforms: [linux]
    dependencies:
      - description: Python2 must be installed
        prereq_command: command -v python2
        get_prereq_command: apt-get install -y python2
    executor:
      name: bash
      elevation_required: true
      command: python2 /tmp/mimipenguin.py
  - name: Dump individual process memory with sh on FreeBSD (Local)
    auto_generated_guid: fa37b633-e097-4415-b2b8-c5bf4c86e423
    description: On FreeBSD procfs must be mounted.
    supported_platforms: [linux]
    executor:
      name: sh
      elevation_required: true
      command: head /proc/1/map
`,
      "utf8"
    );
    execFileSync("git", ["init", "-q", root]);
    execFileSync("git", ["-C", root, "add", "."]);
    execFileSync("git", [
      "-C", root,
      "-c", "user.name=Atomic Test",
      "-c", "user.email=atomic@example.invalid",
      "commit", "-qm", "catalog",
    ]);

    const store = createAtomicCampaignStore({ baseDir: campaigns });
    const created = store.create({
      name: "Compatibility routes",
      campaign_id: "compat-routes-a1b2c3",
      atomics_path: root,
    });
    expect(created).toMatchObject({
      total: 2,
      by_status: { pending: 1, skipped: 1 },
    });
    const digest = String((created as Record<string, unknown>).plan_digest);
    store.approve("compat-routes-a1b2c3", digest);
    const entries = store.list("compat-routes-a1b2c3", 0, 10).entries;
    expect(entries.find((entry) => entry.test_guid.startsWith("a27418de"))).toMatchObject({
      target_platform: "linux",
      preferred_distro: "ubuntu-22.04",
      route: "server_runner",
    });
    const freebsd = entries.find((entry) => entry.test_guid.startsWith("fa37b633"));
    expect(freebsd).toMatchObject({
      target_platform: "freebsd",
      preferred_distro: "freebsd-15.1",
      route: "freebsd_runner",
      disposition: "skip",
      status: "skipped",
      skip_reason:
        "FreeBSD-only Atomic skipped because Elastic Agent and Elastic Defend do not support target-side FreeBSD telemetry",
    });
    expect(store.next("compat-routes-a1b2c3", 10, freebsd?.batch_key)).toMatchObject({
      tests: [],
    });
  });
});
