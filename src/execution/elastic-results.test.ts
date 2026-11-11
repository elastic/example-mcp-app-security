/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AtomicPlan, LoadedRun } from "../tools/atomic-run-state.js";
import {
  buildAtomicResultDocuments,
  buildAtomicSkippedResultDocuments,
  publishAtomicRunResults,
} from "./elastic-results.js";

const TEST_GUID = "11111111-1111-4111-8111-111111111111";

function loadedRun(dir: string): LoadedRun {
  const plan: AtomicPlan = {
    schema_version: 3,
    run_id: "atomic-result-a1b2c3",
    mode: "coverage",
    type: "atomic",
    source: {
      kind: "gap",
      reference: "T1057",
      repository: "https://github.com/redcanaryco/atomic-red-team.git",
      revision: "a".repeat(40),
      catalog_digest: "b".repeat(64),
    },
    runner: {
      repository: "https://github.com/redcanaryco/invoke-atomicredteam.git",
      revision: "c".repeat(40),
    },
    objective: "Publish one completed Linux Atomic result",
    scope: {
      target_kind: "multipass",
      target_id: "atomic-result-vm",
      target_profile: "server",
      execution_user: "ubuntu",
      capabilities: ["shell"],
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
    instrumentation: {
      elastic_agent: {
        stack_version: "9.7.0",
        version: "9.5.6",
        kibana_url: "https://kibana.example",
        fleet_url: "https://fleet.example:8220",
        fleet_server_host_id: "fleet-host",
        agent_policy_id: "policy",
        agent_policy_name: "Linux Defend",
        agent_policy_revision: 1,
        elastic_defend_package_policy_id: "endpoint-policy",
        elastic_defend_package_version: "9.5.0",
        elasticsearch_output_id: "output",
        elasticsearch_url: "https://elasticsearch.example:9200",
        insecure: false,
        health_timeout_seconds: 300,
      },
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
        definition_digest: "d".repeat(64),
        inputs: {},
        expected_outcome: "Process listing is observed",
        success_criteria: [{ kind: "stdout_contains", value: "PID" }],
        cleanup_expected: false,
        risk_flags: [],
      },
    ],
  };
  return {
    dir,
    state: {
      schema_version: 1,
      run_id: plan.run_id,
      name: "Atomic result",
      phase: "completed_with_findings",
      created_at: "2026-11-05T08:00:00.000Z",
      approved_at: "2026-11-05T08:01:00.000Z",
      plan_digest: "e".repeat(64),
      coverage_outcome: "gaps",
      residual_count: 0,
    },
    plan,
    resources: [],
    executions: [
      {
        test_guid: TEST_GUID,
        stage: "execute",
        status: "passed",
        behavior_success: true,
        started_at: "2026-11-05T08:02:00.000Z",
        ended_at: "2026-11-05T08:02:01.000Z",
        exit_code: 0,
      },
    ],
    coverage: [
      {
        test_guid: TEST_GUID,
        outcome: "missed",
        raw_event_count: 12,
        alert_count: 0,
        detector: "elastic",
        reason: "Raw telemetry exists without an alert",
      },
    ],
  };
}

describe("Elastic Atomic result publishing", () => {
  const directories: string[] = [];
  const previousKibana = process.env.KIBANA_URL;
  const previousKey = process.env.ELASTIC_API_KEY;
  const previousIndex = process.env.ATOMIC_RESULTS_INDEX;

  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
    restoreEnvironment("KIBANA_URL", previousKibana);
    restoreEnvironment("ELASTIC_API_KEY", previousKey);
    restoreEnvironment("ATOMIC_RESULTS_INDEX", previousIndex);
  });

  it("builds one stable normalized document per GUID", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "atomic-result-"));
    directories.push(dir);
    const [result] = buildAtomicResultDocuments(loadedRun(dir), "linux-all-a1b2c3");
    expect(result?.id).toMatch(/^[0-9a-f]{64}$/);
    expect(result?.document).toMatchObject({
      event: { action: "atomic-linux-emulation-result", outcome: "success" },
      atomic: {
        campaign: { id: "linux-all-a1b2c3" },
        coverage: { outcome: "missed", raw_event_count: 12, alert_count: 0 },
        links: {
          logs: { url: "https://kibana.example/app/discover" },
          alerts: { url: "https://kibana.example/app/security/alerts" },
        },
        test: { guid: TEST_GUID, technique_id: "T1057" },
      },
    });
  });

  it("builds an auditable FreeBSD skip with unavailable telemetry links", () => {
    const [result] = buildAtomicSkippedResultDocuments({
      campaignId: "linux-all-a1b2c3",
      campaignName: "All Linux",
      campaignPlanDigest: "a".repeat(64),
      campaignCreatedAt: "2026-11-05T07:59:00.000Z",
      campaignApprovedAt: "2026-11-05T07:59:30.000Z",
      timestamp: "2026-11-05T08:00:00.000Z",
      kibanaUrl: "https://kibana.example",
      source: {
        repository: "https://github.com/redcanaryco/atomic-red-team.git",
        revision: "b".repeat(40),
        catalog_digest: "c".repeat(64),
      },
      tests: [{
        technique_id: "T1003.007",
        test_guid: "fa37b633-e097-4415-b2b8-c5bf4c86e423",
        name: "Dump individual process memory with sh on FreeBSD (Local)",
        executor: "sh",
        execution_mode: "runner",
        elevation_required: true,
        cleanup_expected: false,
        risk_flags: [],
        definition_digest: "d".repeat(64),
        reason: "FreeBSD target telemetry is unsupported",
        target_platform: "freebsd",
        preferred_distro: "freebsd-15.1",
        target_profile: "server",
      }],
    });
    expect(result?.document).toMatchObject({
      event: { outcome: "unknown", reason: "FreeBSD target telemetry is unsupported" },
      host: { name: "not-provisioned", os: { type: "freebsd" } },
      user: { name: "not-applicable" },
      atomic: {
        run: {
          phase: "skipped",
          coverage_outcome: "skipped",
          residual_count: 0,
        },
        target: { platform: "freebsd", status: "not_provisioned" },
        test: { execution_mode: "runner", cleanup_expected: false },
        execution: {
          stage: "not_started",
          status: "skipped",
          behavior_success: false,
          has_evidence: false,
        },
        coverage: {
          outcome: "skipped",
          raw_event_count: 0,
          alert_count: 0,
          detector: "elastic",
        },
        links: {
          logs: {
            url: "https://kibana.example/app/discover",
            available: false,
          },
          alerts: {
            url: "https://kibana.example/app/security/alerts",
            available: false,
          },
        },
      },
    });
  });

  it("normalizes a clean unsupported blocked run into an auditable skip", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "atomic-result-"));
    directories.push(dir);
    const loaded = loadedRun(dir);
    const unsupported: LoadedRun = {
      ...loaded,
      state: {
        ...loaded.state,
        phase: "blocked",
        coverage_outcome: "pending",
        residual_count: undefined,
        blocked_reason: "No compatible external target exists",
      },
      executions: [],
      coverage: [{
        test_guid: TEST_GUID,
        outcome: "not_applicable",
        raw_event_count: 0,
        alert_count: 0,
        detector: "elastic",
        reason: "No compatible external target exists",
      }],
    };
    const [result] = buildAtomicResultDocuments(unsupported, "linux-all-a1b2c3");
    expect(result?.document).toMatchObject({
      event: { outcome: "unknown", reason: "No compatible external target exists" },
      host: { name: "atomic-result-vm", os: { type: "linux" } },
      atomic: {
        run: {
          phase: "skipped",
          original_phase: "blocked",
          coverage_outcome: "skipped",
          residual_count: 0,
        },
        target: { status: "not_provisioned" },
        execution: { stage: "not_started", status: "skipped" },
        coverage: { outcome: "skipped", raw_event_count: 0, alert_count: 0 },
        links: {
          logs: { available: false, reason: "No compatible external target exists" },
          alerts: { available: false, reason: "No compatible external target exists" },
        },
      },
    });
  });

  it("writes a durable outbox and updates the campaign GUID result on retry", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "atomic-result-"));
    directories.push(dir);
    process.env.KIBANA_URL = "https://kibana.example";
    process.env.ELASTIC_API_KEY = "secret-api-key";
    process.env.ATOMIC_RESULTS_INDEX = "logs-atomic.results-test";
    let requestBody = "";
    const skipped = buildAtomicSkippedResultDocuments({
      campaignId: "linux-all-a1b2c3",
      campaignName: "All Linux",
      campaignPlanDigest: "a".repeat(64),
      campaignCreatedAt: "2026-11-05T07:59:00.000Z",
      campaignApprovedAt: "2026-11-05T07:59:30.000Z",
      timestamp: "2026-11-05T08:00:00.000Z",
      kibanaUrl: "https://kibana.example",
      source: {
        repository: "https://github.com/redcanaryco/atomic-red-team.git",
        revision: "b".repeat(40),
        catalog_digest: "c".repeat(64),
      },
      tests: [{
        technique_id: "T1003.007",
        test_guid: "fa37b633-e097-4415-b2b8-c5bf4c86e423",
        name: "FreeBSD-only test",
        executor: "sh",
        execution_mode: "runner",
        elevation_required: true,
        cleanup_expected: false,
        risk_flags: [],
        definition_digest: "d".repeat(64),
        reason: "FreeBSD target telemetry is unsupported",
        target_platform: "freebsd",
        preferred_distro: "freebsd-15.1",
        target_profile: "server",
      }],
    });
    const result = await publishAtomicRunResults(loadedRun(dir), {
      campaignId: "linux-all-a1b2c3",
      additionalDocuments: skipped,
      fetchImpl: async (_input, init) => {
        requestBody = String(init?.body ?? "");
        return new Response(
          JSON.stringify({
            errors: false,
            items: [{ index: { status: 200 } }, { index: { status: 201 } }],
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    });
    expect(result.ok).toBe(true);
    expect(result.documents[0]?.result).toBe("updated");
    expect(result.documents[1]).toMatchObject({
      test_guid: "fa37b633-e097-4415-b2b8-c5bf4c86e423",
      result: "created",
    });
    expect(requestBody).toContain('"_index":"logs-atomic.results-test"');
    expect(readFileSync(result.outbox_path, "utf8")).toBe(requestBody);
  });
});

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}
