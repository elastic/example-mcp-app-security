/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  approvedPackageSchema,
  atomicPlanSchema,
  fixtureSchema,
  sourceAssetSchema,
  successCriterionSchema,
  testPlanSchema,
} from "./atomic-schemas.js";

const scriptFixture = {
  input_name: "script",
  content_base64: "IyEvYmluL3NoCmlkCmhvc3RuYW1lCg==",
  sha256: "657a3c8fb414e1392050bdd0b40d3ba06d7ea3ccbf64fc6e0f1ce5bbf411470e",
  mode: "0755" as const,
  description: "Reviewed benign script that prints identity and hostname",
};

describe("digest-approved fixtures", () => {
  it("accepts a fixture as part of an Atomic test plan", () => {
    const parsed = testPlanSchema.parse({
      technique_id: "T1001.002",
      test_guid: "4ff61684-ad91-405c-9fbc-048354ff1d07",
      name: "Execute Embedded Script in Image via Steganography",
      executor: "sh",
      execution_mode: "runner",
      elevation_required: false,
      required_capabilities: ["shell"],
      definition_digest: "a".repeat(64),
      inputs: {
        script: "/var/tmp/atomic-runs/example/fixtures/script.sh",
      },
      expected_outcome: "Execute the reviewed benign embedded script",
      success_criteria: [{ kind: "stdout_contains", value: "ATOMIC-STEG" }],
      cleanup_expected: true,
      risk_flags: [],
      fixtures: [scriptFixture],
    });

    expect(parsed.fixtures).toEqual([scriptFixture]);
  });

  it("rejects malformed fixture content", () => {
    expect(() =>
      fixtureSchema.parse({
        ...scriptFixture,
        content_base64: "not base64",
      })
    ).toThrow();
  });
});

describe("pinned Atomic support files", () => {
  it("accepts a safe relative source asset and rejects traversal", () => {
    expect(
      sourceAssetSchema.parse({
        path: "T1176/src/manifest.json",
        sha256: "a".repeat(64),
        size: 321,
      })
    ).toMatchObject({ path: "T1176/src/manifest.json", size: 321 });
    expect(() =>
      sourceAssetSchema.parse({
        path: "T1176/../T1176/src/manifest.json",
        sha256: "a".repeat(64),
        size: 321,
      })
    ).toThrow();
    expect(() =>
      sourceAssetSchema.parse({
        path: "T1176//src/manifest.json",
        sha256: "a".repeat(64),
        size: 321,
      })
    ).toThrow();
  });
});

describe("digest-approved prerequisites and behavior assertions", () => {
  it("accepts a constrained APT package prerequisite", () => {
    expect(
      approvedPackageSchema.parse({
        manager: "apt",
        name: "binutils",
        reason: "Provides strings for the approved atomic",
      })
    ).toMatchObject({ manager: "apt", name: "binutils" });
  });

  it("rejects package command injection and relative target paths", () => {
    expect(() =>
      approvedPackageSchema.parse({
        manager: "apt",
        name: "binutils;id",
        reason: "invalid",
      })
    ).toThrow();
    expect(() =>
      successCriterionSchema.parse({ kind: "target_path_exists", path: "tmp/marker" })
    ).toThrow();
  });

  it("accepts a digest-approved negative content assertion", () => {
    expect(
      successCriterionSchema.parse({
        kind: "target_path_not_contains",
        path: "/root/.bash_history",
        value: "ATOMIC-HISTORY-MARKER",
      })
    ).toMatchObject({ kind: "target_path_not_contains" });
  });
});

describe("interactive Bash execution adapter", () => {
  const interactiveTest = {
    technique_id: "T1056.001",
    test_guid: "0e59d59d-3265-4d35-bebd-bf5c1ec40db5",
    name: "Logging bash history to syslog",
    executor: "sh",
    execution_mode: "runner",
    execution_adapter: "bash_interactive",
    elevation_required: true,
    required_capabilities: ["shell"],
    definition_digest: "a".repeat(64),
    inputs: {},
    expected_outcome: "Run the pinned prompt hook inside an interactive Bash loop",
    success_criteria: [
      {
        kind: "target_path_contains",
        path: "/var/log/atomic-history.log",
        value: "PROMPT_COMMAND",
      },
    ],
    cleanup_expected: true,
    risk_flags: ["persistence"],
  } as const;

  it("accepts the adapter for an automated sh executor", () => {
    expect(testPlanSchema.parse(interactiveTest).execution_adapter).toBe("bash_interactive");
  });

  it("rejects the adapter for a non-shell executor", () => {
    expect(() =>
      testPlanSchema.parse({ ...interactiveTest, executor: "powershell" })
    ).toThrow(/sh or bash/);
  });
});

describe("manual and GUI execution plans", () => {
  it("accepts a digest-approved operator procedure for a manual executor", () => {
    const parsed = testPlanSchema.parse({
      technique_id: "T1176",
      test_guid: "cb790029-17e6-4c43-b96f-002ce5f10938",
      name: "Firefox",
      executor: "manual",
      execution_mode: "operator",
      elevation_required: false,
      required_capabilities: ["gui", "browser", "interactive"],
      definition_digest: "f".repeat(64),
      inputs: {},
      expected_outcome: "Load the reviewed temporary Firefox extension",
      success_criteria: [
        {
          kind: "manual_evidence",
          description: "Operator confirms the temporary add-on is visible in about:debugging",
        },
      ],
      cleanup_expected: true,
      risk_flags: ["gui"],
      manual: {
        reviewed_steps: [
          "Open about:debugging and load the approved manifest.json as a temporary add-on",
        ],
        evidence_requirements: [
          "Confirm the extension appears in the Temporary Extensions section",
        ],
        cleanup_steps: ["Remove the temporary extension or close Firefox"],
      },
    });

    expect(parsed.execution_mode).toBe("operator");
    expect(parsed.required_capabilities).toContain("gui");
  });

  it("rejects a manual executor without reviewed operator steps", () => {
    expect(() =>
      testPlanSchema.parse({
        technique_id: "T1176",
        test_guid: "cb790029-17e6-4c43-b96f-002ce5f10938",
        name: "Firefox",
        executor: "manual",
        execution_mode: "operator",
        elevation_required: false,
        required_capabilities: ["gui"],
        definition_digest: "f".repeat(64),
        inputs: {},
        expected_outcome: "Load an extension",
        success_criteria: [{ kind: "manual_evidence", description: "Operator confirmation" }],
        cleanup_expected: false,
        risk_flags: ["gui"],
      })
    ).toThrow();
  });
});

describe("Elastic Agent instrumentation plan", () => {
  const basePlan = {
    schema_version: 3,
    run_id: "instrumented-run",
    mode: "atomic",
    type: "atomic",
    source: {
      kind: "atomic-red-team",
      reference: "T1001.002",
      repository: "https://github.com/redcanaryco/atomic-red-team.git",
      revision: "a".repeat(40),
      catalog_digest: "b".repeat(64),
    },
    runner: {
      repository: "https://github.com/redcanaryco/invoke-atomicredteam.git",
      revision: "c".repeat(40),
    },
    objective: "Verify telemetry on an automatically enrolled target",
    scope: {
      target_kind: "multipass",
      target_id: "art-instrumented",
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
        technique_id: "T1001.002",
        test_guid: "4ff61684-ad91-405c-9fbc-048354ff1d07",
        name: "Execute Embedded Script in Image via Steganography",
        executor: "sh",
        execution_mode: "runner",
        elevation_required: false,
        required_capabilities: ["shell"],
        definition_digest: "d".repeat(64),
        inputs: {},
        expected_outcome: "Generate process telemetry",
        success_criteria: [{ kind: "stdout_contains", value: "ATOMIC-STEG" }],
        cleanup_expected: true,
        risk_flags: [],
      },
    ],
  };

  it("binds the discovered Elastic control plane into the plan", () => {
    const parsed = atomicPlanSchema.parse({
      ...basePlan,
      instrumentation: {
        elastic_agent: {
          stack_version: "9.5.6",
          version: "9.5.6",
          kibana_url: "https://kibana.example:5601",
          fleet_url: "https://fleet.example:8220",
          fleet_server_host_id: "fleet-default",
          agent_policy_id: "policy-default",
          agent_policy_name: "Default Linux Defend",
          agent_policy_revision: 7,
          elastic_defend_package_policy_id: "endpoint-default",
          elastic_defend_package_version: "9.5.6",
          elasticsearch_output_id: "output-default",
          elasticsearch_url: "https://elasticsearch.example:9200",
          ca_sha256: "e".repeat(64),
        },
      },
    });

    expect(parsed.instrumentation?.elastic_agent).toMatchObject({
      version: "9.5.6",
      insecure: false,
      health_timeout_seconds: 300,
    });
  });

  it("rejects non-HTTPS Fleet URLs", () => {
    expect(() =>
      atomicPlanSchema.parse({
        ...basePlan,
        instrumentation: {
          elastic_agent: {
            stack_version: "9.5.6",
            version: "9.5.6",
            kibana_url: "https://kibana.example:5601",
            fleet_url: "http://fleet.example:8220",
            fleet_server_host_id: "fleet-default",
            agent_policy_id: "policy-default",
            agent_policy_name: "Default Linux Defend",
            agent_policy_revision: 7,
            elastic_defend_package_policy_id: "endpoint-default",
            elastic_defend_package_version: "9.5.6",
            elasticsearch_output_id: "output-default",
            elasticsearch_url: "https://elasticsearch.example:9200",
          },
        },
      })
    ).toThrow();
  });

  it("accepts digest-bound setup_steps when allow_setup_commands is set", () => {
    const parsed = atomicPlanSchema.parse({
      ...basePlan,
      controls: { ...basePlan.controls, allow_setup_commands: true },
      setup_steps: [
        { description: "enable linger for the execution user", command: ["loginctl", "enable-linger", "ubuntu"], elevated: true },
      ],
    });
    expect(parsed.setup_steps).toHaveLength(1);
    expect(parsed.setup_steps?.[0]?.elevated).toBe(true);
  });

  it("rejects setup_steps unless allow_setup_commands is true (fail closed)", () => {
    expect(() =>
      atomicPlanSchema.parse({
        ...basePlan,
        setup_steps: [{ description: "seed", command: ["true"] }],
      })
    ).toThrow();
  });

  it("defaults allow_setup_commands to false", () => {
    const parsed = atomicPlanSchema.parse({ ...basePlan });
    expect(parsed.controls.allow_setup_commands).toBe(false);
  });
});

describe("target_path_contains success criterion", () => {
  it("accepts a path and value", () => {
    const parsed = successCriterionSchema.parse({
      kind: "target_path_contains",
      path: "/etc/passwd",
      value: "evil_user",
    });
    expect(parsed).toEqual({ kind: "target_path_contains", path: "/etc/passwd", value: "evil_user" });
  });

  it("rejects a non-absolute path", () => {
    expect(() =>
      successCriterionSchema.parse({ kind: "target_path_contains", path: "etc/passwd", value: "x" })
    ).toThrow();
  });
});
