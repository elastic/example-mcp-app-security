/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  ELASTIC_AGENT_INSTALLER,
  elasticAgentArtifact,
  isElasticAgentHealthy,
} from "./elastic-agent.js";
import { runProcess } from "./process.js";

describe("Elastic Agent artifacts", () => {
  it("maps Intel and ARM Linux architectures to official tarballs", () => {
    expect(elasticAgentArtifact("9.5.6", "x86_64")).toMatchObject({
      architecture: "x86_64",
      filename: "elastic-agent-9.5.6-linux-x86_64.tar.gz",
    });
    expect(elasticAgentArtifact("9.5.6", "aarch64")).toMatchObject({
      architecture: "arm64",
      filename: "elastic-agent-9.5.6-linux-arm64.tar.gz",
    });
  });

  it("rejects unsupported architectures", () => {
    expect(() => elasticAgentArtifact("9.5.6", "riscv64")).toThrow(
      "Unsupported Elastic Agent architecture"
    );
  });

  it("ships a syntactically valid Python installer", async () => {
    const result = await runProcess(
      "python3",
      [
        "-c",
        `compile(${JSON.stringify(ELASTIC_AGENT_INSTALLER)}, "elastic-agent-installer", "exec")`,
      ],
      { timeoutMs: 5_000 }
    );

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
  });
});

describe("Elastic Agent health", () => {
  const status = (stdout: string, exitCode = 0, timedOut = false) => ({
    stdout,
    exitCode,
    timedOut,
  });

  it("accepts current JSON status with a healthy Fleet connection", () => {
    expect(
      isElasticAgentHealthy(
        status(JSON.stringify({
          state: 2,
          message: "Running",
          fleetState: 2,
          fleetMessage: "Connected",
          components: [{ id: "endpoint-default", state: 2 }],
        }))
      )
    ).toBe(true);
  });

  it("accepts older JSON field casing and string state names", () => {
    expect(
      isElasticAgentHealthy(
        status(JSON.stringify({ state: "HEALTHY", FleetState: "HEALTHY" }))
      )
    ).toBe(true);
  });

  it("rejects degraded Agent or Fleet state", () => {
    expect(isElasticAgentHealthy(status(JSON.stringify({ state: 3 })))).toBe(false);
    expect(
      isElasticAgentHealthy(status(JSON.stringify({ state: 2, fleet_state: 4 })))
    ).toBe(false);
  });

  it("accepts the current tree and legacy flat human output", () => {
    expect(
      isElasticAgentHealthy(
        status("┌─ fleet\n│  └─ status: (HEALTHY) Connected\n└─ elastic-agent\n   └─ status: (HEALTHY) Running\n")
      )
    ).toBe(true);
    expect(isElasticAgentHealthy(status("State: HEALTHY\nMessage: Running\n"))).toBe(true);
  });

  it("does not mistake a healthy child for a degraded top-level Agent", () => {
    expect(
      isElasticAgentHealthy(
        status("└─ elastic-agent\n   ├─ status: (DEGRADED) Running\n   └─ endpoint-default\n      └─ status: (HEALTHY) Running\n")
      )
    ).toBe(false);
  });

  it("rejects failed and timed-out status commands", () => {
    expect(isElasticAgentHealthy(status(JSON.stringify({ state: 2 }), 1))).toBe(false);
    expect(isElasticAgentHealthy(status(JSON.stringify({ state: 2 }), 0, true))).toBe(false);
  });
});
