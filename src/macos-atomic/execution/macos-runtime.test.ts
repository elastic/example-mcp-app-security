/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  approvedPackageInstallSpec,
  parseBrewQuery,
} from "./approved-packages.js";
import { elasticAgentArtifact, isElasticAgentHealthy } from "./elastic-agent.js";
import { shellQuoteArg, sshTargetDestination } from "./target.js";
import { tartListContains, tartRunArgs } from "./tart.js";
import type { AtomicPlan } from "../tools/atomic-run-state.js";

describe("macOS runtime helpers", () => {
  it("binds Homebrew package versions", () => {
    expect(approvedPackageInstallSpec({
      manager: "brew",
      name: "bash",
      version: "5.3.3",
      reason: "Atomic prerequisite",
    })).toBe("bash@5.3.3");
    expect(parseBrewQuery("bash 5.3.3\n", "bash")).toEqual({
      status: "install ok installed",
      version: "5.3.3",
    });
  });

  it("resolves official Darwin Elastic Agent artifacts for both architectures", () => {
    expect(elasticAgentArtifact("9.5.6", "arm64").filename)
      .toBe("elastic-agent-9.5.6-darwin-aarch64.tar.gz");
    expect(elasticAgentArtifact("9.5.6", "x86_64").filename)
      .toBe("elastic-agent-9.5.6-darwin-x86_64.tar.gz");
  });

  it("accepts the current Elastic Agent tree health output", () => {
    expect(isElasticAgentHealthy({
      exitCode: 0,
      timedOut: false,
      stdout: "elastic-agent (HEALTHY) Running\n",
    })).toBe(true);
  });

  it("quotes remote commands and parses Tart inventories", () => {
    expect(shellQuoteArg("a'b")).toBe("'a'\\''b'");
    expect(sshTargetDestination("admin", "192.0.2.4")).toBe("admin@192.0.2.4");
    expect(tartListContains('[{"Name":"art-macos","Running":true}]', "art-macos"))
      .toBe(true);
    expect(tartListContains("[]", "art-macos")).toBe(false);
  });

  it("opens a Tart window for desktop/operator targets", () => {
    const base = {
      target_kind: "tart",
      target_id: "art-macos",
      target_profile: "desktop",
    } as AtomicPlan["scope"];
    expect(tartRunArgs(base)).toEqual(["run", "art-macos"]);
    expect(tartRunArgs({ ...base, target_profile: "server" }))
      .toEqual(["run", "--no-graphics", "art-macos"]);
  });
});
