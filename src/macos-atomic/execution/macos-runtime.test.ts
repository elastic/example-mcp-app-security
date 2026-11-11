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
import {
  elasticAgentArtifact,
  elasticEndpointInstallTestPassed,
  isElasticAgentHealthy,
  isElasticSystemExtensionActiveAndEnabled,
} from "./elastic-agent.js";
import { shellQuoteArg, sshTargetDestination } from "./target.js";
import { tartCloneTimeoutMs, tartListContains, tartRunArgs } from "./tart.js";
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

  it("requires the Elastic system extension to be both active and enabled", () => {
    const header =
      "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n";
    expect(isElasticSystemExtensionActiveAndEnabled(
      header +
        "*\t*\t2BT3HPN62Z\tco.elastic.systemextension (9.5.6)\tElasticEndpoint\t[activated enabled]\n"
    )).toBe(true);
    expect(isElasticSystemExtensionActiveAndEnabled(
      header +
        "\t*\t2BT3HPN62Z\tco.elastic.systemextension (9.5.6)\tElasticEndpoint\t[activated waiting for user]\n"
    )).toBe(false);
  });

  it("rejects Elastic Endpoint install tests that still need macOS approvals", () => {
    expect(elasticEndpointInstallTestPassed("all required permissions are enabled"))
      .toBe(true);
    expect(elasticEndpointInstallTestPassed("Enable Full Disk Access to continue"))
      .toBe(false);
    expect(elasticEndpointInstallTestPassed("Approve the network content filter"))
      .toBe(false);
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

  it("bounds a Tart clone by the approved run TTL instead of thirty minutes", () => {
    expect(tartCloneTimeoutMs(120)).toBe(120 * 60_000);
    expect(tartCloneTimeoutMs(300)).toBe(240 * 60_000);
    expect(() => tartCloneTimeoutMs(0)).toThrow("positive integer TTL");
  });
});
