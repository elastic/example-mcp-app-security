/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  BOOTSTRAP_SCRIPT,
  canResumeOrphanedMultipassTarget,
  multipassImageForDistro,
  multipassStateFromInfo,
} from "./atomic-target.js";

describe("target distro routing", () => {
  it("derives immutable Ubuntu aliases from the approved distro", () => {
    expect(multipassImageForDistro("ubuntu-22.04")).toBe("22.04");
    expect(multipassImageForDistro("ubuntu-24.04")).toBe("24.04");
    expect(multipassImageForDistro("rhel-9")).toContain(
      "Rocky-9-GenericCloud-Base-9.8-20260525.0.aarch64.qcow2"
    );
    expect(BOOTSTRAP_SCRIPT).toContain("command -v dnf");
    expect(BOOTSTRAP_SCRIPT).toContain("> /usr/bin/pwsh");
  });

  it("rejects an unknown automatic image mapping", () => {
    expect(() => multipassImageForDistro("debian-13")).toThrow(/does not recognize/);
  });
});

describe("orphaned Multipass provisioning resume", () => {
  const orphan = {
    id: "art-test",
    kind: "target",
    origin: "orphaned",
    cleaned: false,
  };

  it("allows only the exact uncleaned orphan during provisioning", () => {
    expect(canResumeOrphanedMultipassTarget("provisioning", [orphan], "art-test")).toBe(true);
    expect(canResumeOrphanedMultipassTarget("cleaning", [orphan], "art-test")).toBe(false);
    expect(canResumeOrphanedMultipassTarget("provisioning", [orphan], "other")).toBe(false);
    expect(
      canResumeOrphanedMultipassTarget(
        "provisioning",
        [{ ...orphan, cleaned: true }],
        "art-test"
      )
    ).toBe(false);
  });

  it("parses only the requested target state from Multipass JSON", () => {
    const stdout = JSON.stringify({
      info: {
        "art-test": { state: "Running" },
        other: { state: "Stopped" },
      },
    });
    expect(multipassStateFromInfo(stdout, "art-test")).toBe("Running");
    expect(multipassStateFromInfo(stdout, "missing")).toBeUndefined();
    expect(multipassStateFromInfo("not-json", "art-test")).toBeUndefined();
  });
});
