/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { listTestAssets, loadLinuxCatalog } from "./catalog.js";

describe("Linux atomic catalog", () => {
  const directories: string[] = [];

  afterEach(() => {
    for (const directory of directories.splice(0)) {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("keeps Linux tests, filters other platforms, and classifies risk", () => {
    const root = mkdtempSync(path.join(tmpdir(), "atomic-catalog-"));
    directories.push(root);
    const technique = path.join(root, "T9999");
    mkdirSync(technique);
    writeFileSync(
      path.join(technique, "T9999.yaml"),
      `attack_technique: T9999
display_name: Example
atomic_tests:
  - name: Risky Linux test
    auto_generated_guid: 22222222-2222-4222-8222-222222222222
    description: Reboots a disposable test host
    supported_platforms: [linux]
    input_arguments:
      message:
        description: test message
        type: string
        default: hello
    executor:
      name: bash
      elevation_required: true
      command: shutdown -r now
      cleanup_command: echo restored
  - name: Windows test
    auto_generated_guid: 33333333-3333-4333-8333-333333333333
    description: not for Linux
    supported_platforms: [windows]
    executor:
      name: command_prompt
      command: whoami
`,
      "utf8"
    );
    const catalog = loadLinuxCatalog(root);
    expect(catalog.tests).toHaveLength(1);
    expect(catalog.tests[0]?.test_guid).toBe("22222222-2222-4222-8222-222222222222");
    expect(catalog.tests[0]?.risk_flags).toContain("reboot");
    expect(catalog.tests[0]?.risk_flags).toContain("destructive");
    expect(catalog.tests[0]?.risk_flags).toContain("elevated");
    expect(catalog.tests[0]?.shared_target_safe).toBe(false);
    expect(catalog.tests[0]?.definition_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(catalog.catalog_digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("marks manual tests instead of pretending they are automated", () => {
    const root = mkdtempSync(path.join(tmpdir(), "atomic-catalog-"));
    directories.push(root);
    const technique = path.join(root, "T9998");
    mkdirSync(technique);
    writeFileSync(
      path.join(technique, "T9998.yaml"),
      `attack_technique: T9998
display_name: Manual Example
atomic_tests:
  - name: Manual Linux test
    auto_generated_guid: 44444444-4444-4444-8444-444444444444
    description: Human action
    supported_platforms: [linux]
    executor:
      name: manual
      steps: Perform the reviewed action
`,
      "utf8"
    );
    const test = loadLinuxCatalog(root).tests[0];
    expect(test?.manual).toBe(true);
    expect(test?.shared_target_safe).toBe(false);
    expect(test?.risk_flags).toContain("manual");
  });

  it("routes Mac HISTCONTROL to its explicitly supported Linux environment", () => {
    const root = mkdtempSync(path.join(tmpdir(), "atomic-catalog-"));
    directories.push(root);
    const technique = path.join(root, "T1690");
    mkdirSync(technique);
    writeFileSync(
      path.join(technique, "T1690.yaml"),
      `attack_technique: T1690
display_name: Prevent Command History Logging
atomic_tests:
  - name: Mac HISTCONTROL
    auto_generated_guid: 468566d5-83e5-40c1-b338-511e1659628d
    description: Persist HISTCONTROL in bash_profile
    supported_platforms: [macos, linux]
    executor:
      name: manual
      steps: export HISTCONTROL=ignoreboth
`,
      "utf8"
    );

    const test = loadLinuxCatalog(root).tests[0];
    expect(test?.target_platform).toBe("linux");
    expect(test?.preferred_distro).toBe("ubuntu-24.04");
  });

  it("routes broken CentOS-only Cb syntax to the Linux compatibility target", () => {
    const root = mkdtempSync(path.join(tmpdir(), "atomic-catalog-"));
    directories.push(root);
    const technique = path.join(root, "T1685");
    mkdirSync(technique);
    writeFileSync(
      path.join(technique, "T1685.yaml"),
      `attack_technique: T1685
display_name: Disable or Modify Tools
atomic_tests:
  - name: Disable Cb Response
    auto_generated_guid: ae8943f7-0f8d-44de-962d-fbc2e2f03eb8
    description: Disable the Cb Response service
    supported_platforms: [linux]
    executor:
      name: sh
      command: systemctl stop cbdaemon
`,
      "utf8"
    );

    const test = loadLinuxCatalog(root).tests[0];
    expect(test?.target_platform).toBe("linux");
    expect(test?.preferred_distro).toBe("ubuntu-24.04");
  });

  it("inventories non-YAML support files with immutable metadata", () => {
    const root = mkdtempSync(path.join(tmpdir(), "atomic-catalog-"));
    directories.push(root);
    const technique = path.join(root, "T1176");
    const source = path.join(technique, "src");
    mkdirSync(source, { recursive: true });
    writeFileSync(
      path.join(technique, "T1176.yaml"),
      `attack_technique: T1176
display_name: Browser Extensions
atomic_tests:
  - name: Firefox
    auto_generated_guid: cb790029-17e6-4c43-b96f-002ce5f10938
    description: Load a temporary extension
    supported_platforms: [linux]
    executor:
      name: manual
      steps: Load ./src/manifest.json
`,
      "utf8"
    );
    writeFileSync(path.join(source, "manifest.json"), "{\"name\":\"Atomic\"}\n", "utf8");
    writeFileSync(path.join(source, "background.js"), "console.log('atomic');\n", "utf8");

    const catalog = loadLinuxCatalog(root);
    const assets = listTestAssets(catalog, "cb790029-17e6-4c43-b96f-002ce5f10938");
    expect(assets.map((asset) => asset.path)).toEqual([
      "T1176/src/background.js",
      "T1176/src/manifest.json",
    ]);
    expect(assets.every((asset) => /^[0-9a-f]{64}$/.test(asset.sha256))).toBe(true);
    expect(assets[1]?.size).toBe(18);
  });
});
