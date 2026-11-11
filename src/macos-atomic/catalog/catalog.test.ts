/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { listTestAssets, loadMacosCatalog } from "./catalog.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe("macOS Atomic catalog", () => {
  it("selects macOS tests, detects architecture, and digests support assets", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "macos-atomic-catalog-"));
    roots.push(root);
    const technique = path.join(root, "T1000");
    fs.mkdirSync(path.join(technique, "src"), { recursive: true });
    fs.writeFileSync(path.join(technique, "src", "payload.txt"), "benign\n");
    fs.writeFileSync(
      path.join(technique, "T1000.yaml"),
      `attack_technique: T1000
display_name: Test technique
atomic_tests:
  - name: Intel-only macOS test
    auto_generated_guid: 11111111-1111-4111-8111-111111111111
    description: Run under Rosetta on an Intel Mac
    supported_platforms: [macos]
    executor:
      name: sh
      command: arch -x86_64 /usr/bin/true
      elevation_required: false
  - name: Linux-only test
    auto_generated_guid: 22222222-2222-4222-8222-222222222222
    supported_platforms: [linux]
    executor:
      name: sh
      command: id
  - name: AppleScript Finder access
    auto_generated_guid: 33333333-3333-4333-8333-333333333333
    supported_platforms: [macos]
    executor:
      name: sh
      command: osascript -e 'tell application "Finder" to get name of startup disk'
`,
      "utf8"
    );

    const catalog = loadMacosCatalog(root);
    expect(catalog.tests).toHaveLength(2);
    expect(catalog.tests[0]).toMatchObject({
      target_platform: "macos",
      preferred_architecture: "x86_64",
      executor: "sh",
    });
    expect(catalog.tests[1]).toMatchObject({
      test_guid: "33333333-3333-4333-8333-333333333333",
      risk_flags: expect.arrayContaining(["gui", "tcc"]),
    });
    expect(catalog.catalog_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(listTestAssets(catalog, catalog.tests[0]!.test_guid)).toEqual([
      expect.objectContaining({ path: "T1000/src/payload.txt", size: 7 }),
    ]);
  });
});
