/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  assertSafeAssetPath,
  operatorSourceAssetRelativePath,
  sourceAssetPath,
} from "./source-assets.js";

describe("Atomic source asset paths", () => {
  it("accepts repository-relative files and rejects escapes", () => {
    expect(() => assertSafeAssetPath("T1176/src/manifest.json")).not.toThrow();
    expect(() => assertSafeAssetPath("../manifest.json")).toThrow(/Unsafe/);
    expect(() => assertSafeAssetPath("T1176\\src\\manifest.json")).toThrow(/Unsafe/);
    expect(() => assertSafeAssetPath("/etc/passwd")).toThrow(/Unsafe/);
    expect(() => assertSafeAssetPath("T1176//manifest.json")).toThrow(/Unsafe/);
    expect(() => assertSafeAssetPath("T1176/./manifest.json")).toThrow(/Unsafe/);
  });

  it("derives immutable and confined-browser-safe target locations", () => {
    expect(sourceAssetPath("T1176/src/manifest.json")).toBe(
      "/opt/atomic-red-team/atomics/T1176/src/manifest.json"
    );
    expect(
      operatorSourceAssetRelativePath(
        "atomic-firefox-a1b2c3",
        "T1176/src/manifest.json"
      )
    ).toBe(
      "AtomicRedTeamAssets/atomic-firefox-a1b2c3/T1176/src/manifest.json"
    );
  });
});
