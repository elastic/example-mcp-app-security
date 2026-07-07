/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { readPackageVersion } from "./package-version.js";

function moduleUrlFor(dir: string): string {
  return pathToFileURL(join(dir, "fake-module.js")).href;
}

describe("readPackageVersion", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "pkg-version-"));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("returns the version from a package.json next to the calling module", () => {
    writeFileSync(
      join(tmp, "package.json"),
      JSON.stringify({ version: "1.2.3" }),
    );

    expect(readPackageVersion(moduleUrlFor(tmp))).toBe("1.2.3");
  });

  it("falls back to the parent directory's package.json (the dist/ + .mcpb layout)", () => {
    const child = join(tmp, "dist");
    mkdirSync(child);
    writeFileSync(
      join(tmp, "package.json"),
      JSON.stringify({ version: "2.0.0" }),
    );

    expect(readPackageVersion(moduleUrlFor(child))).toBe("2.0.0");
  });

  it("prefers the closer package.json over the parent's", () => {
    const child = join(tmp, "nested");
    mkdirSync(child);
    writeFileSync(
      join(tmp, "package.json"),
      JSON.stringify({ version: "outer" }),
    );
    writeFileSync(
      join(child, "package.json"),
      JSON.stringify({ version: "inner" }),
    );

    expect(readPackageVersion(moduleUrlFor(child))).toBe("inner");
  });

  it("returns the default '0.0.0' fallback when no package.json is reachable", () => {
    expect(readPackageVersion(moduleUrlFor(tmp))).toBe("0.0.0");
  });

  it("honours a custom fallback when no package.json is reachable", () => {
    expect(readPackageVersion(moduleUrlFor(tmp), "9.9.9")).toBe("9.9.9");
  });

  it("falls back when the nearest package.json is malformed JSON", () => {
    writeFileSync(join(tmp, "package.json"), "{not json");

    expect(readPackageVersion(moduleUrlFor(tmp), "fb")).toBe("fb");
  });

  it("falls back when package.json has no `version` field", () => {
    writeFileSync(
      join(tmp, "package.json"),
      JSON.stringify({ name: "foo" }),
    );

    expect(readPackageVersion(moduleUrlFor(tmp), "fb")).toBe("fb");
  });

  it("falls back when `version` is an empty string", () => {
    writeFileSync(
      join(tmp, "package.json"),
      JSON.stringify({ version: "" }),
    );

    expect(readPackageVersion(moduleUrlFor(tmp), "fb")).toBe("fb");
  });

  it("skips a malformed package.json in startDir and reads the parent's", () => {
    const child = join(tmp, "dist");
    mkdirSync(child);
    writeFileSync(join(child, "package.json"), "{not json");
    writeFileSync(
      join(tmp, "package.json"),
      JSON.stringify({ version: "from-parent" }),
    );

    expect(readPackageVersion(moduleUrlFor(child))).toBe("from-parent");
  });

  it("does not throw when moduleUrl is not a valid file:// URL", () => {
    expect(() => readPackageVersion("not a url at all")).not.toThrow();
    expect(readPackageVersion("not a url at all", "fb")).toBe("fb");
  });
});
