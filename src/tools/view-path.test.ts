/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import { resolveViewPath } from "./view-path.js";

const TOOLS_DIR = path.dirname(fileURLToPath(import.meta.url));

describe("resolveViewPath", () => {
  let existsSyncSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    existsSyncSpy = vi.spyOn(fs, "existsSync");
  });

  afterEach(() => {
    existsSyncSpy.mockRestore();
  });

  it("returns the first candidate that exists on disk", () => {
    const expected = path.resolve(
      TOOLS_DIR,
      "../../dist/views/alert-triage/mcp-app.html"
    );
    existsSyncSpy.mockImplementation((p: fs.PathLike) => p === expected);

    expect(resolveViewPath("alert-triage")).toBe(expected);
  });

  it("falls through to a later candidate when earlier ones do not exist", () => {
    const expected = path.resolve(
      TOOLS_DIR,
      "../../views/threat-hunt/mcp-app.html"
    );
    existsSyncSpy.mockImplementation((p: fs.PathLike) => p === expected);

    expect(resolveViewPath("threat-hunt")).toBe(expected);
  });

  it("falls back to the bundled dist/views/<name>/mcp-app.html when no candidate exists", () => {
    existsSyncSpy.mockReturnValue(false);

    const fallback = path.resolve(
      TOOLS_DIR,
      "views/case-management/mcp-app.html"
    );
    expect(resolveViewPath("case-management")).toBe(fallback);
  });

  it("interpolates the view name into every candidate path", () => {
    const checked: string[] = [];
    existsSyncSpy.mockImplementation((p: fs.PathLike) => {
      checked.push(String(p));
      return false;
    });

    resolveViewPath("attack-discovery");

    expect(checked.length).toBeGreaterThan(0);
    for (const candidate of checked) {
      expect(candidate).toContain("attack-discovery");
      expect(candidate.endsWith("mcp-app.html")).toBe(true);
    }
  });
});
