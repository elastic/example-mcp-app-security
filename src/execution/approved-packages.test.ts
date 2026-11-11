/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  approvedPackageInstallSpec,
  parseDpkgQuery,
  parsePkgQuery,
} from "./approved-packages.js";

describe("approved package helpers", () => {
  it("preserves an optional digest-approved package version", () => {
    expect(
      approvedPackageInstallSpec({
        manager: "apt",
        name: "binutils",
        version: "2.42-4ubuntu2.5",
        reason: "Provides strings",
      })
    ).toBe("binutils=2.42-4ubuntu2.5");
  });

  it("parses dpkg installation status and version", () => {
    expect(parseDpkgQuery("install ok installed\t2.42-4ubuntu2.5\n")).toEqual({
      status: "install ok installed",
      version: "2.42-4ubuntu2.5",
    });
  });

  it("formats and parses FreeBSD pkg packages", () => {
    expect(
      approvedPackageInstallSpec({
        manager: "pkg",
        name: "bash",
        version: "5.2.37",
        reason: "Runs a bash executor",
      })
    ).toBe("bash-5.2.37");
    expect(parsePkgQuery("bash\t5.2.37\n", "bash")).toEqual({
      status: "install ok installed",
      version: "5.2.37",
    });
  });
});
