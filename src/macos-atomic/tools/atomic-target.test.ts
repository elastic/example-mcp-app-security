/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import { pinnedRepositoryRevisionArgs } from "./atomic-target.js";

describe("macOS Atomic target verification", () => {
  it("verifies root-owned pinned repositories as root", () => {
    expect(pinnedRepositoryRevisionArgs("/opt/atomic-red-team")).toEqual([
      "sudo",
      "git",
      "-C",
      "/opt/atomic-red-team",
      "rev-parse",
      "HEAD",
    ]);
  });
});
