/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { DESKTOP_INSTALLER_SOURCE } from "./desktop-profile.js";

describe("Multipass desktop installer", () => {
  it("is valid Python and never embeds a static VNC password", () => {
    const compiled = spawnSync(
      "python3",
      ["-c", "import sys; compile(sys.stdin.read(), '<desktop-installer>', 'exec')"],
      { input: DESKTOP_INSTALLER_SOURCE, encoding: "utf8" }
    );
    expect(compiled.status, compiled.stderr).toBe(0);
    expect(DESKTOP_INSTALLER_SOURCE).toContain("secrets.token_urlsafe");
    expect(DESKTOP_INSTALLER_SOURCE).not.toMatch(/password\s*=\s*[\"'][^\"']+[\"']/);
  });
});
