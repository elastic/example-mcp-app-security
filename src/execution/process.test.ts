/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import { runProcess } from "./process.js";

describe("runProcess input", () => {
  it("sends sensitive configuration over stdin instead of command arguments", async () => {
    const result = await runProcess(
      process.execPath,
      ["-e", "process.stdin.pipe(process.stdout)"],
      { timeoutMs: 5_000, input: "stdin-only-value" }
    );

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("stdin-only-value");
    expect(result.args.join(" ")).not.toContain("stdin-only-value");
  });
});
