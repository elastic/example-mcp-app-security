/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createStderrLogger } from "./logger.js";

describe("createStderrLogger", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("writes child logger messages to stderr with context", () => {
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    createStderrLogger(["elastic-security"]).child("telemetry").info("opted in");

    expect(write).toHaveBeenCalledWith("[elastic-security:telemetry] opted in\n");
  });

  it("formats errors with their stack when available", () => {
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const err = new Error("boom");
    err.stack = "Error: boom\n  at test";

    createStderrLogger(["server"]).error(err);

    expect(write).toHaveBeenCalledWith("[server] Error: boom\n  at test\n");
  });
});
