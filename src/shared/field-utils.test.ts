/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import { toScalar } from "./field-utils.js";

describe("toScalar", () => {
  it("returns a scalar value unchanged", () => {
    expect(toScalar("sa-da-vm-lls-01")).toBe("sa-da-vm-lls-01");
  });

  it("returns the first element of a non-empty array", () => {
    expect(toScalar(["sa-da-vm-lls-01", "sa-da-ingest-01"])).toBe("sa-da-vm-lls-01");
  });

  it("returns undefined for an empty array", () => {
    expect(toScalar([])).toBeUndefined();
  });

  it("returns undefined for undefined", () => {
    expect(toScalar(undefined)).toBeUndefined();
  });
});
