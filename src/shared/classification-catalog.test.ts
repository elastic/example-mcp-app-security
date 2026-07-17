/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import {
  applyCatalog,
  emptyCatalog,
  signatureFor,
  type CatalogData,
} from "./classification-catalog.js";
import type { IndexAffordances } from "./environment-profile.js";

const heuristic: IndexAffordances = {
  huntable: true,
  matchable: false,
  enrichable: false,
  pivotable: false,
  confidence: "medium",
  evidence: ["owned-asset anchor"],
  source: "heuristic",
};

describe("signatureFor", () => {
  it("is stable regardless of field order and duplicates", () => {
    expect(signatureFor("idx", ["b", "a", "a"])).toBe(
      signatureFor("idx", ["a", "b"])
    );
  });

  it("changes when the name or the field shape changes", () => {
    const base = signatureFor("idx", ["a", "b"]);
    expect(signatureFor("idx2", ["a", "b"])).not.toBe(base);
    expect(signatureFor("idx", ["a", "b", "c"])).not.toBe(base);
  });
});

describe("applyCatalog", () => {
  it("returns the heuristic verdict when no entry matches", () => {
    expect(applyCatalog(emptyCatalog(), "sig-x", heuristic)).toBe(heuristic);
    expect(applyCatalog(emptyCatalog(), undefined, heuristic)).toBe(heuristic);
  });

  it("overrides with the sticky verdict when the signature matches", () => {
    const human: IndexAffordances = {
      ...heuristic,
      huntable: false,
      matchable: true,
      confidence: "high",
      source: "human",
    };
    const catalog: CatalogData = {
      version: 1,
      entries: {
        "sig-1": {
          signature: "sig-1",
          name: "some-intel-feed",
          affordances: human,
          approved_at: "2026-07-16T00:00:00.000Z",
        },
      },
    };
    expect(applyCatalog(catalog, "sig-1", heuristic)).toEqual(human);
  });
});
