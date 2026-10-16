/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { PROPOSAL_FIELD_KEYS } from "../../../../shared/alert-zero-types";
import { FIELD_COVERAGE, coverageSections, getUnmappedFields } from "./fieldCoverage";
import { FULL_PROPOSAL } from "./testFixtures";

/** Sections that carry a `data-section` attribute in the header / Proposal tab. */
const RENDERED_SECTIONS = [
  "Header",
  "Outcome",
  "Previous attempt",
  "Why",
  "What happens if you approve",
  "Lineage",
  "Investigation",
  "Provenance",
];

describe("FIELD_COVERAGE", () => {
  it("maps every proposal field key, and nothing else", () => {
    expect(Object.keys(FIELD_COVERAGE).sort()).toEqual([...PROPOSAL_FIELD_KEYS].sort());
    for (const key of PROPOSAL_FIELD_KEYS) {
      expect(FIELD_COVERAGE[key], key).toBeTruthy();
    }
  });

  it("only names sections the detail pane renders", () => {
    for (const key of PROPOSAL_FIELD_KEYS) {
      for (const section of coverageSections(key)) {
        expect(RENDERED_SECTIONS, `${key} → ${section}`).toContain(section);
      }
    }
  });

  it("is exercised by a fixture that populates every field", () => {
    const record = FULL_PROPOSAL as unknown as Record<string, unknown>;
    for (const key of PROPOSAL_FIELD_KEYS) {
      expect(record[key], key).not.toBeUndefined();
    }
  });
});

describe("getUnmappedFields", () => {
  it("returns nothing for a proposal with only known keys", () => {
    expect(getUnmappedFields(FULL_PROPOSAL as unknown as Record<string, unknown>)).toEqual([]);
  });

  it("detects keys the contract does not know", () => {
    const withExtra = { ...FULL_PROPOSAL, autonomyLevel: "supervised", nested: { a: 1 } };
    expect(getUnmappedFields(withExtra)).toEqual(["autonomyLevel", "nested"]);
  });
});
