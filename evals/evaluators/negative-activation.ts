/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Evaluator, EvaluatorResult, ExpectedBehavior, Trajectory } from "../types.js";

/**
 * Binary evaluator for distractor examples: did the LLM correctly avoid
 * calling the skill's entry-point tool?
 *
 * This is the complement of `skillActivation`. Use it on examples where the
 * user query should NOT trigger the skill — e.g. a migration skill dataset
 * includes unrelated queries (case management, threat hunting) to confirm the
 * LLM doesn't call `migrate-rules` for everything.
 *
 * Score semantics (binary):
 *   1 — skill tool absent from trajectory (correct — not distracted)
 *   0 — skill tool present in trajectory (false positive — skill over-triggered)
 *
 * Returns `'N/A'` when `expected.skill` is absent, consistent with how
 * `skillActivation` handles missing skill declarations.
 *
 * CI gate: datasets should require 100% on this evaluator for distractor
 * examples — a false positive means the skill's SKILL.md is too aggressive
 * and will fire on unrelated queries in production.
 */
export const negativeActivation: Evaluator = (
  trajectory: Trajectory,
  expected: ExpectedBehavior
): EvaluatorResult => {
  if (!expected.skill) {
    return { score: "N/A" };
  }

  const falsePositive = trajectory.some((tc) => tc.tool === expected.skill);

  return {
    score: falsePositive ? 0 : 1,
    reason: falsePositive
      ? `Tool "${expected.skill}" was called but should not have been (false positive)`
      : `Tool "${expected.skill}" was correctly absent from the trajectory`,
  };
};
