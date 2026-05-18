/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Evaluator, EvaluatorResult, ExpectedBehavior, Trajectory } from "../types.js";

/**
 * Binary evaluator: did the LLM call the skill's entry-point tool?
 *
 * Each MCP skill has a single model-facing entry-point tool (e.g. `migrate-rules`
 * for the automatic-migration skill, `manage-rules` for detection-rule-management).
 * `expected.skill` holds that tool name. The evaluator checks whether the
 * trajectory contains at least one call to that tool.
 *
 * Returns `'N/A'` when `expected.skill` is absent so datasets that don't
 * care about skill routing can omit the field without failing the run.
 */
export const skillActivation: Evaluator = (
  trajectory: Trajectory,
  expected: ExpectedBehavior
): EvaluatorResult => {
  if (!expected.skill) {
    return { score: "N/A" };
  }

  const activated = trajectory.some((tc) => tc.tool === expected.skill);

  return {
    score: activated ? 1 : 0,
    reason: activated
      ? `Tool "${expected.skill}" was called`
      : `Tool "${expected.skill}" was never called (trajectory: [${trajectory.map((t) => t.tool).join(", ") || "empty"}])`,
  };
};
