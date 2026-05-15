/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Evaluator, EvaluatorResult, ExpectedBehavior, Trajectory } from "../types.js";

/**
 * Set-based tool-selection evaluator: how well did the LLM pick the right tools?
 *
 * Computes precision, recall, and their harmonic mean (F1) against the
 * set of tool names in `expected.tools`. Deduplicates both sides — order
 * and repetition are tested by the trajectory evaluator instead.
 *
 *   precision = |called ∩ expected| / |called|   (no spurious calls)
 *   recall    = |called ∩ expected| / |expected|  (no missed calls)
 *   score     = F1 = 2·P·R / (P+R)               ∈ [0, 1]
 *
 * Returns `'N/A'` when `expected.tools` is absent so datasets that only
 * care about skill routing don't need to declare tool lists.
 *
 * CI gate: datasets should require ≥0.8 (80%) on positive examples.
 * The failure reason lists missed and extra tools to make debugging fast.
 */
export const toolSelection: Evaluator = (
  trajectory: Trajectory,
  expected: ExpectedBehavior
): EvaluatorResult => {
  if (!expected.tools) {
    return { score: "N/A" };
  }

  const expectedSet = new Set(expected.tools);
  const calledSet = new Set(trajectory.map((tc) => tc.tool));

  if (expectedSet.size === 0 && calledSet.size === 0) {
    return { score: 1, reason: "No tools expected and none called" };
  }

  const tp = [...calledSet].filter((t) => expectedSet.has(t)).length;
  const precision = calledSet.size > 0 ? tp / calledSet.size : 0;
  const recall = expectedSet.size > 0 ? tp / expectedSet.size : 0;
  const f1 =
    precision + recall > 0
      ? (2 * precision * recall) / (precision + recall)
      : 0;

  const missed = [...expectedSet].filter((t) => !calledSet.has(t));
  const extra = [...calledSet].filter((t) => !expectedSet.has(t));

  const parts = [
    `F1=${f1.toFixed(2)} (precision=${precision.toFixed(2)}, recall=${recall.toFixed(2)})`,
    ...(missed.length > 0 ? [`missed: [${missed.join(", ")}]`] : []),
    ...(extra.length > 0 ? [`extra: [${extra.join(", ")}]`] : []),
  ];

  return { score: f1, reason: parts.join(" | ") };
};
