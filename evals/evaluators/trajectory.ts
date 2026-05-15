/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Evaluator, EvaluatorResult, ExpectedBehavior, Trajectory } from "../types.js";

/**
 * Sequence-aware evaluator: how closely did the LLM follow the expected tool order?
 *
 * Computes the Longest Common Subsequence (LCS) of the actual tool-call
 * sequence against `expected.tools`, then normalises by the longer of the
 * two sequences:
 *
 *   score = lcs(actual, expected) / max(|actual|, |expected|) ∈ [0, 1]
 *
 * Dividing by the max penalises both missing tools (low recall) and extra
 * spurious tools (low precision) without needing separate P/R components —
 * those are tool-selection's job.
 *
 * Returns `'N/A'` when `expected.tools` is absent so datasets that don't
 * specify an ordered tool sequence don't fail on this evaluator. This guard
 * is load-bearing: running LCS against an undefined expectation would produce
 * meaningless 0-scores that mask real regressions in other evaluators.
 */
export const trajectoryScore: Evaluator = (
  trajectory: Trajectory,
  expected: ExpectedBehavior
): EvaluatorResult => {
  if (!expected.tools) {
    return { score: "N/A" };
  }

  const actual = trajectory.map((tc) => tc.tool);
  const exp = expected.tools;

  if (actual.length === 0 && exp.length === 0) {
    return { score: 1, reason: "Both actual and expected sequences are empty" };
  }

  const lcsLen = lcs(actual, exp);
  const denom = Math.max(actual.length, exp.length);
  const score = lcsLen / denom;

  return {
    score,
    reason:
      `LCS=${lcsLen} / max(|actual|=${actual.length}, |expected|=${exp.length})` +
      `=${denom} → score=${score.toFixed(2)}` +
      (score < 1
        ? ` | actual=[${actual.join(", ")}] expected=[${exp.join(", ")}]`
        : ""),
  };
};

/**
 * Classic O(m·n) DP implementation of Longest Common Subsequence length.
 * Compares elements by identity (===), which is correct for tool name strings.
 */
function lcs(a: string[], b: string[]): number {
  const m = a.length;
  const n = b.length;
  // Single flat array instead of Array<Array<number>> avoids inner allocation
  const dp = new Array<number>((m + 1) * (n + 1)).fill(0);
  const idx = (i: number, j: number) => i * (n + 1) + j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[idx(i, j)] =
        a[i - 1] === b[j - 1]
          ? dp[idx(i - 1, j - 1)] + 1
          : Math.max(dp[idx(i - 1, j)], dp[idx(i, j - 1)]);
    }
  }

  return dp[idx(m, n)];
}
