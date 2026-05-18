/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Evaluator, EvaluatorResult, ExpectedBehavior, Trajectory } from "../types.js";
import type { LlmProvider } from "../llm/types.js";

/**
 * LLM-as-judge evaluator: asks an LLM to score the trajectory against
 * the natural-language assertions in `expected.criteria`.
 *
 * Returns `'N/A'` when `expected.criteria` is absent or empty so datasets
 * that rely only on structural evaluators don't incur extra LLM calls.
 *
 * Usage:
 *   import { createCriteriaEvaluator } from "./criteria.js";
 *   import { createDefaultLlmProvider } from "../llm/index.js";
 *
 *   runDataset(dataset, {
 *     criteria: createCriteriaEvaluator(createDefaultLlmProvider()),
 *   });
 *
 * The factory pattern is necessary because the `Evaluator` type is a plain
 * function — the LLM provider is closed over rather than passed as an arg.
 */
export function createCriteriaEvaluator(llm: LlmProvider): Evaluator {
  return async (
    trajectory: Trajectory,
    expected: ExpectedBehavior
  ): Promise<EvaluatorResult> => {
    if (!expected.criteria || expected.criteria.length === 0) {
      return { score: "N/A" };
    }

    const prompt = buildJudgePrompt(trajectory, expected.criteria);
    const response = await llm.chat([{ role: "user", content: prompt }], []);
    const text = response.content ?? "";

    return parseJudgeResponse(text);
  };
}

/**
 * Builds the rubric prompt sent to the judge LLM.
 *
 * Asks for a JSON object with `score` (0–1) and `reasoning` (string) so
 * parsing is deterministic. The trajectory is serialised as a compact JSON
 * array of `{tool, args}` pairs — `result` is omitted to avoid token bloat
 * from large tool outputs.
 */
function buildJudgePrompt(trajectory: Trajectory, criteria: string[]): string {
  const trajectoryStr = JSON.stringify(
    trajectory.map(({ tool, args }) => ({ tool, args })),
    null,
    2
  );

  const criteriaList = criteria
    .map((c, i) => `${i + 1}. ${c}`)
    .join("\n");

  return `You are an impartial evaluator assessing the quality of an AI assistant's tool-calling behaviour.

## Trajectory (tools the assistant called, in order)

\`\`\`json
${trajectoryStr}
\`\`\`

## Evaluation criteria

${criteriaList}

## Task

Score how well the trajectory satisfies ALL of the criteria above on a scale from 0.0 to 1.0:
- 1.0  All criteria fully satisfied
- 0.75 Most criteria satisfied with minor gaps
- 0.5  About half the criteria satisfied
- 0.25 Most criteria unmet with only minor satisfaction
- 0.0  No criteria satisfied at all

Respond with a single JSON object — no markdown fences, no extra text:
{"score": <number 0.0–1.0>, "reasoning": "<concise explanation referencing specific criteria>"}`;
}

/**
 * Parses the judge LLM's response into an EvaluatorResult.
 *
 * Tries JSON.parse first. Falls back to a regex that extracts a bare number
 * from the text in case the model wraps the response in prose.
 */
function parseJudgeResponse(text: string): EvaluatorResult {
  const trimmed = text.trim();

  // Primary: extract the first {...} object in the response
  const jsonMatch = trimmed.match(/\{[\s\S]*\}/);
  if (jsonMatch) {
    try {
      const parsed = JSON.parse(jsonMatch[0]) as unknown;
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "score" in parsed &&
        typeof (parsed as Record<string, unknown>).score === "number"
      ) {
        const { score, reasoning } = parsed as {
          score: number;
          reasoning?: unknown;
        };
        const clampedScore = Math.min(1, Math.max(0, score));
        return {
          score: clampedScore,
          reason:
            typeof reasoning === "string"
              ? reasoning
              : `raw judge response: ${trimmed}`,
        };
      }
    } catch {
      // fall through to regex fallback
    }
  }

  // Fallback: look for a bare decimal / integer in [0, 1]
  const numMatch = trimmed.match(/\b(1(?:\.0+)?|0(?:\.\d+)?)\b/);
  if (numMatch) {
    const score = parseFloat(numMatch[1]);
    return {
      score,
      reason: `score parsed from prose; raw response: ${trimmed.slice(0, 200)}`,
    };
  }

  return {
    score: 0,
    reason: `judge response could not be parsed; raw response: ${trimmed.slice(0, 200)}`,
  };
}
