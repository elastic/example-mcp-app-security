/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, afterAll } from "vitest";
import type { Dataset, EvalResult, EvaluatorResult, Evaluator } from "./types.js";
import { runMcpHostLoop } from "./runMcpHostLoop.js";

export interface RunnerOptions {
  /** Minimum numeric score [0–1] for a test to pass. Defaults to 0.5. */
  passingScore?: number;
}

/**
 * Registers a Vitest suite for every example in `dataset`.
 *
 * The entire suite is skipped unless `RUN_LLM_EVALS=1` is set in the
 * environment, so regular `npm test` incurs zero LLM cost.
 *
 * Each example becomes one `it` that:
 *   1. Runs the in-process MCP host loop to collect a trajectory.
 *   2. Passes the trajectory to every evaluator.
 *   3. Asserts that numeric scores meet `passingScore`.
 *
 * After all examples complete, a Markdown summary is written to stdout so
 * the GitHub Actions job summary (>> $GITHUB_STEP_SUMMARY) can capture it.
 */
export function runDataset(
  dataset: Dataset,
  evaluators: Record<string, Evaluator>,
  options: RunnerOptions = {}
): void {
  const { passingScore = 0.5 } = options;

  describe.skipIf(!process.env.RUN_LLM_EVALS)(dataset.name, () => {
    const results: EvalResult[] = [];

    for (const example of dataset.examples) {
      it(example.id, async () => {
        const trajectory = await runMcpHostLoop(example.input);

        const evalResults: Record<string, EvaluatorResult> = {};
        for (const [name, evaluator] of Object.entries(evaluators)) {
          evalResults[name] = await evaluator(trajectory, example.expected);
        }

        const result: EvalResult = {
          exampleId: example.id,
          input: example.input,
          trajectory,
          evaluators: evalResults,
        };
        results.push(result);

        for (const [name, evalResult] of Object.entries(evalResults)) {
          if (evalResult.score !== "N/A") {
            expect(
              evalResult.score,
              `[${name}] score ${evalResult.score.toFixed(2)} < ${passingScore}` +
                (evalResult.reason ? `: ${evalResult.reason}` : "")
            ).toBeGreaterThanOrEqual(passingScore);
          }
        }
      });
    }

    afterAll(() => {
      process.stdout.write(buildMarkdownSummary(dataset.name, results) + "\n");
    });
  });
}

function buildMarkdownSummary(datasetName: string, results: EvalResult[]): string {
  if (results.length === 0) {
    return `## Eval results: ${datasetName}\n\n_No examples ran._\n`;
  }

  const evaluatorNames = Array.from(
    new Set(results.flatMap((r) => Object.keys(r.evaluators)))
  );

  const headers = ["id", "input", ...evaluatorNames];
  const separator = headers.map(() => "---");

  const rows = results.map((r) => {
    const scoreCells = evaluatorNames.map((name) => {
      const e = r.evaluators[name];
      if (!e) return "—";
      if (e.score === "N/A") return "N/A";
      return `${(e.score * 100).toFixed(0)}%`;
    });
    return [r.exampleId, truncate(r.input, 60), ...scoreCells];
  });

  const lines = [
    `## Eval results: ${datasetName}`,
    "",
    `| ${headers.join(" | ")} |`,
    `| ${separator.join(" | ")} |`,
    ...rows.map((row) => `| ${row.join(" | ")} |`),
    "",
  ];

  return lines.join("\n");
}

function truncate(s: string, maxLen: number): string {
  return s.length <= maxLen ? s : `${s.slice(0, maxLen - 1)}…`;
}
