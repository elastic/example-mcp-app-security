/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** A single tool invocation captured during an MCP host loop run. */
export interface ToolCall {
  tool: string;
  args: Record<string, unknown>;
  result?: unknown;
}

/** Ordered sequence of tool calls produced by one eval run. */
export type Trajectory = ToolCall[];

/**
 * What a passing run should look like.
 * `tools` and `criteria` are both optional — evaluators that depend on them
 * return `'N/A'` when the field is absent, so a dataset can omit whichever
 * dimension is irrelevant for a given example.
 */
export interface ExpectedBehavior {
  /** Ordered list of tool names the host should call. Used by trajectory / tool-selection evaluators. */
  tools?: string[];
  /** Natural-language assertions checked by the criteria (LLM-as-judge) evaluator. */
  criteria?: string[];
  /** Skill ID that should be activated. Used by the skill-activation evaluator. */
  skill?: string;
}

/** One test case inside a dataset. */
export interface Example {
  /** Stable identifier — used as a key in result tables and CI summaries. */
  id: string;
  /** The user message sent to the LLM host at the start of the simulation. */
  input: string;
  expected: ExpectedBehavior;
}

/** A named collection of examples that can be loaded by the runner. */
export interface Dataset {
  name: string;
  examples: Example[];
}

/**
 * Output of a single evaluator for one example.
 * `score` is a value in [0, 1] when the evaluator ran, or `'N/A'` when the
 * evaluator skipped (e.g. `expected.tools` was absent for trajectory evaluator).
 */
export interface EvaluatorResult {
  score: number | 'N/A';
  /** Human-readable explanation of the score, required when score is numeric. */
  reason?: string;
}

/** Aggregate result for one example after all evaluators have run. */
export interface EvalResult {
  exampleId: string;
  input: string;
  trajectory: Trajectory;
  /** Keys are evaluator names (e.g. `'skill-activation'`, `'trajectory'`). */
  evaluators: Record<string, EvaluatorResult>;
}

/**
 * Contract every evaluator module must satisfy.
 * Async to accommodate LLM-as-judge evaluators that call an LLM provider.
 */
export type Evaluator = (
  trajectory: Trajectory,
  expected: ExpectedBehavior
) => EvaluatorResult | Promise<EvaluatorResult>;
