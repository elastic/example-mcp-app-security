/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Dataset, Example } from "../types.js";
import { runDataset } from "../runner.js";
import { skillActivation } from "../evaluators/skill-activation.js";
import { negativeActivation } from "../evaluators/negative-activation.js";
import { toolSelection } from "../evaluators/tool-selection.js";

/**
 * The model-facing entry-point tool registered by the
 * detection-rule-management skill (src/tools/detection-rules.ts).
 */
const SKILL_TOOL = "manage-rules";

// ---------------------------------------------------------------------------
// Positive examples — the LLM should call manage-rules
// ---------------------------------------------------------------------------

const positiveExamples: Example[] = [
  {
    id: "drm-pos-01",
    input: "Show me my noisy rules — which detection rules are generating the most alerts?",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
  {
    id: "drm-pos-02",
    input: "List all my currently enabled detection rules",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
  {
    id: "drm-pos-03",
    input: "Find high severity detection rules related to PowerShell execution",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
  {
    id: "drm-pos-04",
    input: "What detection rules do I have covering initial access tactics?",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
];

// ---------------------------------------------------------------------------
// Distractor examples — the LLM should NOT call manage-rules
// ---------------------------------------------------------------------------

const distractorExamples: Example[] = [
  {
    id: "drm-neg-01",
    input: "Create a new case for a ransomware incident I'm currently investigating",
    expected: {
      // skill is set so negativeActivation knows which tool to check for absence
      skill: SKILL_TOOL,
    },
  },
  {
    id: "drm-neg-02",
    input: "Show me all critical alerts that fired in the last hour",
    expected: {
      skill: SKILL_TOOL,
    },
  },
  {
    id: "drm-neg-03",
    input: "Run an ES|QL query to find failed SSH login attempts on my Linux hosts",
    expected: {
      skill: SKILL_TOOL,
    },
  },
  {
    id: "drm-neg-04",
    input: "A process on host web-01 just spawned cmd.exe — help me investigate",
    expected: {
      skill: SKILL_TOOL,
    },
  },
];

// ---------------------------------------------------------------------------
// Export the full dataset for reference / cross-dataset tooling
// ---------------------------------------------------------------------------

export const detectionRuleManagementDataset: Dataset = {
  name: "detection-rule-management",
  examples: [...positiveExamples, ...distractorExamples],
};

// ---------------------------------------------------------------------------
// Vitest eval suites
// Each runDataset call registers a describe block gated on RUN_LLM_EVALS.
// Positives and distractors use different evaluators and passing thresholds.
// ---------------------------------------------------------------------------

runDataset(
  { name: "detection-rule-management: positives", examples: positiveExamples },
  {
    "skill-activation": skillActivation,
    "tool-selection": toolSelection,
  },
  { passingScore: 0.8 }
);

runDataset(
  { name: "detection-rule-management: distractors", examples: distractorExamples },
  {
    "negative-activation": negativeActivation,
  },
  { passingScore: 1.0 } // 100% — any false positive is a regression
);
