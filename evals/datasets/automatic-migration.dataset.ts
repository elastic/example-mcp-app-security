/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Dataset, Example } from "../types.js";

/**
 * The model-facing entry-point tool registered by the
 * automatic-migration skill (src/tools/migration.ts).
 */
const SKILL_TOOL = "migrate-rules";

// ---------------------------------------------------------------------------
// Positive examples — the LLM should call migrate-rules
// ---------------------------------------------------------------------------

export const positiveExamples: Example[] = [
  {
    id: "am-pos-01",
    input: "I want to migrate my Splunk rules to Elastic Security",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
  {
    id: "am-pos-02",
    input: "Help me upload my SPL bundle and convert the detections",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
  {
    id: "am-pos-03",
    input: "We're onboarding from Splunk — how do I bring our detection rules over?",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
  {
    id: "am-pos-04",
    input: "Start a SIEM migration for our 200 Splunk correlation rules",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
  {
    id: "am-pos-05",
    input: "Convert our detection rules from Splunk to Elastic format",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
  {
    id: "am-pos-06",
    input: "Install the translated rules from my last migration run",
    expected: {
      skill: SKILL_TOOL,
      tools: [SKILL_TOOL],
    },
  },
];

// ---------------------------------------------------------------------------
// Distractor examples — the LLM should NOT call migrate-rules
// ---------------------------------------------------------------------------

export const distractorExamples: Example[] = [
  {
    id: "am-neg-01",
    input: "Show me which detection rules are generating the most false positives",
    expected: {
      // skill is set so negativeActivation knows which tool to check for absence
      skill: SKILL_TOOL,
    },
  },
  {
    id: "am-neg-02",
    input: "Triage the open critical alerts from the last 24 hours",
    expected: {
      skill: SKILL_TOOL,
    },
  },
  {
    id: "am-neg-03",
    input: "Create a threat hunt for lateral movement via PsExec",
    expected: {
      skill: SKILL_TOOL,
    },
  },
  {
    id: "am-neg-04",
    input: "Open a new case for the ransomware incident on host SRVWIN04",
    expected: {
      skill: SKILL_TOOL,
    },
  },
  {
    id: "am-neg-05",
    input: "Run an ES|QL query to find brute-force login attempts in the last hour",
    expected: {
      skill: SKILL_TOOL,
    },
  },
  {
    id: "am-neg-06",
    input: "Generate sample endpoint data so I can test my detection rules",
    expected: {
      skill: SKILL_TOOL,
    },
  },
];

// ---------------------------------------------------------------------------
// Export the full dataset for reference / cross-dataset tooling
// ---------------------------------------------------------------------------

export const automaticMigrationDataset: Dataset = {
  name: "automatic-migration",
  examples: [...positiveExamples, ...distractorExamples],
};
