/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * End-to-end eval spec for the automatic-migration skill.
 *
 * Proves skill-activation and boundary discrimination against the
 * automatic-migration proof dataset. Run via:
 *
 *   npm run test:evals
 *
 * This suite is skipped in regular `npm test` because runDataset wraps
 * everything in `describe.skipIf(!process.env.RUN_LLM_EVALS)`.
 *
 * Gate summary:
 *   positives   — skill-activation + tool-selection ≥ 80%
 *   distractors — negative-activation = 100% (any false positive is a regression)
 */

import { runDataset } from "./runner.js";
import {
  positiveExamples,
  distractorExamples,
} from "./datasets/automatic-migration.dataset.js";
import { skillActivation } from "./evaluators/skill-activation.js";
import { negativeActivation } from "./evaluators/negative-activation.js";
import { toolSelection } from "./evaluators/tool-selection.js";

runDataset(
  {
    name: "automatic-migration: positives",
    examples: positiveExamples,
  },
  {
    "skill-activation": skillActivation,
    "tool-selection": toolSelection,
  },
  { passingScore: 0.8 }
);

runDataset(
  {
    name: "automatic-migration: distractors",
    examples: distractorExamples,
  },
  {
    "negative-activation": negativeActivation,
  },
  { passingScore: 1.0 } // 100% — any false positive is a regression
);
