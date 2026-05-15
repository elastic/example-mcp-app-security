/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { defineConfig } from "vitest/config";

/**
 * Vitest config for LLM eval suites.  Intentionally separate from the main
 * vitest.config.ts so `npm test` never picks up eval files (and thus never
 * makes LLM calls or requires API keys in a regular dev/CI run).
 *
 * Run via: npm run test:evals
 */
export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    include: ["evals/**/*.{test,spec,eval}.ts", "evals/datasets/**/*.dataset.ts"],
    testTimeout: 120_000,
  },
});
