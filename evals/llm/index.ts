/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { LlmProvider } from "./types.js";

/**
 * Returns the default LLM provider by inspecting environment variables.
 *
 * Priority: ANTHROPIC_API_KEY → Anthropic (claude-haiku-4-5)
 *           OPENAI_API_KEY    → OpenAI / LiteLLM proxy (gpt-4o-mini)
 *
 * The concrete adapters (evals/llm/anthropic.ts, evals/llm/openai.ts) are
 * implemented in the next commit; this stub ensures runMcpHostLoop.ts
 * type-checks now and surfaces a clear error at runtime when evals are run
 * before the adapters land.
 */
export function createDefaultLlmProvider(): LlmProvider {
  if (process.env.ANTHROPIC_API_KEY) {
    throw new Error(
      "Anthropic LLM adapter not yet implemented (evals/llm/anthropic.ts). " +
        "It will land in the next commit."
    );
  }
  if (process.env.OPENAI_API_KEY) {
    throw new Error(
      "OpenAI LLM adapter not yet implemented (evals/llm/openai.ts). " +
        "It will land in the next commit."
    );
  }
  throw new Error(
    "No LLM provider configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY " +
      "before running evals (npm run test:evals)."
  );
}
