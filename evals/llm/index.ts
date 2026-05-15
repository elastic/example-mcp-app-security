/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { LlmProvider } from "./types.js";
import { OpenAiProvider } from "./openai.js";

/**
 * Returns the default LLM provider by inspecting environment variables.
 *
 * Priority order:
 *   1. ANTHROPIC_API_KEY → Anthropic adapter (claude-haiku-4-5) — coming soon
 *   2. OPENAI_API_KEY    → OpenAI / LiteLLM proxy (gpt-4o-mini)
 *
 * Set LITELLM_BASE_URL alongside OPENAI_API_KEY to route through a LiteLLM
 * proxy, e.g. to use Claude via the OpenAI-compatible endpoint.
 */
export function createDefaultLlmProvider(): LlmProvider {
  if (process.env.ANTHROPIC_API_KEY) {
    throw new Error(
      "Anthropic LLM adapter not yet implemented (evals/llm/anthropic.ts). " +
        "Use OPENAI_API_KEY instead, or wait for the Anthropic adapter."
    );
  }
  if (process.env.OPENAI_API_KEY) {
    return new OpenAiProvider({
      baseURL: process.env.LITELLM_BASE_URL,
    });
  }
  throw new Error(
    "No LLM provider configured. Set OPENAI_API_KEY (or ANTHROPIC_API_KEY " +
      "once the Anthropic adapter lands) before running evals (npm run test:evals)."
  );
}
