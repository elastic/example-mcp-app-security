/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { LlmProvider } from "./types.js";
import { AnthropicProvider } from "./anthropic.js";
import { OpenAiProvider } from "./openai.js";

/**
 * Returns the default LLM provider by inspecting environment variables.
 *
 * Priority order:
 *   1. ANTHROPIC_API_KEY → AnthropicProvider (claude-haiku-4-5-20251001)
 *   2. OPENAI_API_KEY    → OpenAiProvider / LiteLLM proxy / Ollama (gpt-4o-mini default)
 *
 * Set LITELLM_BASE_URL alongside OPENAI_API_KEY to route through a LiteLLM
 * proxy, e.g. to reach Claude via the OpenAI-compatible endpoint. Set
 * OPENAI_MODEL to override the chat model (e.g. `qwen2.5:32b-instruct-q4_K_M`
 * when proxying through Ollama at `http://localhost:11434/v1`).
 */
export function createDefaultLlmProvider(): LlmProvider {
  if (process.env.ANTHROPIC_API_KEY) {
    return new AnthropicProvider();
  }
  if (process.env.OPENAI_API_KEY) {
    return new OpenAiProvider({
      model: process.env.OPENAI_MODEL,
      baseURL: process.env.LITELLM_BASE_URL,
    });
  }
  throw new Error(
    "No LLM provider configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY " +
      "before running evals (npm run test:evals)."
  );
}
