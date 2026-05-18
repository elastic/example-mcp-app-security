/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/** A single tool the LLM may call, described in JSON Schema. */
export interface LlmToolDefinition {
  name: string;
  description: string;
  /** JSON Schema object describing the tool's input parameters. */
  parameters: Record<string, unknown>;
}

/** One tool invocation requested by the LLM in an assistant turn. */
export interface LlmToolCallRequest {
  id: string;
  type: "function";
  function: {
    name: string;
    /** JSON-encoded argument object. */
    arguments: string;
  };
}

/**
 * Discriminated union covering every role that can appear in a chat thread.
 * Shaped after the OpenAI chat messages API so a single interface works for
 * both the OpenAI and Anthropic adapters (and any LiteLLM proxy in between).
 *
 * Anthropic note: Anthropic's HTTP API takes the system prompt as a
 * top-level `system: string` parameter on `messages.create`, not inside
 * the messages array. The adapter extracts `system`-roled messages from
 * the union and passes them via that parameter — this discriminant only
 * dictates the SHAPE the harness uses internally.
 */
export type LlmMessage =
  | { role: "system"; content: string }
  | { role: "user"; content: string }
  | {
      role: "assistant";
      content: string | null;
      tool_calls?: LlmToolCallRequest[];
    }
  | { role: "tool"; content: string; tool_call_id: string };

/** Narrowed assistant message — what LlmProvider.chat() must return. */
export type AssistantMessage = Extract<LlmMessage, { role: "assistant" }>;

/**
 * Minimal provider contract every LLM adapter must satisfy.
 * The interface is intentionally thin: give it a message history + tool
 * catalogue, get back the next assistant turn (possibly with tool calls).
 */
export interface LlmProvider {
  chat(
    messages: LlmMessage[],
    tools: LlmToolDefinition[]
  ): Promise<AssistantMessage>;
}
