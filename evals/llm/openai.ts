/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import OpenAI from "openai";
import type {
  AssistantMessage,
  LlmMessage,
  LlmProvider,
  LlmToolDefinition,
} from "./types.js";

const DEFAULT_MODEL = "gpt-4o-mini";

export interface OpenAiProviderOptions {
  /** Chat model to use. Defaults to gpt-4o-mini. */
  model?: string;
  /**
   * Override the API base URL. Point this at a LiteLLM proxy to route calls
   * through any provider the proxy supports without changing client code.
   */
  baseURL?: string;
  /**
   * API key. Defaults to the OPENAI_API_KEY environment variable, which is
   * the standard OpenAI SDK default.
   */
  apiKey?: string;
}

export class OpenAiProvider implements LlmProvider {
  private readonly client: OpenAI;
  private readonly model: string;

  constructor({
    model = DEFAULT_MODEL,
    baseURL,
    apiKey,
  }: OpenAiProviderOptions = {}) {
    this.model = model;
    this.client = new OpenAI({
      ...(apiKey !== undefined ? { apiKey } : {}),
      ...(baseURL !== undefined ? { baseURL } : {}),
    });
  }

  async chat(
    messages: LlmMessage[],
    tools: LlmToolDefinition[]
  ): Promise<AssistantMessage> {
    const response = await this.client.chat.completions.create({
      model: this.model,
      messages: messages.map(toOaiMessage),
      ...(tools.length > 0 ? { tools: tools.map(toOaiTool) } : {}),
    });

    const choice = response.choices[0];
    if (!choice) {
      throw new Error("OpenAI returned no choices");
    }

    const msg = choice.message;
    return {
      role: "assistant",
      content: msg.content ?? null,
      ...(msg.tool_calls
        ? {
            tool_calls: msg.tool_calls
              .filter(
                (tc): tc is OpenAI.ChatCompletionMessageFunctionToolCall =>
                  tc.type === "function"
              )
              .map((tc) => ({
                id: tc.id,
                type: "function" as const,
                function: {
                  name: tc.function.name,
                  arguments: tc.function.arguments,
                },
              })),
          }
        : {}),
    };
  }
}

function toOaiMessage(msg: LlmMessage): OpenAI.ChatCompletionMessageParam {
  switch (msg.role) {
    case "system":
      return { role: "system", content: msg.content };
    case "user":
      return { role: "user", content: msg.content };
    case "assistant":
      return {
        role: "assistant",
        content: msg.content,
        ...(msg.tool_calls
          ? {
              tool_calls: msg.tool_calls.map((tc) => ({
                id: tc.id,
                type: "function" as const,
                function: {
                  name: tc.function.name,
                  arguments: tc.function.arguments,
                },
              })),
            }
          : {}),
      };
    case "tool":
      return {
        role: "tool",
        content: msg.content,
        tool_call_id: msg.tool_call_id,
      };
  }
}

function toOaiTool(tool: LlmToolDefinition): OpenAI.ChatCompletionTool {
  return {
    type: "function",
    function: {
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
    },
  };
}
