/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import Anthropic from "@anthropic-ai/sdk";
import type {
  AssistantMessage,
  LlmMessage,
  LlmProvider,
  LlmToolDefinition,
} from "./types.js";

const DEFAULT_MODEL = "claude-haiku-4-5-20251001";

/** Max tokens to request from the Anthropic API per turn. */
const MAX_TOKENS = 4096;

export interface AnthropicProviderOptions {
  /** Chat model to use. Defaults to claude-haiku-4-5-20251001. */
  model?: string;
  /**
   * API key. Defaults to the ANTHROPIC_API_KEY environment variable, which is
   * the standard Anthropic SDK default.
   */
  apiKey?: string;
}

export class AnthropicProvider implements LlmProvider {
  private readonly client: Anthropic;
  private readonly model: string;

  constructor({
    model = DEFAULT_MODEL,
    apiKey,
  }: AnthropicProviderOptions = {}) {
    this.model = model;
    this.client = new Anthropic({
      ...(apiKey !== undefined ? { apiKey } : {}),
    });
  }

  async chat(
    messages: LlmMessage[],
    tools: LlmToolDefinition[]
  ): Promise<AssistantMessage> {
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: MAX_TOKENS,
      messages: toAnthropicMessages(messages),
      ...(tools.length > 0 ? { tools: tools.map(toAnthropicTool) } : {}),
    });

    const textBlocks = response.content.filter(
      (c): c is Anthropic.TextBlock => c.type === "text"
    );
    const toolUseBlocks = response.content.filter(
      (c): c is Anthropic.ToolUseBlock => c.type === "tool_use"
    );

    return {
      role: "assistant",
      content: textBlocks.map((b) => b.text).join("") || null,
      ...(toolUseBlocks.length > 0
        ? {
            tool_calls: toolUseBlocks.map((tu) => ({
              id: tu.id,
              type: "function" as const,
              function: {
                name: tu.name,
                // Anthropic returns a parsed object; re-encode to match the
                // OpenAI-style LlmToolCallRequest.function.arguments shape.
                arguments: JSON.stringify(tu.input),
              },
            })),
          }
        : {}),
    };
  }
}

/**
 * Converts OpenAI-style LlmMessage[] to Anthropic MessageParam[].
 *
 * Structural differences from OpenAI:
 *   - Anthropic has no `tool` role. Tool results go as `user` messages with
 *     `tool_result` content blocks.
 *   - Consecutive tool-result messages are merged into a single user message
 *     so the API never receives two adjacent user turns.
 *   - Assistant content is an array of TextBlockParam / ToolUseBlockParam.
 */
function toAnthropicMessages(
  messages: LlmMessage[]
): Anthropic.MessageParam[] {
  const result: Anthropic.MessageParam[] = [];

  for (const msg of messages) {
    if (msg.role === "user") {
      result.push({ role: "user", content: msg.content });
    } else if (msg.role === "assistant") {
      const content: Anthropic.ContentBlockParam[] = [];
      if (msg.content) {
        content.push({ type: "text", text: msg.content });
      }
      for (const tc of msg.tool_calls ?? []) {
        let input: unknown;
        try {
          input = JSON.parse(tc.function.arguments);
        } catch {
          input = {};
        }
        content.push({ type: "tool_use", id: tc.id, name: tc.function.name, input });
      }
      result.push({ role: "assistant", content });
    } else {
      // msg.role === "tool"
      const block: Anthropic.ToolResultBlockParam = {
        type: "tool_result",
        tool_use_id: msg.tool_call_id,
        content: msg.content,
      };

      // Merge into the preceding user message when it already holds
      // tool_result blocks — the Anthropic API rejects two adjacent user turns.
      const prev = result[result.length - 1];
      if (
        prev?.role === "user" &&
        Array.isArray(prev.content) &&
        (prev.content as Anthropic.ContentBlockParam[])[0]?.type ===
          "tool_result"
      ) {
        (prev.content as Anthropic.ContentBlockParam[]).push(block);
      } else {
        result.push({ role: "user", content: [block] });
      }
    }
  }

  return result;
}

function toAnthropicTool(tool: LlmToolDefinition): Anthropic.Tool {
  return {
    name: tool.name,
    description: tool.description,
    input_schema: tool.parameters as Anthropic.Tool.InputSchema,
  };
}
