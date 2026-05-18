/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createServer } from "../src/server.js";
import type { Trajectory, ToolCall } from "./types.js";
import type { LlmProvider, LlmMessage } from "./llm/types.js";
import { createDefaultLlmProvider } from "./llm/index.js";

/** Maximum LLM → tool-call turns before halting to prevent runaway evals. */
const MAX_TURNS = 8;

/**
 * Returns true when an MCP tool should be exposed to the LLM.
 *
 * Mirrors the MCP host visibility contract — tools marked
 * `_meta.ui.visibility: ["app"]` (without `"model"`) are invoked exclusively
 * by an MCP app via `app.callServerTool()`. Real hosts (Claude Desktop,
 * Cursor) hide those from the LLM; the eval harness must do the same to
 * match what the model actually sees in production.
 */
function isVisibleToModel(tool: { _meta?: unknown }): boolean {
  const meta = tool._meta as
    | { ui?: { visibility?: readonly string[] } }
    | undefined;
  const visibility = meta?.ui?.visibility;
  if (!visibility || visibility.length === 0) return true;
  if (visibility.includes("model")) return true;
  return !visibility.includes("app");
}

export interface HostLoopOptions {
  /**
   * Pre-built MCP server to test against.
   *
   * Pass a server constructed with mocked services for dataset-level evals
   * that don't need a live cluster. Omit to use `createServer()`, which reads
   * CLUSTERS_JSON / CLUSTERS_FILE and requires a real Elastic cluster.
   *
   * Each call to `runMcpHostLoop` should receive a **fresh** server instance;
   * reusing a connected server across calls is not supported.
   */
  server?: McpServer;
  /**
   * LLM provider used to simulate the MCP host making tool-call decisions.
   * Defaults to auto-selecting from ANTHROPIC_API_KEY / OPENAI_API_KEY.
   */
  llm?: LlmProvider;
  /**
   * Maximum number of LLM→tool-call turns per run.
   * Defaults to MAX_TURNS (8).
   */
  maxTurns?: number;
  /**
   * Optional system prompt prepended to the message history.
   *
   * Real MCP hosts (Claude Desktop, Cursor) inject a host-level system prompt
   * that constrains tool selection, response shape, and confirmation flow.
   * Without one, the harness measures raw model-vs-tools behavior, which can
   * over- or under-report activation depending on the model family. Use this
   * to pin behavior to what the production host will instruct, or to swap in
   * a SKILL.md body when testing skill-driven flows.
   *
   * Pass a non-empty string. Empty strings are ignored to keep behavior
   * identical to omitting the option.
   */
  systemPrompt?: string;
}

/**
 * Simulates one MCP host loop run entirely in-process.
 *
 * Architecture:
 *   LLM ↔ Client ↔─InMemoryTransport─↔ McpServer ↔ (ES / Kibana clients)
 *
 * The function:
 *   1. Wires a fresh Client to the server via InMemoryTransport.
 *   2. Lists available MCP tools and hands them to the LLM as tool definitions.
 *   3. Loops up to `maxTurns` times:
 *        a. Asks the LLM for the next assistant turn.
 *        b. If the LLM emits tool calls, executes each via client.callTool().
 *        c. Records every call in the trajectory.
 *        d. Feeds results back into the message history.
 *        e. Breaks when the LLM emits no tool calls (task complete).
 *   4. Closes the client and returns the trajectory.
 */
export async function runMcpHostLoop(
  input: string,
  {
    server,
    llm,
    maxTurns = MAX_TURNS,
    systemPrompt,
  }: HostLoopOptions = {}
): Promise<Trajectory> {
  const resolvedServer = server ?? createServer();
  const resolvedLlm = llm ?? createDefaultLlmProvider();

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await resolvedServer.connect(serverTransport);

  const client = new Client({ name: "eval-host", version: "1.0.0" });
  await client.connect(clientTransport);

  try {
    const { tools: mcpTools } = await client.listTools();
    // Strip app-only tools — they're invoked by the React workbench via
    // `app.callServerTool()` and a real MCP host (Claude Desktop, Cursor)
    // hides them from the LLM by inspecting `_meta.ui.visibility`. Without
    // this filter the model sees `find-rules`, `start-translation`,
    // `install-rules`, etc. as alternatives to the model-facing entry
    // points and the activation rate collapses on smaller models.
    const toolDefs = mcpTools.filter(isVisibleToModel).map((t) => ({
      name: t.name,
      description: t.description ?? "",
      parameters: t.inputSchema as Record<string, unknown>,
    }));

    const messages: LlmMessage[] = [];
    if (systemPrompt && systemPrompt.trim().length > 0) {
      messages.push({ role: "system", content: systemPrompt });
    }
    messages.push({ role: "user", content: input });
    const trajectory: Trajectory = [];

    for (let turn = 0; turn < maxTurns; turn++) {
      const response = await resolvedLlm.chat(messages, toolDefs);
      messages.push(response);

      if (!response.tool_calls || response.tool_calls.length === 0) {
        // LLM chose not to call a tool — simulation complete.
        break;
      }

      for (const toolCall of response.tool_calls) {
        const toolName = toolCall.function.name;
        let toolArgs: Record<string, unknown>;
        try {
          toolArgs = JSON.parse(toolCall.function.arguments) as Record<
            string,
            unknown
          >;
        } catch {
          // Malformed JSON from the LLM; record the call with empty args
          // so the trajectory evaluator can detect the failure.
          toolArgs = {};
        }

        const result = await client.callTool({
          name: toolName,
          arguments: toolArgs,
        });

        const record: ToolCall = {
          tool: toolName,
          args: toolArgs,
          result: result.content,
        };
        trajectory.push(record);

        // Feed the tool result back so the LLM can reason about it.
        messages.push({
          role: "tool",
          content: JSON.stringify(result.content),
          tool_call_id: toolCall.id,
        });
      }
    }

    return trajectory;
  } finally {
    // Closing the client also closes clientTransport, which triggers
    // serverTransport.onclose() — the InMemoryTransport linked pair
    // tears down cleanly without needing an explicit server.close().
    await client.close();
  }
}
