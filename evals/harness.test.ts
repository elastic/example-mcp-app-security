/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Mock-based harness integration test.
 *
 * Exercises the full eval pipeline (runMcpHostLoop → evaluators) with a
 * deterministic mock LLM, proving the harness mechanics satisfy both dataset
 * gate requirements without requiring real API keys.
 *
 * No API keys needed — runs as part of `npm run test:evals`.
 * Gate thresholds match the LLM eval specs:
 *   positives   — skill-activation + tool-selection ≥ 80%
 *   distractors — negative-activation = 100%
 */

import { describe, it, expect } from "vitest";
import { runMcpHostLoop } from "./runMcpHostLoop.js";
import { skillActivation } from "./evaluators/skill-activation.js";
import { toolSelection } from "./evaluators/tool-selection.js";
import { negativeActivation } from "./evaluators/negative-activation.js";
import {
  positiveExamples as drmPositives,
  distractorExamples as drmDistractors,
} from "./datasets/detection-rule-management.dataset.js";
import {
  positiveExamples as amPositives,
  distractorExamples as amDistractors,
} from "./datasets/automatic-migration.dataset.js";
import type {
  LlmProvider,
  AssistantMessage,
  LlmMessage,
} from "./llm/types.js";
import { createEvalServer } from "./helpers/evalServer.js";

// ---------------------------------------------------------------------------
// Gate thresholds — must match the LLM eval specs in *.eval.test.ts
// ---------------------------------------------------------------------------

const POSITIVE_GATE = 0.8;
const DISTRACTOR_GATE = 1.0;

// ---------------------------------------------------------------------------
// Mock LLM implementations
// ---------------------------------------------------------------------------

/**
 * Returns an LLM that calls `toolName` exactly once, then returns plain text.
 * Used for positive examples to simulate correct skill activation.
 */
function makeActivatingLlm(toolName: string): LlmProvider {
  let called = false;
  return {
    async chat(_messages, tools): Promise<AssistantMessage> {
      if (!called && tools.some((t) => t.name === toolName)) {
        called = true;
        return {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_mock_0",
              type: "function" as const,
              function: { name: toolName, arguments: "{}" },
            },
          ],
        };
      }
      return { role: "assistant", content: "Done." };
    },
  };
}

/** Always returns plain text without calling any tool. Used for distractor examples. */
const passiveLlm: LlmProvider = {
  async chat(): Promise<AssistantMessage> {
    return {
      role: "assistant",
      content: "I can help with that directly without additional tools.",
    };
  },
};

// ---------------------------------------------------------------------------
// detection-rule-management harness tests
// ---------------------------------------------------------------------------

describe("eval harness: detection-rule-management positives", () => {
  for (const example of drmPositives) {
    it(`${example.id} — skill-activation + tool-selection ≥ ${POSITIVE_GATE}`, async () => {
      const trajectory = await runMcpHostLoop(example.input, {
        server: createEvalServer(),
        llm: makeActivatingLlm("manage-rules"),
      });

      const activation = await skillActivation(trajectory, example.expected);
      const selection = await toolSelection(trajectory, example.expected);

      if (activation.score !== "N/A") {
        expect(activation.score, `skill-activation: ${activation.reason}`).toBeGreaterThanOrEqual(POSITIVE_GATE);
      }
      if (selection.score !== "N/A") {
        expect(selection.score, `tool-selection: ${selection.reason}`).toBeGreaterThanOrEqual(POSITIVE_GATE);
      }
    });
  }
});

describe("eval harness: detection-rule-management distractors", () => {
  for (const example of drmDistractors) {
    it(`${example.id} — negative-activation = 100%`, async () => {
      const trajectory = await runMcpHostLoop(example.input, {
        server: createEvalServer(),
        llm: passiveLlm,
      });

      const result = await negativeActivation(trajectory, example.expected);
      if (result.score !== "N/A") {
        expect(result.score, `negative-activation: ${result.reason}`).toBe(DISTRACTOR_GATE);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// automatic-migration harness tests
// ---------------------------------------------------------------------------

describe("eval harness: automatic-migration positives", () => {
  for (const example of amPositives) {
    it(`${example.id} — skill-activation + tool-selection ≥ ${POSITIVE_GATE}`, async () => {
      const trajectory = await runMcpHostLoop(example.input, {
        server: createEvalServer(),
        llm: makeActivatingLlm("migrate-rules"),
      });

      const activation = await skillActivation(trajectory, example.expected);
      const selection = await toolSelection(trajectory, example.expected);

      if (activation.score !== "N/A") {
        expect(activation.score, `skill-activation: ${activation.reason}`).toBeGreaterThanOrEqual(POSITIVE_GATE);
      }
      if (selection.score !== "N/A") {
        expect(selection.score, `tool-selection: ${selection.reason}`).toBeGreaterThanOrEqual(POSITIVE_GATE);
      }
    });
  }
});

describe("eval harness: automatic-migration distractors", () => {
  for (const example of amDistractors) {
    it(`${example.id} — negative-activation = 100%`, async () => {
      const trajectory = await runMcpHostLoop(example.input, {
        server: createEvalServer(),
        llm: passiveLlm,
      });

      const result = await negativeActivation(trajectory, example.expected);
      if (result.score !== "N/A") {
        expect(result.score, `negative-activation: ${result.reason}`).toBe(DISTRACTOR_GATE);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// HostLoopOptions.systemPrompt — propagation contract
//
// Real MCP hosts inject a system prompt that constrains tool selection.
// Verify the option flows from `runMcpHostLoop` to the provider's `chat()`
// as a `role: "system"` message, AND that empty / whitespace-only strings
// are dropped so the absence of a system prompt is observable.
// ---------------------------------------------------------------------------

describe("eval harness: systemPrompt propagation", () => {
  /**
   * Captures every `messages` array the provider's `chat()` receives so
   * the test can assert what the harness handed off.
   */
  function makeRecordingLlm(): {
    provider: LlmProvider;
    calls: LlmMessage[][];
  } {
    const calls: LlmMessage[][] = [];
    const provider: LlmProvider = {
      async chat(messages): Promise<AssistantMessage> {
        calls.push([...messages]);
        return { role: "assistant", content: "Done." };
      },
    };
    return { provider, calls };
  }

  it("prepends a system message when systemPrompt is provided", async () => {
    const { provider, calls } = makeRecordingLlm();
    await runMcpHostLoop("Find me my noisy rules", {
      server: createEvalServer(),
      llm: provider,
      systemPrompt: "You are a security analyst. Always call a tool before answering.",
    });

    expect(calls.length).toBeGreaterThanOrEqual(1);
    const firstTurn = calls[0]!;
    expect(firstTurn[0]).toEqual({
      role: "system",
      content: "You are a security analyst. Always call a tool before answering.",
    });
    expect(firstTurn[1]).toEqual({
      role: "user",
      content: "Find me my noisy rules",
    });
  });

  it("does not inject a system message when systemPrompt is omitted", async () => {
    const { provider, calls } = makeRecordingLlm();
    await runMcpHostLoop("Find me my noisy rules", {
      server: createEvalServer(),
      llm: provider,
    });

    expect(calls.length).toBeGreaterThanOrEqual(1);
    const firstTurn = calls[0]!;
    expect(firstTurn[0]?.role).toBe("user");
    expect(firstTurn.some((m) => m.role === "system")).toBe(false);
  });

  it("treats empty / whitespace-only systemPrompt as omitted", async () => {
    for (const prompt of ["", "   ", "\n\t"]) {
      const { provider, calls } = makeRecordingLlm();
      await runMcpHostLoop("Find me my noisy rules", {
        server: createEvalServer(),
        llm: provider,
        systemPrompt: prompt,
      });
      const firstTurn = calls[0]!;
      expect(
        firstTurn.some((m) => m.role === "system"),
        `empty-string systemPrompt (${JSON.stringify(prompt)}) should not inject a system message`
      ).toBe(false);
    }
  });
});
