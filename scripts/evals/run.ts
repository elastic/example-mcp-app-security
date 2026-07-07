/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Lightweight tool-invocation evals against the shared serverless cluster.
 * Complements Vitest unit tests — validates live tool contracts and payloads.
 */

import { createServer } from "../../src/server.js";
import { connectInProcess } from "../../src/test/helpers/integrationServer.js";
import {
  applySharedClusterEnv,
  formatSkipMessage,
  resolveSharedClustersFile,
} from "../e2e/env.js";
import { LIVE_EVAL_SCENARIOS, type EvalScenario } from "./scenarios.js";

function parseToolJson(result: { content?: Array<{ type: string; text?: string }> }): unknown {
  const text = result.content?.find((c) => c.type === "text")?.text;
  if (!text) throw new Error("tool response missing text content");
  return JSON.parse(text);
}

async function runScenario(
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
  scenario: EvalScenario
): Promise<void> {
  const body = await callTool(scenario.tool, scenario.arguments);
  scenario.assert(body);
}

async function main(): Promise<number> {
  if (process.env.MCP_EVALS_SKIP === "1") {
    console.log("MCP evals skipped (MCP_EVALS_SKIP=1)");
    return 0;
  }

  const resolved = resolveSharedClustersFile();
  if (!resolved) {
    console.log(formatSkipMessage().replace("MCP E2E", "MCP evals"));
    return process.env.MCP_E2E_REQUIRED === "1" ? 1 : 0;
  }

  applySharedClusterEnv(resolved);
  console.log(`MCP evals using clusters file (${resolved.source}): ${resolved.clustersFile}`);

  const harness = await connectInProcess(createServer());
  const failures: string[] = [];

  try {
    const callTool = async (name: string, args: Record<string, unknown>) =>
      parseToolJson(await harness.client.callTool({ name, arguments: args }));

    for (const scenario of LIVE_EVAL_SCENARIOS) {
      try {
        await runScenario(callTool, scenario);
        console.log(`PASS ${scenario.id}`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        failures.push(`${scenario.id}: ${msg}`);
        console.error(`FAIL ${scenario.id}: ${msg}`);
      }
    }
  } finally {
    await harness.close();
  }

  if (failures.length > 0) {
    console.error(`MCP evals failed (${failures.length}/${LIVE_EVAL_SCENARIOS.length})`);
    return 1;
  }

  console.log(`MCP EVALS_PASS (${LIVE_EVAL_SCENARIOS.length} scenarios)`);
  return 0;
}

main().catch((err: unknown) => {
  console.error("MCP evals crashed:", err instanceof Error ? err.message : err);
  process.exit(1);
});
