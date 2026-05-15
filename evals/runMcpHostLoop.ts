/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Trajectory } from "./types.js";

/**
 * Simulates one MCP host loop turn using the SDK's InMemoryTransport and
 * returns the ordered sequence of tool calls the LLM made.
 *
 * Full implementation lands in the next commit; this stub satisfies the
 * import so runner.ts type-checks now.
 */
export async function runMcpHostLoop(_input: string): Promise<Trajectory> {
  throw new Error("runMcpHostLoop is not yet implemented");
}
