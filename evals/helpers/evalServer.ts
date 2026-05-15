/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { vi } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerDetectionRuleTools } from "../../src/tools/detection-rules.js";
import { registerMigrationTools } from "../../src/tools/migration.js";
import type { MigrationsService } from "../../src/elastic/service/migrationsService.js";
import type { RulesService } from "../../src/elastic/service/rulesService.js";

/**
 * Creates a real McpServer backed by stub services for eval runs.
 *
 * Only the methods called by the two model-facing tools (`migrate-rules`,
 * `manage-rules`) are stubbed — other service methods are left as bare
 * `vi.fn()` since they won't be invoked during skill-routing evals.
 *
 * A fresh server must be created for each `runMcpHostLoop` call because
 * the InMemoryTransport pair is torn down after every run.
 *
 * No live Elastic cluster is required — skill-routing evaluators only
 * inspect which tools the LLM called, not what those tools returned.
 */
export function createEvalServer(): McpServer {
  const server = new McpServer({ name: "eval-server", version: "0.0.0" });

  const migrationsService = {
    listMigrations: vi.fn().mockResolvedValue([]),
  } as unknown as MigrationsService;

  const rulesService = {
    findRules: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  } as unknown as RulesService;

  registerMigrationTools(server, { migrationsService });
  registerDetectionRuleTools(server, { rulesService });

  return server;
}
