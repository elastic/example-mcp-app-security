/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { listTestAssets, loadMacosCatalog } from "../catalog/catalog.js";
import { textResult } from "./atomic-run.js";

const catalogSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("summary"),
    atomics_path: z.string().min(1),
  }),
  z.object({
    action: z.literal("get"),
    atomics_path: z.string().min(1),
    test_guid: z.string().uuid(),
  }),
  z.object({
    action: z.literal("assets"),
    atomics_path: z.string().min(1),
    test_guid: z.string().uuid(),
  }),
  z.object({
    action: z.literal("list"),
    atomics_path: z.string().min(1),
    technique_id: z.string().optional(),
    executor: z.string().optional(),
    risk_flag: z.string().optional(),
    query: z.string().optional(),
    offset: z.number().int().min(0).default(0),
    limit: z.number().int().min(1).max(200).default(50),
  }),
]);

const catalogToolSchema = z.object({
  action: z.enum(["summary", "get", "assets", "list"]),
  atomics_path: z.string().min(1),
  test_guid: z.string().uuid().optional(),
  technique_id: z.string().optional(),
  executor: z.string().optional(),
  risk_flag: z.string().optional(),
  query: z.string().optional(),
  offset: z.number().int().min(0).default(0),
  limit: z.number().int().min(1).max(200).default(50),
});

export function registerAtomicCatalogTool(server: McpServer): void {
  server.registerTool(
    "macos-atomic-catalog",
    {
      title: "Atomic Red Team macOS Catalog",
      description:
        "Read-only parser for a pinned Atomic Red Team atomics directory. Lists only macOS tests, returns immutable definition/catalog digests, and inventories test support files with byte size and SHA-256 so they can be bound into an approved plan.",
      inputSchema: catalogToolSchema,
      annotations: { readOnlyHint: true },
    },
    async (input) => {
      try {
        const parsed = catalogSchema.parse(input);
        const catalog = loadMacosCatalog(parsed.atomics_path);
        if (parsed.action === "summary") {
          const byExecutor: Record<string, number> = {};
          const byRisk: Record<string, number> = {};
          for (const test of catalog.tests) {
            byExecutor[test.executor] = (byExecutor[test.executor] ?? 0) + 1;
            for (const flag of test.risk_flags) byRisk[flag] = (byRisk[flag] ?? 0) + 1;
          }
          return textResult({
            atomics_path: catalog.atomics_path,
            revision: catalog.revision,
            catalog_digest: catalog.catalog_digest,
            macos_test_count: catalog.tests.length,
            skipped_file_count: catalog.skipped_files.length,
            by_executor: byExecutor,
            by_risk: byRisk,
          });
        }
        if (parsed.action === "get") {
          const test = catalog.tests.find((candidate) => candidate.test_guid === parsed.test_guid);
          if (!test) return textResult({ error: "macOS atomic test not found" }, true);
          return textResult({
            revision: catalog.revision,
            catalog_digest: catalog.catalog_digest,
            test,
          });
        }
        if (parsed.action === "assets") {
          const test = catalog.tests.find((candidate) => candidate.test_guid === parsed.test_guid);
          if (!test) return textResult({ error: "macOS atomic test not found" }, true);
          const assets = listTestAssets(catalog, parsed.test_guid);
          return textResult({
            revision: catalog.revision,
            catalog_digest: catalog.catalog_digest,
            test_guid: parsed.test_guid,
            definition_file: test.definition_file,
            asset_count: assets.length,
            assets,
          });
        }
        const needle = parsed.query?.toLowerCase();
        const filtered = catalog.tests.filter((test) => {
          if (parsed.technique_id && test.technique_id !== parsed.technique_id) return false;
          if (parsed.executor && test.executor !== parsed.executor.toLowerCase()) return false;
          if (parsed.risk_flag && !test.risk_flags.includes(parsed.risk_flag)) return false;
          if (
            needle &&
            !`${test.technique_id} ${test.name} ${test.description}`.toLowerCase().includes(needle)
          ) {
            return false;
          }
          return true;
        });
        return textResult({
          revision: catalog.revision,
          catalog_digest: catalog.catalog_digest,
          total: filtered.length,
          offset: parsed.offset,
          tests: filtered.slice(parsed.offset, parsed.offset + parsed.limit),
        });
      } catch (error) {
        return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
      }
    }
  );
}
