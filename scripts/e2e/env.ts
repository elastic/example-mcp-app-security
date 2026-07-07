/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const ENV_KEYS = ["MCP_E2E_CLUSTERS_FILE", "CLUSTERS_FILE"] as const;

const DEFAULT_SHARED_PATH = join(homedir(), ".mcp-e2e", "clusters.json");

export interface SharedClusterResolution {
  readonly clustersFile: string;
  readonly source: (typeof ENV_KEYS)[number] | "default-path";
}

/** Resolve the shared serverless cluster credentials file (never commit this path). */
export function resolveSharedClustersFile(): SharedClusterResolution | null {
  for (const key of ENV_KEYS) {
    const raw = process.env[key]?.trim();
    if (raw && existsSync(raw)) {
      return { clustersFile: raw, source: key };
    }
  }
  if (existsSync(DEFAULT_SHARED_PATH)) {
    return { clustersFile: DEFAULT_SHARED_PATH, source: "default-path" };
  }
  return null;
}

/** Apply cluster env for createServer() — clears CLUSTERS_JSON when using a file. */
export function applySharedClusterEnv(resolved: SharedClusterResolution): void {
  process.env.CLUSTERS_FILE = resolved.clustersFile;
  delete process.env.CLUSTERS_JSON;
}

export function formatSkipMessage(): string {
  return [
    "MCP E2E skipped: no shared cluster credentials found.",
    "Set one of:",
    "  MCP_E2E_CLUSTERS_FILE",
    "  CLUSTERS_FILE",
    `Or place credentials at ${DEFAULT_SHARED_PATH}`,
    "See docs/testing-shared-instance.md",
  ].join("\n");
}
