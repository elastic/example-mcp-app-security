/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Resolve the `version` field of the `package.json` nearest to the
 * calling module.
 *
 * Pass `import.meta.url` from the caller. The lookup searches the
 * module's directory and its immediate parent — enough to cover both
 * the `dist/` (compiled server build) and repo-root (esbuild bundle
 * for `.mcpb`) layouts the MCP App ships in.
 *
 * Returns `fallback` if no readable, parseable `package.json` with a
 * truthy `version` field is found, or if `moduleUrl` cannot be
 * resolved to a filesystem path. Never throws — callers use this at
 * startup for telemetry context, where a missing version must not
 * abort the process.
 */
export function readPackageVersion(
  moduleUrl: string,
  fallback = "0.0.0",
): string {
  let here: string;
  try {
    here = dirname(fileURLToPath(moduleUrl));
  } catch {
    return fallback;
  }

  for (const candidate of [
    join(here, "package.json"),
    join(here, "..", "package.json"),
  ]) {
    try {
      const raw = readFileSync(candidate, "utf8");
      const parsed = JSON.parse(raw) as { version?: string };
      if (parsed.version) return parsed.version;
    } catch {
      // try next candidate
    }
  }

  return fallback;
}
