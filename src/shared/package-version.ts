/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

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
    } catch {}
  }

  return fallback;
}
