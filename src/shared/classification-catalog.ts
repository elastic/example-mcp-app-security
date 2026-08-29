/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { IndexAffordances } from "./environment-profile.js";

/**
 * The classification catalog is the memory of the human-in-the-loop loop: once an
 * analyst (or an LLM whose verdict the analyst approved) confirms what an index
 * *is* and what workers may do with it, that verdict is stored keyed by the
 * index's shape {@link signatureFor}. On a later run the heuristic still builds
 * the skeleton, but any index whose shape matches an approved entry adopts the
 * sticky verdict instead — so approvals persist and reruns are deterministic,
 * while a material shape change (new fields) invalidates the key and re-surfaces
 * the index for review.
 */

export const CATALOG_VERSION = 1 as const;

export interface CatalogEntry {
  /** Shape signature this verdict applies to (the map key, duplicated for portability). */
  readonly signature: string;
  /** Index name at approval time — for human readability; not part of the key. */
  readonly name: string;
  /** The approved capabilities. `source` is normally `"human"` (or `"llm"` if auto-accepted). */
  readonly affordances: IndexAffordances;
  /** ISO timestamp of approval. */
  readonly approved_at: string;
  /** Optional analyst note explaining the correction. */
  readonly note?: string;
}

export interface CatalogData {
  readonly version: typeof CATALOG_VERSION;
  readonly entries: Record<string, CatalogEntry>;
}

/** Pluggable store so the service can be tested without touching the filesystem. */
export interface ClassificationCatalog {
  load(): Promise<CatalogData>;
  save(data: CatalogData): Promise<void>;
}

export function emptyCatalog(): CatalogData {
  return { version: CATALOG_VERSION, entries: {} };
}

/**
 * Deterministic shape fingerprint: index name + the sorted set of huntable field
 * names. Deliberately excludes volatile facts (doc counts, sizes, timestamps) so
 * the key is stable across runs, but tracks the field *shape* so genuinely new
 * structure invalidates a stale verdict.
 */
export function signatureFor(name: string, huntableFieldNames: string[]): string {
  const shape = [...new Set(huntableFieldNames)].sort().join(",");
  return createHash("sha1").update(`${name}\n${shape}`).digest("hex").slice(0, 16);
}

/**
 * Merge sticky catalog verdicts over a heuristic skeleton. Returns a new
 * affordances object (source preserved from the catalog, typically `"human"`)
 * when an approved entry matches the signature; otherwise the heuristic verdict
 * is returned unchanged.
 */
export function applyCatalog(
  catalog: CatalogData,
  signature: string | undefined,
  heuristic: IndexAffordances
): IndexAffordances {
  if (!signature) return heuristic;
  const entry = catalog.entries[signature];
  return entry ? entry.affordances : heuristic;
}

/** JSON-file-backed catalog. Missing/corrupt file reads as empty (fail-open). */
export class FileClassificationCatalog implements ClassificationCatalog {
  constructor(private readonly path: string) {}

  async load(): Promise<CatalogData> {
    try {
      const raw = await readFile(this.path, "utf8");
      const parsed = JSON.parse(raw) as CatalogData;
      if (parsed?.version === CATALOG_VERSION && parsed.entries) return parsed;
      return emptyCatalog();
    } catch {
      return emptyCatalog();
    }
  }

  async save(data: CatalogData): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    await writeFile(this.path, JSON.stringify(data, null, 2) + "\n", "utf8");
  }
}
