/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { readFileSync } from "node:fs";
import { z } from "zod";
import type {
  ClusterCredentials,
  ClusterSummary,
  CredentialClient,
} from "./credential-client.js";

const ClusterSchema = z.object({
  name: z.string().min(1),
  elasticsearchUrl: z.url(),
  kibanaUrl: z.url(),
  elasticsearchApiKey: z.string().min(1),
});

const ClustersConfigSchema = z
  .array(ClusterSchema)
  .min(1, "at least one cluster is required")
  .superRefine((clusters, ctx) => {
    const seen = new Set<string>();
    clusters.forEach((c, i) => {
      if (seen.has(c.name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [i, "name"],
          message: `duplicate cluster name: ${c.name}`,
        });
      }
      seen.add(c.name);
    });
  });

interface RawSource {
  readonly raw: string;
  readonly source: string;
}

interface ParsedClusters {
  readonly clusters: readonly ClusterCredentials[];
  readonly defaultName: string;
}

const stripTrailingSlash = (url: string): string => url.replace(/\/$/, "");

function readSource(): RawSource {
  const file = process.env.CLUSTERS_FILE?.trim();
  const json = process.env.CLUSTERS_JSON?.trim();

  if (file && json) {
    console.warn(
      "Both CLUSTERS_FILE and CLUSTERS_JSON are set; preferring CLUSTERS_FILE."
    );
  }

  if (file) {
    try {
      return { raw: readFileSync(file, "utf-8"), source: `CLUSTERS_FILE (${file})` };
    } catch (e) {
      throw new Error(
        `CLUSTERS_FILE: cannot read ${file} — ${(e as Error).message}`
      );
    }
  }
  if (json) {
    return { raw: json, source: "CLUSTERS_JSON" };
  }
  throw new Error(
    "No clusters configured. Set CLUSTERS_JSON or CLUSTERS_FILE in your MCP config."
  );
}

function safeParseJson(raw: string, source: string): unknown {
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw new Error(`${source}: invalid JSON — ${(e as Error).message}`);
  }
}

function parseClusters({ raw, source }: RawSource): ParsedClusters {
  const result = ClustersConfigSchema.safeParse(safeParseJson(raw, source));

  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  • ${i.path.join(".") || "<root>"}: ${i.message}`)
      .join("\n");
    throw new Error(`${source}: invalid clusters config\n${issues}`);
  }

  const clusters = Object.freeze(
    result.data.map((c) =>
      Object.freeze({
        name: c.name,
        elasticsearchUrl: stripTrailingSlash(c.elasticsearchUrl),
        kibanaUrl: stripTrailingSlash(c.kibanaUrl),
        elasticsearchApiKey: c.elasticsearchApiKey,
      })
    )
  );

  return Object.freeze({ clusters, defaultName: clusters[0].name });
}

/**
 * Build a {@link CredentialClient} from `CLUSTERS_FILE` / `CLUSTERS_JSON`.
 *
 * Reads and validates the configuration eagerly. Throws if neither environment
 * variable is set, if the source cannot be read, if the JSON is malformed, or
 * if the schema validation fails — letting the process exit at startup with a
 * clear, actionable error rather than failing on the first tool call.
 */
export function createCredentialClient(): CredentialClient {
  const { clusters, defaultName } = parseClusters(readSource());

  const summary: readonly ClusterSummary[] = Object.freeze(
    clusters.map((c) =>
      Object.freeze({ name: c.name, isDefault: c.name === defaultName })
    )
  );

  return Object.freeze({
    get(name?: string): ClusterCredentials {
      const target = name ?? defaultName;
      const found = clusters.find((c) => c.name === target);
      if (!found) {
        const available = clusters.map((c) => c.name).join(", ");
        throw new Error(
          `Cluster "${target}" not found. Available: ${available}`
        );
      }
      return found;
    },
    list(): readonly ClusterSummary[] {
      return summary;
    },
    defaultName(): string {
      return defaultName;
    },
  });
}
