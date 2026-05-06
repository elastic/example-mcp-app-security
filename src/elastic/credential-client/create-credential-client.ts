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

/**
 * The exact placeholder values shipped in our install templates
 * (`.github/cursor-mcp-config.json`, `.env.example`, host setup docs). If a
 * cluster still contains any of these, the user installed the server but
 * never replaced the placeholders — fail loud at startup so they don't
 * silently hit the first tool call against a fake hostname.
 *
 * Hostnames are matched as substrings of the URL so trailing paths /
 * trailing slashes don't matter; API keys are matched case-insensitively
 * against the full string.
 */
const PLACEHOLDER_URL_FRAGMENTS: readonly string[] = [
  "your-cluster.es.cloud.example.com",
  "your-cluster.kb.cloud.example.com",
];
const PLACEHOLDER_API_KEYS: readonly string[] = [
  "your-api-key",
  "your-elasticsearch-api-key",
];

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

      if (PLACEHOLDER_URL_FRAGMENTS.some((p) => c.elasticsearchUrl.includes(p))) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [i, "elasticsearchUrl"],
          message:
            "looks like an unmodified placeholder — replace with your real Elasticsearch URL",
        });
      }
      if (PLACEHOLDER_URL_FRAGMENTS.some((p) => c.kibanaUrl.includes(p))) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [i, "kibanaUrl"],
          message:
            "looks like an unmodified placeholder — replace with your real Kibana URL",
        });
      }
      if (PLACEHOLDER_API_KEYS.includes(c.elasticsearchApiKey.toLowerCase())) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [i, "elasticsearchApiKey"],
          message:
            "looks like an unmodified placeholder — replace with your real Elasticsearch API key",
        });
      }
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

/**
 * Detect the "all-empty placeholder" shape produced by the Claude Desktop
 * (.mcpb) install dialog when the user picks a Clusters File and leaves the
 * inline single-cluster fields blank.
 *
 * The manifest's env templating substitutes empty strings for unset
 * `user_config` values, yielding e.g. `[{"name":"primary",
 * "elasticsearchUrl":"","kibanaUrl":"","elasticsearchApiKey":""}]`. We treat
 * that as "the user didn't fill in inline credentials" rather than a
 * malformed config.
 */
function isEmptyTemplatePlaceholder(raw: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return false;
  }
  if (!Array.isArray(parsed) || parsed.length === 0) return false;
  return parsed.every(
    (c) =>
      c !== null &&
      typeof c === "object" &&
      ((c as Record<string, unknown>).elasticsearchUrl ?? "") === "" &&
      ((c as Record<string, unknown>).kibanaUrl ?? "") === "" &&
      ((c as Record<string, unknown>).elasticsearchApiKey ?? "") === ""
  );
}

function readSource(): RawSource {
  const file = process.env.CLUSTERS_FILE?.trim();
  const rawJson = process.env.CLUSTERS_JSON?.trim();
  const json = rawJson && !isEmptyTemplatePlaceholder(rawJson) ? rawJson : undefined;

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
    "No clusters configured. Either point CLUSTERS_FILE at a JSON file " +
      "describing your cluster(s), or set CLUSTERS_JSON to an inline JSON " +
      "array. In the Claude Desktop install dialog, pick a Clusters File or " +
      "fill in the Elasticsearch URL, Kibana URL, and API key fields."
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
