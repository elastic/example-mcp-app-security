/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import { esRequest } from "./client.js";
import type { IndexInfo, FieldMapping } from "../shared/types.js";

export async function listIndices(pattern?: string): Promise<IndexInfo[]> {
  const target = pattern || "logs-*,.alerts-security*";
  const result = await esRequest<
    { index: string; health: string; status: string; "docs.count": string; "store.size": string }[]
  >(`/_cat/indices/${target}`, {
    params: { format: "json", h: "index,health,status,docs.count,store.size", s: "index" },
  });

  return result.map((r) => ({
    index: r.index,
    health: r.health,
    status: r.status,
    docsCount: r["docs.count"],
    storeSize: r["store.size"],
  }));
}

export async function getMapping(index: string): Promise<FieldMapping> {
  const result = await esRequest<Record<string, { mappings: { properties: FieldMapping } }>>(
    `/${index}/_mapping`
  );

  const firstKey = Object.keys(result)[0];
  if (!firstKey) return {};

  return flattenMapping(result[firstKey].mappings.properties);
}

function flattenMapping(
  properties: Record<string, unknown>,
  prefix = ""
): FieldMapping {
  const result: FieldMapping = {};

  for (const [key, value] of Object.entries(properties)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    const v = value as Record<string, unknown>;

    if (v.properties) {
      Object.assign(result, flattenMapping(v.properties as Record<string, unknown>, fullKey));
    } else {
      result[fullKey] = {
        type: (v.type as string) || "object",
        ...(v.fields ? { fields: v.fields as Record<string, { type: string }> } : {}),
      };
    }
  }

  return result;
}
