/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FieldMapping, IndexInfo } from "../../shared/types.js";
import type { IndicesClient } from "../client/indicesClient.js";

const DEFAULT_INDEX_PATTERN = "logs-*,.alerts-security*";

interface IndicesServiceOptions {
  readonly indicesClient: IndicesClient;
}

/**
 * Business logic for index discovery.
 *
 * Resolves the default index pattern, normalises the `_cat/indices` shape
 * into the {@link IndexInfo} domain type, and flattens nested `_mapping`
 * trees into dot-notation {@link FieldMapping} records.
 */
export class IndicesService {
  constructor(private readonly options: IndicesServiceOptions) {}

  /**
   * List indices matching `pattern` (default `logs-*,.alerts-security*`).
   *
   * Returns rows sorted by index name with health, status, doc count, and
   * store size — the exact projection the existing UI expects.
   */
  async listIndices(pattern?: string): Promise<IndexInfo[]> {
    const target = pattern || DEFAULT_INDEX_PATTERN;
    const result = await this.options.indicesClient.catIndices(target, {
      format: "json",
      h: "index,health,status,docs.count,store.size",
      s: "index",
    });

    return result.map((r) => ({
      index: r.index,
      health: r.health,
      status: r.status,
      docsCount: r["docs.count"],
      storeSize: r["store.size"],
    }));
  }

  /**
   * Fetch the field mapping for `index` flattened to dot-notation.
   *
   * Returns `{}` when the response envelope is empty (e.g. unknown index
   * resolution). Inner `properties` sub-trees are recursively walked; leaf
   * nodes preserve their `type` and any multi-field `fields` definition.
   */
  async getMapping(index: string): Promise<FieldMapping> {
    const result = await this.options.indicesClient.getRawMapping(index);

    const firstKey = Object.keys(result)[0];
    if (!firstKey) return {};

    return flattenMapping(result[firstKey].mappings.properties);
  }
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
      Object.assign(
        result,
        flattenMapping(v.properties as Record<string, unknown>, fullKey)
      );
    } else {
      result[fullKey] = {
        type: (v.type as string) || "object",
        ...(v.fields
          ? { fields: v.fields as Record<string, { type: string }> }
          : {}),
      };
    }
  }

  return result;
}
