/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Coerce an ECS field that may come back as either a scalar or an array (a
 * multi-valued field, common on correlated/network-derived alerts) into a
 * single scalar.
 *
 * Elasticsearch does not enforce single- vs. multi-valued fields at the
 * document level, so the *same* mapped field can be a plain string on one
 * document and a `string[]` on another. Code that expects a scalar (e.g.
 * grouping/sorting by `host.name`) must normalize at the boundary rather than
 * assume the shape declared in a TypeScript type actually holds at runtime.
 *
 * @returns the first element for a non-empty array, `undefined` for an empty
 * array, or the value unchanged if it isn't an array.
 */
export function toScalar<T>(value: T | T[] | undefined): T | undefined {
  if (!Array.isArray(value)) return value;
  return value.length > 0 ? value[0] : undefined;
}
