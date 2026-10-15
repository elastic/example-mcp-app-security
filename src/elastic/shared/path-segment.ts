/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Encode a dynamic value (id, index name, index pattern) as a single URL path
 * segment.
 *
 * Bare `.` / `..` are rejected because axios resolves the URL with
 * `new URL()`, which collapses dot segments. Empty values are rejected
 * because they leave `//` in the path. Commas still work as index
 * separators: Elasticsearch decodes `%2C` before splitting the index list.
 */
export function pathSegment(value: string): string {
  if (value === "" || value === "." || value === "..") {
    throw new Error(`Invalid path segment: ${JSON.stringify(value)}`);
  }
  return encodeURIComponent(value);
}
