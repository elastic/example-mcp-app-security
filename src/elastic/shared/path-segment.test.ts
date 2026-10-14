/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import { pathSegment } from "./path-segment.js";

/** Path axios sends once it has resolved `url` against a base URL. */
function resolvedPath(url: string): string {
  const parsed = new URL(`https://es.example.com${url}`);
  return parsed.pathname + parsed.search;
}

describe("pathSegment", () => {
  it.each([
    "1e4c051b-401d-4bfe-8888-ef637561c8eb",
    ".internal.alerts-security.alerts-default-000001",
    ".alerts-security.alerts-*",
  ])("leaves %s unchanged", (value) => {
    expect(pathSegment(value)).toBe(value);
  });

  it.each([
    ["a/b", "a%2Fb"],
    ["a?b", "a%3Fb"],
    ["a#b", "a%23b"],
    ["../x", "..%2Fx"],
    ["%2e%2e", "%252e%252e"],
    ["a\\b", "a%5Cb"],
    ["<logs-{now/d}>", "%3Clogs-%7Bnow%2Fd%7D%3E"],
  ])("encodes %j as a single segment", (value, encoded) => {
    expect(pathSegment(value)).toBe(encoded);
    expect(resolvedPath(`/${pathSegment(value)}/_search`)).toBe(
      `/${encoded}/_search`
    );
  });

  it("encodes commas, which Elasticsearch decodes back into an index list", () => {
    expect(pathSegment("logs-*,.alerts-security*")).toBe(
      "logs-*%2C.alerts-security*"
    );
  });

  it.each(["", ".", ".."])("rejects %j", (value) => {
    expect(() => pathSegment(value)).toThrowError(/Invalid path segment/);
  });
});
