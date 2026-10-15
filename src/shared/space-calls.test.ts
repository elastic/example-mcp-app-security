/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect } from "vitest";
import {
  parseListSpacesResult,
  parseSpaceCountsResult,
  spaceDisplayName,
  withSpaceArg,
} from "./space-calls.js";

function text(data: unknown) {
  return { content: [{ type: "text", text: JSON.stringify(data) }] };
}

describe("withSpaceArg", () => {
  it("adds the active space when it differs from the configured one", () => {
    expect(withSpaceArg({ name: "poll-alerts", arguments: { days: 7 } }, "soc", "default")).toEqual({
      name: "poll-alerts",
      arguments: { days: 7, space: "soc" },
    });
  });

  it("creates arguments when the call has none", () => {
    expect(withSpaceArg({ name: "list-ai-connectors" }, "soc", "default")).toEqual({
      name: "list-ai-connectors",
      arguments: { space: "soc" },
    });
  });

  it("leaves calls alone while the active space is the configured one", () => {
    const params = { name: "poll-alerts", arguments: { days: 7 } };
    expect(withSpaceArg(params, "default", "default")).toBe(params);
  });

  it("leaves calls alone before spaces are known", () => {
    const params = { name: "poll-alerts", arguments: {} };
    expect(withSpaceArg(params, "", "")).toBe(params);
  });

  it.each(["report-analytics-event", "list-spaces", "count-by-space"])(
    "never scopes %s",
    (name) => {
      const params = { name, arguments: { kind: "alerts" } };
      expect(withSpaceArg(params, "soc", "default")).toBe(params);
    },
  );

  it("never overrides an explicit space", () => {
    const params = { name: "poll-alerts", arguments: { space: "default" } };
    expect(withSpaceArg(params, "soc", "default")).toBe(params);
  });

  it("does not mutate the caller's arguments", () => {
    const args = { days: 7 };
    withSpaceArg({ name: "poll-alerts", arguments: args }, "soc", "default");
    expect(args).toEqual({ days: 7 });
  });
});

describe("parseListSpacesResult", () => {
  it("parses spaces and drops malformed entries", () => {
    expect(
      parseListSpacesResult(
        text({
          configured: "default",
          spaces: [
            { id: "default", name: "Default", color: "#00bfb3", initials: "D" },
            { id: "soc", name: "SOC", color: 3 },
            { name: "no id" },
          ],
        }),
      ),
    ).toEqual({
      configured: "default",
      spaces: [
        { id: "default", name: "Default", color: "#00bfb3", initials: "D" },
        { id: "soc", name: "SOC" },
      ],
    });
  });

  it("returns null for errors and unexpected shapes", () => {
    expect(parseListSpacesResult({ isError: true, ...text({ configured: "d", spaces: [] }) })).toBeNull();
    expect(parseListSpacesResult(text({ spaces: [] }))).toBeNull();
    expect(parseListSpacesResult({ content: [{ type: "text", text: "not json" }] })).toBeNull();
    expect(parseListSpacesResult(undefined)).toBeNull();
  });
});

describe("parseSpaceCountsResult", () => {
  it("keeps numeric counts only", () => {
    expect(
      parseSpaceCountsResult(text({ kind: "alerts", days: 7, counts: { soc: 4, bad: "x", zero: 0 } })),
    ).toEqual({ kind: "alerts", days: 7, counts: { soc: 4, zero: 0 } });
  });

  it("returns null for errors and unknown kinds", () => {
    expect(parseSpaceCountsResult({ isError: true, ...text({ kind: "alerts", counts: {} }) })).toBeNull();
    expect(parseSpaceCountsResult(text({ kind: "cases", counts: {} }))).toBeNull();
  });
});

describe("spaceDisplayName", () => {
  it("falls back to the id for unknown spaces", () => {
    const spaces = [{ id: "soc", name: "SOC" }];
    expect(spaceDisplayName(spaces, "soc")).toBe("SOC");
    expect(spaceDisplayName(spaces, "gone")).toBe("gone");
  });
});
