/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, expect, it } from "vitest";
import {
  createMcpAppBootstrap,
  inspectMcpAppBootstrapResult,
  type SampleDataBootstrapPayload,
} from "./mcp-app-bootstrap.js";

describe("inspectMcpAppBootstrapResult", () => {
  it("ignores ordinary tool results", () => {
    const result = inspectMcpAppBootstrapResult({
      content: [{ type: "text", text: JSON.stringify({ ok: true }) }],
    });
    expect(result).toEqual({ status: "not_bootstrap" });
  });

  it("returns a ready state for a valid bootstrap envelope", () => {
    const result = inspectMcpAppBootstrapResult({
      content: [
        {
          type: "text",
          text: JSON.stringify(
            createMcpAppBootstrap("sample-data", {
              scenarios: ["ransomware-kill-chain"],
              existingData: {
                totalDocs: 1,
                totalAlerts: 2,
                existingRules: 3,
                byScenario: {},
              },
            }),
          ),
        },
      ],
    });
    expect(result.status).toBe("ready");
    if (result.status !== "ready") {
      throw new Error("Expected ready bootstrap result");
    }
    expect(result.envelope.viewId).toBe("sample-data");
    if (result.envelope.viewId !== "sample-data") {
      throw new Error("Expected sample-data bootstrap");
    }
    expect(
      (result.envelope.payload as SampleDataBootstrapPayload).existingData.totalDocs,
    ).toBe(1);
  });

  it("surfaces an invalid viewId as an error", () => {
    const result = inspectMcpAppBootstrapResult({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            kind: "mcp_app_bootstrap",
            viewId: "bogus",
            payload: {},
          }),
        },
      ],
    });
    expect(result.status).toBe("error");
    if (result.status !== "error") {
      throw new Error("Expected bootstrap error");
    }
    expect(result.reason).toContain("viewId");
  });

  it("surfaces a missing payload as an error", () => {
    const result = inspectMcpAppBootstrapResult({
      content: [
        {
          type: "text",
          text: JSON.stringify({
            kind: "mcp_app_bootstrap",
            viewId: "alert-triage",
          }),
        },
      ],
    });
    expect(result.status).toBe("error");
    if (result.status !== "error") {
      throw new Error("Expected bootstrap error");
    }
    expect(result.reason).toContain("missing its payload body");
  });
});
