/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerEmulationRunTools } from "./emulation-run.js";
import { createEmulationRunStore, planDigest, type EmulationPlan } from "./emulation-run-state.js";
import {
  createMockMcpServer,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import { noopAnalyticsClient } from "../test/helpers/mockAnalytics.js";

describe("registerEmulationRunTools", () => {
  let server: MockMcpServer;
  const dirs: string[] = [];

  afterEach(() => {
    for (const dir of dirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  beforeEach(() => {
    server = createMockMcpServer();
    const baseDir = mkdtempSync(path.join(tmpdir(), "emul-tool-"));
    dirs.push(baseDir);
    registerEmulationRunTools(server as unknown as McpServer, {
      analytics: noopAnalyticsClient,
      store: createEmulationRunStore({ baseDir }),
    });
  });

  it("registers a single model-facing harness tool", () => {
    expect([...server.tools.keys()]).toEqual(["emulation-run"]);
  });

  it("returns stop=true after set_plan so the agent cannot skip HITL", async () => {
    const init = parseToolText<{ run_id: string }>(
      await server.tool("emulation-run").callback({ action: "init", name: "void-blizzard" })
    );
    const plan: EmulationPlan = {
      schema_version: 1,
      run_id: init.run_id,
      mode: "intelligence",
      type: "micro",
      source: { reference: "https://example.invalid/post", kind: "published-url" },
      objective: "Reproduce the reported S3 exfil behavior from a batch-job role",
      scope: { provider: "aws", scope_id: "123456789012", region: "us-east-1" },
      behaviors: [
        {
          id: "list",
          api: "s3:ListBucket",
          actor: "ec2 instance profile",
          target: "prod-analytics",
          expected_outcome: "object listing",
        },
      ],
    };
    const pending = parseToolText<{ stop: boolean; phase: string; allowed_actions: string[] }>(
      await server.tool("emulation-run").callback({
        action: "set_plan",
        run_id: init.run_id,
        plan,
      })
    );
    expect(pending.stop).toBe(true);
    expect(pending.phase).toBe("awaiting_approval");

    const executeTooSoon = parseToolText<{ ok: boolean; error?: string }>(
      await server.tool("emulation-run").callback({
        action: "record_behavior",
        run_id: init.run_id,
        behavior: plan.behaviors[0],
      })
    );
    expect(executeTooSoon.ok).toBe(false);

    const approved = parseToolText<{ phase: string; stop?: boolean }>(
      await server.tool("emulation-run").callback({
        action: "approve",
        run_id: init.run_id,
        plan_digest: planDigest(plan),
      })
    );
    expect(approved.phase).toBe("approved");
    expect(approved.stop).toBeFalsy();
  });
});
