/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

import { createServer } from "../../server.js";
import { connectInProcess } from "../helpers/integrationServer.js";
import { noopAnalyticsClient } from "../helpers/mockAnalytics.js";

const SKILLS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../skills"
);

/**
 * Tools the model must never see. MCP hosts (e.g. Claude Code >= 2.1.280)
 * drop `visibility: ["app"]` tools from the model's tool list, so anything
 * added here becomes unreachable from skills and from hosts that don't
 * render the views.
 */
const APP_ONLY_TOOLS = ["report-analytics-event"];

/** Spec default when `_meta.ui.visibility` is omitted. */
const DEFAULT_VISIBILITY = ["model", "app"];

function visibilityOf(tool: Tool): string[] {
  const ui = tool._meta?.ui as { visibility?: string[] } | undefined;
  return ui?.visibility ?? DEFAULT_VISIBILITY;
}

function listSkillMarkdown(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return listSkillMarkdown(full);
    return entry.name.endsWith(".md") ? [full] : [];
  });
}

describe("tool visibility", () => {
  let originalClustersJson: string | undefined;
  let originalClustersFile: string | undefined;
  let tools: Tool[];

  beforeAll(async () => {
    originalClustersJson = process.env.CLUSTERS_JSON;
    originalClustersFile = process.env.CLUSTERS_FILE;
    delete process.env.CLUSTERS_FILE;
    process.env.CLUSTERS_JSON = JSON.stringify([
      {
        name: "primary",
        elasticsearchUrl: "https://es.example.com",
        kibanaUrl: "https://kb.example.com",
        elasticsearchApiKey: "test-key",
      },
    ]);

    const harness = await connectInProcess(
      createServer({ analytics: noopAnalyticsClient })
    );
    try {
      tools = (await harness.client.listTools()).tools;
    } finally {
      await harness.close();
    }
  });

  afterAll(() => {
    if (originalClustersJson === undefined) delete process.env.CLUSTERS_JSON;
    else process.env.CLUSTERS_JSON = originalClustersJson;
    if (originalClustersFile === undefined) delete process.env.CLUSTERS_FILE;
    else process.env.CLUSTERS_FILE = originalClustersFile;
  });

  it("exposes every tool to the model except the UI telemetry hook", () => {
    const hiddenFromModel = tools
      .filter((tool) => !visibilityOf(tool).includes("model"))
      .map((tool) => tool.name)
      .sort();

    expect(hiddenFromModel).toEqual([...APP_ONLY_TOOLS].sort());
  });

  it("keeps every tool callable from the views", () => {
    const hiddenFromApp = tools
      .filter((tool) => !visibilityOf(tool).includes("app"))
      .map((tool) => tool.name);

    expect(hiddenFromApp).toEqual([]);
  });

  it("only points the bundled skills at model-visible tools", () => {
    const registered = new Set(tools.map((tool) => tool.name));
    const modelVisible = new Set(
      tools
        .filter((tool) => visibilityOf(tool).includes("model"))
        .map((tool) => tool.name)
    );
    const referenced = new Set<string>();

    for (const file of listSkillMarkdown(SKILLS_DIR)) {
      const text = fs.readFileSync(file, "utf-8");
      for (const [, name] of text.matchAll(/`([a-z0-9]+(?:-[a-z0-9]+)+)`/g)) {
        if (registered.has(name)) referenced.add(name);
      }
    }

    expect(referenced.size).toBeGreaterThan(0);
    expect([...referenced].filter((name) => !modelVisible.has(name))).toEqual(
      []
    );
  });
});
