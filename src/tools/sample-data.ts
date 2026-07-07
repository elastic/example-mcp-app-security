/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import {
  SCENARIO_NAMES,
  SCENARIO_RULES,
  type SampleDataService,
  type ScenarioName,
} from "../elastic/service/index.js";
import { createMcpAppBootstrap } from "../shared/mcp-app-bootstrap.js";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import { registerTrackedAppTool } from "./tracked-app-tool.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://generate-sample-data/mcp-app.html";

const _pendingRuleIdMap: Record<string, string> = {};

export interface SampleDataToolDeps {
  readonly sampleDataService: SampleDataService;
  readonly analytics: AnalyticsClient;
}

export function registerSampleDataTools(
  server: McpServer,
  deps: SampleDataToolDeps
) {
  const { sampleDataService, analytics } = deps;
  registerTrackedAppTool(
    analytics,
    server,
    "generate-sample-data",
    {
      title: "Generate Sample Security Data",
      description: `Open the interactive sample data generator UI. The user selects attack scenarios (${SCENARIO_NAMES.join(", ")}), event count, and triggers generation from the UI — do NOT ask the user which scenario to generate, just call this tool immediately with no arguments.`,
      inputSchema: {},
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async () => {
      const existingData = await sampleDataService.checkExistingData();
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(
            createMcpAppBootstrap("sample-data", {
              scenarios: SCENARIO_NAMES,
              existingData,
            }),
          ),
        }],
      };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "generate-scenario",
    {
      title: "Generate Scenario",
      description: "Generate a specific attack scenario",
      inputSchema: {
        scenario: z.enum(SCENARIO_NAMES as [string, ...string[]]),
        count: z.number().optional(),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ scenario, count }) => {
      const args: Parameters<SampleDataService["generateSampleData"]>[0] = {
        scenario: scenario as ScenarioName,
        count,
      };
      if (Object.keys(_pendingRuleIdMap).length > 0) {
        args.ruleIdMap = _pendingRuleIdMap;
      }
      const result = await sampleDataService.generateSampleData(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "cleanup-sample-data",
    {
      title: "Cleanup Sample Data",
      description: "Remove all generated sample data",
      inputSchema: {},
      _meta: { ui: { visibility: ["app"] } },
    },
    async () => {
      const result = await sampleDataService.cleanupSampleData();
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "create-rules-for-scenario",
    {
      title: "Create Detection Rules for Scenario",
      description: "Create real Kibana detection rules that correspond to a sample data scenario. Rules are created disabled.",
      inputSchema: {
        scenario: z.enum(SCENARIO_NAMES as [string, ...string[]]),
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ scenario }) => {
      const defs = SCENARIO_RULES[scenario as ScenarioName] || [];
      if (defs.length === 0) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ created: 0, ruleIds: [], message: "No rule definitions for this scenario" }) }] };
      }
      const result = await sampleDataService.createRulesForScenario(scenario as ScenarioName);
      Object.assign(_pendingRuleIdMap, result.ruleIdMap);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    "check-existing-sample-data",
    {
      title: "Check Existing Sample Data",
      description: "Check if sample data already exists in the cluster",
      inputSchema: {},
      _meta: { ui: { visibility: ["app"] } },
    },
    async () => {
      try {
        const result = await sampleDataService.checkExistingData();
        return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
      } catch {
        return { content: [{ type: "text" as const, text: JSON.stringify({ totalDocs: 0, totalAlerts: 0, byScenario: {} }) }] };
      }
    }
  );

  const viewPath = resolveViewPath("sample-data");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
