/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppTool,
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
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://generate-sample-data/mcp-app.html";

const namespaceSchema = z
  .string()
  .optional()
  .describe(
    "Kibana space ID to seed/clean data in (default: 'default'). Determines the Security alerts index the generator writes to (`.alerts-security.alerts-<ns>`) and the space detection rules are created in."
  );

const _pendingRuleIdMap: Record<string, string> = {};

/** Services the sample-data tools depend on (default cluster only, for now). */
export interface SampleDataToolDeps {
  readonly sampleDataService: SampleDataService;
}

export function registerSampleDataTools(
  server: McpServer,
  deps: SampleDataToolDeps
) {
  const { sampleDataService } = deps;
  registerAppTool(
    server,
    "generate-sample-data",
    {
      title: "Generate Sample Security Data",
      description: `Open the interactive sample data generator UI. The user selects attack scenarios (${SCENARIO_NAMES.join(", ")}), event count, and triggers generation from the UI — do NOT ask the user which scenario to generate, just call this tool immediately with no arguments.`,
      inputSchema: { namespace: namespaceSchema },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ namespace }) => {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ status: "ready", scenarios: SCENARIO_NAMES, params: { namespace } }) }],
      };
    }
  );

  registerAppTool(
    server,
    "generate-scenario",
    {
      title: "Generate Scenario",
      description: "Generate a specific attack scenario",
      inputSchema: {
        scenario: z.enum(SCENARIO_NAMES as [string, ...string[]]),
        count: z.number().optional(),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ scenario, count, namespace }) => {
      const args: Parameters<SampleDataService["generateSampleData"]>[0] = {
        scenario: scenario as ScenarioName,
        count,
        namespace,
      };
      if (Object.keys(_pendingRuleIdMap).length > 0) {
        args.ruleIdMap = _pendingRuleIdMap;
      }
      const result = await sampleDataService.generateSampleData(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "cleanup-sample-data",
    {
      title: "Cleanup Sample Data",
      description: "Remove all generated sample data",
      inputSchema: { namespace: namespaceSchema },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ namespace }) => {
      const result = await sampleDataService.cleanupSampleData(namespace);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "create-rules-for-scenario",
    {
      title: "Create Detection Rules for Scenario",
      description: "Create real Kibana detection rules that correspond to a sample data scenario. Rules are created disabled.",
      inputSchema: {
        scenario: z.enum(SCENARIO_NAMES as [string, ...string[]]),
        namespace: namespaceSchema,
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ scenario, namespace }) => {
      const defs = SCENARIO_RULES[scenario as ScenarioName] || [];
      if (defs.length === 0) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ created: 0, ruleIds: [], message: "No rule definitions for this scenario" }) }] };
      }
      const result = await sampleDataService.createRulesForScenario(
        scenario as ScenarioName,
        namespace
      );
      Object.assign(_pendingRuleIdMap, result.ruleIdMap);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "check-existing-sample-data",
    {
      title: "Check Existing Sample Data",
      description: "Check if sample data already exists in the cluster",
      inputSchema: { namespace: namespaceSchema },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ namespace }) => {
      try {
        const result = await sampleDataService.checkExistingData(namespace);
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
