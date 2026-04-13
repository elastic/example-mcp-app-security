import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppTool,
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import { generateSampleData, cleanupSampleData, createRulesForScenario, checkExistingData, SCENARIO_NAMES, SCENARIO_RULES } from "../elastic/sample-data.js";
import type { ScenarioName } from "../elastic/sample-data.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://generate-sample-data/mcp-app.html";

let _pendingRuleIdMap: Record<string, string> = {};

export function registerSampleDataTools(server: McpServer) {
  registerAppTool(
    server,
    "generate-sample-data",
    {
      title: "Generate Sample Security Data",
      description: `Open the interactive sample data generator UI. The user selects attack scenarios (${SCENARIO_NAMES.join(", ")}), event count, and triggers generation from the UI — do NOT ask the user which scenario to generate, just call this tool immediately with no arguments.`,
      inputSchema: {},
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async () => {
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ status: "ready", scenarios: SCENARIO_NAMES }) }],
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
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ scenario, count }) => {
      const args: Parameters<typeof generateSampleData>[0] = { scenario: scenario as ScenarioName, count };
      if (_pendingRuleIdMap && Object.keys(_pendingRuleIdMap).length > 0) {
        args.ruleIdMap = _pendingRuleIdMap;
      }
      const result = await generateSampleData(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerAppTool(
    server,
    "cleanup-sample-data",
    {
      title: "Cleanup Sample Data",
      description: "Remove all generated sample data",
      inputSchema: {},
      _meta: { ui: { visibility: ["app"] } },
    },
    async () => {
      const result = await cleanupSampleData();
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
      },
      _meta: { ui: { visibility: ["app"] } },
    },
    async ({ scenario }) => {
      const defs = SCENARIO_RULES[scenario] || [];
      if (defs.length === 0) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ created: 0, ruleIds: [], message: "No rule definitions for this scenario" }) }] };
      }
      const result = await createRulesForScenario(scenario as ScenarioName);
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
      inputSchema: {},
      _meta: { ui: { visibility: ["app"] } },
    },
    async () => {
      try {
        const result = await checkExistingData();
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
