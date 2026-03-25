import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerAppTool,
  registerAppResource,
  RESOURCE_MIME_TYPE,
} from "@modelcontextprotocol/ext-apps/server";
import { z } from "zod";
import fs from "fs";
import { generateSampleData, cleanupSampleData, SCENARIO_NAMES } from "../elastic/sample-data.js";
import type { ScenarioName } from "../elastic/sample-data.js";
import { resolveViewPath } from "./view-path.js";

const RESOURCE_URI = "ui://generate-sample-data/mcp-app.html";

export function registerSampleDataTools(server: McpServer) {
  registerAppTool(
    server,
    "generate-sample-data",
    {
      title: "Generate Sample Security Data",
      description: `Generate ECS-compliant security events and synthetic alerts for demos and testing. Available scenarios: ${SCENARIO_NAMES.join(", ")}. Generates process events, network events, CloudTrail logs, Okta events, and matching alerts.`,
      inputSchema: {
        scenario: z
          .enum(SCENARIO_NAMES as [string, ...string[]])
          .optional()
          .describe("Attack scenario to generate (omit for all)"),
        count: z.number().optional().describe("Number of events per scenario (default: 50)"),
      },
      _meta: { ui: { resourceUri: RESOURCE_URI } },
    },
    async ({ scenario, count }) => {
      const result = await generateSampleData({
        scenario: scenario as ScenarioName | undefined,
        count,
      });
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result) }],
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
      const result = await generateSampleData({ scenario: scenario as ScenarioName, count });
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

  const viewPath = resolveViewPath("sample-data");
  registerAppResource(server, RESOURCE_URI, RESOURCE_URI, { mimeType: RESOURCE_MIME_TYPE }, async () => {
    const html = fs.readFileSync(viewPath, "utf-8");
    return { contents: [{ uri: RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: html }] };
  });
}
