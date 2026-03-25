import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAlertTriageTools } from "./tools/alert-triage.js";
import { registerCaseManagementTools } from "./tools/case-management.js";
import { registerDetectionRuleTools } from "./tools/detection-rules.js";
import { registerThreatHuntTools } from "./tools/threat-hunt.js";
import { registerSampleDataTools } from "./tools/sample-data.js";
import { registerAttackDiscoveryTools } from "./tools/attack-discovery.js";

export function createServer(): McpServer {
  const server = new McpServer({
    name: "elastic-security",
    version: "0.1.0",
  });

  registerAlertTriageTools(server);
  registerCaseManagementTools(server);
  registerDetectionRuleTools(server);
  registerThreatHuntTools(server);
  registerSampleDataTools(server);
  registerAttackDiscoveryTools(server);

  return server;
}
