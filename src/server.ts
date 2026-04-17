/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

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
    version: "1.0.0",
  });

  registerAlertTriageTools(server);
  registerCaseManagementTools(server);
  registerDetectionRuleTools(server);
  registerThreatHuntTools(server);
  registerSampleDataTools(server);
  registerAttackDiscoveryTools(server);

  return server;
}
