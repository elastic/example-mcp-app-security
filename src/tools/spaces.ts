/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { SpacesService } from "../elastic/service/index.js";
import type { AnalyticsClient } from "../elastic/analytics/index.js";
import {
  COUNT_BY_SPACE_TOOL,
  LIST_SPACES_TOOL,
  SPACE_ARG,
} from "../shared/spaces.js";
import { registerTrackedAppTool } from "./tracked-app-tool.js";

export interface SpaceToolDeps {
  readonly spacesService: SpacesService;
  readonly analytics: AnalyticsClient;
}

export function registerSpaceTools(server: McpServer, deps: SpaceToolDeps) {
  const { spacesService, analytics } = deps;

  registerTrackedAppTool(
    analytics,
    server,
    LIST_SPACES_TOOL,
    {
      title: "List Kibana Spaces",
      description: `List the Kibana spaces this API key can access (id, name, color, initials) and the configured space that tools use by default. To work in another space, pass its id as the \`${SPACE_ARG}\` argument of any other tool.`,
      inputSchema: {},
      annotations: { readOnlyHint: true },
      _meta: { ui: { visibility: ["model", "app"] } },
    },
    async () => {
      const result = await spacesService.listSpaces();
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );

  registerTrackedAppTool(
    analytics,
    server,
    COUNT_BY_SPACE_TOOL,
    {
      title: "Count Alerts or Discoveries by Space",
      description: `Count open security alerts or open attack discoveries in every Kibana space with one query, keyed by space id. Spaces with nothing open are omitted. Use it to find which spaces need attention, then pass a space id as the \`${SPACE_ARG}\` argument of other tools.`,
      inputSchema: {
        kind: z
          .enum(["alerts", "discoveries"])
          .describe("What to count: open detection alerts or open attack discoveries"),
        days: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Number of days to look back (default: 7 for alerts, 1 for discoveries)"),
      },
      annotations: { readOnlyHint: true },
      _meta: { ui: { visibility: ["model", "app"] } },
    },
    async ({ kind, days }) => {
      const result = await spacesService.countBySpace(kind, days);
      return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
    }
  );
}
