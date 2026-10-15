/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { registerSpaceTools } from "./spaces.js";
import type { SpacesService } from "../elastic/service/index.js";
import {
  createMockMcpServer,
  parseToolText,
} from "../test/helpers/mockMcpServer.js";
import { noopAnalyticsClient } from "../test/helpers/mockAnalytics.js";
import type { ListSpacesResult, SpaceCountsResult } from "../shared/spaces.js";

function setup() {
  const server = createMockMcpServer();
  const spacesService = {
    listSpaces: vi.fn(),
    countBySpace: vi.fn(),
  };
  registerSpaceTools(server as unknown as McpServer, {
    spacesService: spacesService as unknown as SpacesService,
    analytics: noopAnalyticsClient,
  });
  return { server, spacesService };
}

describe("registerSpaceTools", () => {
  it("registers list-spaces and count-by-space as read-only tools visible to model and app", () => {
    const { server } = setup();
    expect([...server.tools.keys()].sort()).toEqual(["count-by-space", "list-spaces"]);
    for (const name of ["list-spaces", "count-by-space"]) {
      const { config } = server.tool(name);
      expect(config.annotations, name).toEqual({ readOnlyHint: true });
      expect(config._meta, name).toMatchObject({ ui: { visibility: ["model", "app"] } });
      expect(config.description, name).toContain("`space`");
    }
  });

  describe("list-spaces", () => {
    it("returns the service result as JSON", async () => {
      const { server, spacesService } = setup();
      const result: ListSpacesResult = {
        configured: "default",
        spaces: [
          { id: "default", name: "Default", color: "#00bfb3", initials: "D" },
          { id: "soc", name: "SOC" },
        ],
      };
      spacesService.listSpaces.mockResolvedValueOnce(result);

      const out = await server.tool("list-spaces").callback({});

      expect(parseToolText(out)).toEqual(result);
    });
  });

  describe("count-by-space", () => {
    it("forwards kind and days and returns the counts as JSON", async () => {
      const { server, spacesService } = setup();
      const result: SpaceCountsResult = {
        kind: "alerts",
        days: 3,
        counts: { default: 4, soc: 9 },
      };
      spacesService.countBySpace.mockResolvedValueOnce(result);

      const out = await server.tool("count-by-space").callback({ kind: "alerts", days: 3 });

      expect(spacesService.countBySpace).toHaveBeenCalledExactlyOnceWith("alerts", 3);
      expect(parseToolText(out)).toEqual(result);
    });

    it("leaves the look-back to the service default when days is omitted", async () => {
      const { server, spacesService } = setup();
      spacesService.countBySpace.mockResolvedValueOnce({
        kind: "discoveries",
        days: 1,
        counts: {},
      });

      await server.tool("count-by-space").callback({ kind: "discoveries" });

      expect(spacesService.countBySpace).toHaveBeenCalledWith("discoveries", undefined);
    });

    it("only accepts a known kind and a positive whole number of days", () => {
      const { server } = setup();
      const schema = z.object(
        server.tool("count-by-space").config.inputSchema as z.ZodRawShape
      );

      expect(schema.safeParse({ kind: "alerts" }).success).toBe(true);
      expect(schema.safeParse({ kind: "discoveries", days: 14 }).success).toBe(true);
      expect(schema.safeParse({ kind: "cases" }).success).toBe(false);
      expect(schema.safeParse({ kind: "alerts", days: 0 }).success).toBe(false);
      expect(schema.safeParse({ kind: "alerts", days: 1.5 }).success).toBe(false);
    });
  });
});
