/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  describe,
  it,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
  vi,
} from "vitest";
import fs from "fs";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

import { createServer } from "../../server.js";
import { createCredentialClient } from "../../elastic/credential-client/index.js";
import type { CredentialClient } from "../../elastic/credential-client/index.js";
import { AlertsService, RulesService } from "../../elastic/service/index.js";
import { currentSpaceId } from "../../elastic/shared/space-context.js";
import {
  COUNT_BY_SPACE_TOOL,
  LIST_SPACES_TOOL,
  SPACE_ARG,
} from "../../shared/spaces.js";
import { MockAxios } from "../helpers/mockAxios.js";
import { connectInProcess } from "../helpers/integrationServer.js";
import { installClustersJson } from "../helpers/clustersEnv.js";
import { noopAnalyticsClient } from "../helpers/mockAnalytics.js";

const ES_BASE_URL = "https://es.example.com";
const KIBANA_BASE_URL = "https://kb.example.com";

const CLUSTERS_JSON = JSON.stringify([
  {
    name: "primary",
    elasticsearchUrl: ES_BASE_URL,
    kibanaUrl: KIBANA_BASE_URL,
    elasticsearchApiKey: "test-key",
  },
]);

const SPACES_PATH = "/api/spaces/space";
const ALERT_COUNTS_PATH = "/.alerts-security.alerts-*/_search";
const NOT_SPACE_SCOPED = [LIST_SPACES_TOOL, COUNT_BY_SPACE_TOOL, "report-analytics-event"];

type JsonSchema = {
  properties?: Record<string, { type?: string; pattern?: string; description?: string }>;
  required?: string[];
};

/** Credentials from `CLUSTERS_JSON`, with the configured space overridden. */
function credentialClientInSpace(spaceId: string): CredentialClient {
  const base = createCredentialClient();
  return {
    get: (name) => ({ ...base.get(name), spaceId }),
    list: () => base.list(),
    defaultName: () => base.defaultName(),
  };
}

function textOf(result: Record<string, unknown>): string {
  return (result.content as { type: "text"; text: string }[])[0].text;
}

/**
 * Per-call `space` argument and the space discovery tools, exercised over a
 * real MCP `Client` / `Server` pair with ES and Kibana stubbed by MockAxios.
 */
describe("Kibana spaces (in-process Client + Server)", () => {
  const mockAxios = new MockAxios();
  let restoreAxios: () => void;
  let restoreClustersEnv: () => void;

  beforeAll(() => {
    restoreClustersEnv = installClustersJson(CLUSTERS_JSON);
    restoreAxios = mockAxios.install();
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>view</html>");
  });

  afterAll(() => {
    restoreAxios();
    vi.restoreAllMocks();
    restoreClustersEnv();
  });

  beforeEach(() => {
    mockAxios.reset();
  });

  describe("tools/list", () => {
    let tools: Tool[];

    beforeAll(async () => {
      const harness = await connectInProcess(createServer({ analytics: noopAnalyticsClient }));
      try {
        tools = (await harness.client.listTools()).tools;
      } finally {
        await harness.close();
      }
    });

    it("advertises an optional, pattern-checked `space` on every space-aware tool", () => {
      const scoped = tools.filter((t) => !NOT_SPACE_SCOPED.includes(t.name));
      expect(scoped.length).toBeGreaterThan(40);

      for (const tool of scoped) {
        const schema = tool.inputSchema as JsonSchema;
        expect(schema.properties?.[SPACE_ARG], tool.name).toMatchObject({
          type: "string",
          pattern: "^[a-z0-9_-]+$",
        });
        expect(schema.required ?? [], tool.name).not.toContain(SPACE_ARG);
      }

      const triage = tools.find((t) => t.name === "triage-alerts");
      const space = (triage?.inputSchema as JsonSchema).properties?.[SPACE_ARG];
      expect(space?.description).toContain(LIST_SPACES_TOOL);
    });

    it.each(NOT_SPACE_SCOPED)("does not advertise `space` on %s", (name) => {
      const tool = tools.find((t) => t.name === name);
      expect(tool, name).toBeDefined();
      expect((tool?.inputSchema as JsonSchema).properties ?? {}).not.toHaveProperty(SPACE_ARG);
    });
  });

  describe("tools/call with `space`", () => {
    const observedSpaces: string[] = [];

    beforeEach(() => {
      observedSpaces.length = 0;
      vi.spyOn(AlertsService.prototype, "getAlerts").mockImplementation(async () => {
        observedSpaces.push(currentSpaceId());
        return { total: 0, bySeverity: {}, byRule: [], byHost: [], alerts: [] };
      });
    });

    afterEach(() => {
      vi.mocked(AlertsService.prototype.getAlerts).mockRestore();
    });

    it("runs the handler in the requested space, else in the configured one", async () => {
      const harness = await connectInProcess(
        createServer({
          analytics: noopAnalyticsClient,
          credentialClient: credentialClientInSpace("ops"),
        })
      );
      try {
        const inSoc = await harness.client.callTool({
          name: "triage-alerts",
          arguments: { days: 3, [SPACE_ARG]: "soc" },
        });
        const inDefault = await harness.client.callTool({
          name: "triage-alerts",
          arguments: { days: 3 },
        });

        expect(inSoc.isError).toBeFalsy();
        expect(inDefault.isError).toBeFalsy();
        expect(observedSpaces).toEqual(["soc", "ops"]);
        expect(currentSpaceId()).toBe("default");
      } finally {
        await harness.close();
      }
    });

    it("strips `space` before the handler forwards its args", async () => {
      const findRules = vi
        .spyOn(RulesService.prototype, "findRules")
        .mockResolvedValue({ total: 0, page: 1, perPage: 20, data: [] });
      const harness = await connectInProcess(createServer({ analytics: noopAnalyticsClient }));
      try {
        const result = await harness.client.callTool({
          name: "find-rules",
          arguments: { filter: "alert.attributes.enabled:true", [SPACE_ARG]: "soc" },
        });

        expect(result.isError).toBeFalsy();
        expect(findRules).toHaveBeenCalledExactlyOnceWith({
          filter: "alert.attributes.enabled:true",
        });
      } finally {
        findRules.mockRestore();
        await harness.close();
      }
    });

    it.each(["SOC", "my space", "*", "../default", ""])(
      "rejects the invalid space %j before the handler runs",
      async (space) => {
        const harness = await connectInProcess(createServer({ analytics: noopAnalyticsClient }));
        try {
          const result = await harness.client.callTool({
            name: "triage-alerts",
            arguments: { [SPACE_ARG]: space },
          });

          expect(result.isError).toBe(true);
          expect(textOf(result)).toContain("Input validation error");
          expect(textOf(result)).toContain(SPACE_ARG);
          expect(observedSpaces).toEqual([]);
          expect(mockAxios.history()).toEqual([]);
        } finally {
          await harness.close();
        }
      }
    );
  });

  describe("space discovery tools", () => {
    it("list-spaces returns the accessible spaces and the configured space", async () => {
      mockAxios.onGet(SPACES_PATH, {
        data: [
          {
            id: "default",
            name: "Default",
            color: "#00bfb3",
            initials: "D",
            disabledFeatures: [],
            _reserved: true,
          },
          { id: "soc", name: "SOC", color: "#e7664c", initials: "SO", disabledFeatures: [] },
        ],
      });

      const harness = await connectInProcess(createServer({ analytics: noopAnalyticsClient }));
      try {
        const result = await harness.client.callTool({ name: LIST_SPACES_TOOL, arguments: {} });

        expect(result.isError).toBeFalsy();
        expect(JSON.parse(textOf(result))).toEqual({
          configured: "default",
          spaces: [
            { id: "default", name: "Default", color: "#00bfb3", initials: "D" },
            { id: "soc", name: "SOC", color: "#e7664c", initials: "SO" },
          ],
        });

        const [request] = mockAxios.history();
        expect(request.method?.toLowerCase()).toBe("get");
        expect(request.url).toBe(SPACES_PATH);
        expect(request.baseURL).toBe(KIBANA_BASE_URL);
        expect(request.headers?.["elastic-api-version"]).toBe("2023-10-31");
      } finally {
        await harness.close();
      }
    });

    it("count-by-space counts open alerts per space with one cross-space query", async () => {
      mockAxios.onPost(ALERT_COUNTS_PATH, {
        data: {
          hits: { total: { value: 0 }, hits: [] },
          aggregations: {
            by_space: {
              buckets: [
                { key: "default", doc_count: 5 },
                { key: "soc", doc_count: 2 },
              ],
            },
          },
        },
      });

      const harness = await connectInProcess(createServer({ analytics: noopAnalyticsClient }));
      try {
        const result = await harness.client.callTool({
          name: COUNT_BY_SPACE_TOOL,
          arguments: { kind: "alerts" },
        });

        expect(result.isError).toBeFalsy();
        expect(JSON.parse(textOf(result))).toEqual({
          kind: "alerts",
          days: 7,
          counts: { default: 5, soc: 2 },
        });

        const calls = mockAxios.history();
        expect(calls).toHaveLength(1);
        expect(calls[0].url).toBe(ALERT_COUNTS_PATH);
        expect(calls[0].baseURL).toBe(ES_BASE_URL);
        expect(calls[0].params).toEqual({
          ignore_unavailable: "true",
          allow_no_indices: "true",
        });
        const body = JSON.parse(calls[0].data as string) as {
          aggs: { by_space: { terms: { field: string } } };
        };
        expect(body.aggs.by_space.terms.field).toBe("kibana.space_ids");
      } finally {
        await harness.close();
      }
    });

    it("count-by-space rejects an unknown kind", async () => {
      const harness = await connectInProcess(createServer({ analytics: noopAnalyticsClient }));
      try {
        const result = await harness.client.callTool({
          name: COUNT_BY_SPACE_TOOL,
          arguments: { kind: "cases" },
        });

        expect(result.isError).toBe(true);
        expect(textOf(result)).toContain("Input validation error");
        expect(mockAxios.history()).toEqual([]);
      } finally {
        await harness.close();
      }
    });
  });
});
