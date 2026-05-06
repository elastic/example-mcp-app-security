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
  vi,
} from "vitest";
import fs from "fs";

import { createServer } from "../../server.js";
import { MockAxios } from "../helpers/mockAxios.js";
import { connectInProcess } from "../helpers/integrationServer.js";

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

const ALERTS_PATH = "/.alerts-security.alerts-*/_search";
const RULES_FIND_PATH = "/api/detection_engine/rules/_find";
const CAT_INDICES_PATH = "/_cat/indices/logs-*,.alerts-security*";
const ESQL_PATH = "/_query";
const USER_PROFILE_PATH = "/internal/security/user_profile";

/**
 * End-to-end test that boots `createServer()`, connects a real MCP `Client`
 * over an `InMemoryTransport` pair, and exercises the public protocol:
 * `tools/list`, `resources/list`, `tools/call`. All Elasticsearch and Kibana
 * traffic is intercepted by an in-memory axios adapter — no real network
 * I/O — and the view HTML resource reads are stubbed via `fs`.
 */
describe("MCP server integration (in-process Client + Server)", () => {
  const mockAxios = new MockAxios();
  let restoreAxios: () => void;
  let originalClustersJson: string | undefined;
  let originalClustersFile: string | undefined;

  beforeAll(() => {
    originalClustersJson = process.env.CLUSTERS_JSON;
    originalClustersFile = process.env.CLUSTERS_FILE;
    process.env.CLUSTERS_JSON = CLUSTERS_JSON;
    delete process.env.CLUSTERS_FILE;

    restoreAxios = mockAxios.install();

    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>view</html>");
  });

  afterAll(() => {
    restoreAxios();
    vi.restoreAllMocks();
    if (originalClustersJson === undefined) delete process.env.CLUSTERS_JSON;
    else process.env.CLUSTERS_JSON = originalClustersJson;
    if (originalClustersFile === undefined) delete process.env.CLUSTERS_FILE;
    else process.env.CLUSTERS_FILE = originalClustersFile;
  });

  beforeEach(() => {
    mockAxios.reset();
  });

  /** Boot a fresh in-process server / client pair for one test. */
  function bootHarness() {
    return connectInProcess(createServer());
  }

  it("advertises every registered tool over `tools/list`", async () => {
    const harness = await bootHarness();
    try {
      const list = await harness.client.listTools();
      const names = list.tools.map((t) => t.name).sort();
      expect(names).toEqual(
        [
          // alert-triage
          "triage-alerts",
          "poll-alerts",
          "get-alert-context",
          "acknowledge-alert",
          "acknowledge-alerts-bulk",
          // case-management
          "manage-cases",
          "list-cases",
          "get-case",
          "create-case",
          "update-case",
          "add-case-comment",
          "attach-alert-to-case",
          "get-case-alerts",
          "get-case-comments",
          "get-user-profile",
          // detection-rules
          "manage-rules",
          "find-rules",
          "get-rule",
          "create-rule",
          "patch-rule",
          "toggle-rule",
          "validate-query",
          "noisy-rules",
          "manage-exceptions",
          // threat-hunt
          "threat-hunt",
          "execute-esql",
          "list-indices",
          "get-mapping",
          "get-entity-detail",
          "investigate-entity",
          // sample-data
          "generate-sample-data",
          "generate-scenario",
          "cleanup-sample-data",
          "create-rules-for-scenario",
          "check-existing-sample-data",
          // attack-discovery
          "triage-attack-discoveries",
          "poll-discoveries",
          "assess-discovery-confidence",
          "enrich-discovery",
          "approve-discoveries",
          "acknowledge-discoveries",
          "generate-attack-discovery",
          "get-generation-status",
          "list-ai-connectors",
        ].sort()
      );
    } finally {
      await harness.close();
    }
  });

  it("advertises every UI resource over `resources/list`", async () => {
    const harness = await bootHarness();
    try {
      const list = await harness.client.listResources();
      const uris = list.resources.map((r) => r.uri).sort();
      expect(uris).toEqual(
        [
          "ui://triage-alerts/mcp-app.html",
          "ui://manage-cases/mcp-app.html",
          "ui://manage-rules/mcp-app.html",
          "ui://threat-hunt/mcp-app.html",
          "ui://generate-sample-data/mcp-app.html",
          "ui://triage-attack-discoveries/mcp-app.html",
        ].sort()
      );
    } finally {
      await harness.close();
    }
  });

  it("returns the bundled HTML body when reading a UI resource", async () => {
    const harness = await bootHarness();
    try {
      const result = await harness.client.readResource({
        uri: "ui://triage-alerts/mcp-app.html",
      });
      expect(result.contents).toEqual([
        {
          uri: "ui://triage-alerts/mcp-app.html",
          mimeType: "text/html;profile=mcp-app",
          text: "<html>view</html>",
        },
      ]);
    } finally {
      await harness.close();
    }
  });

  describe("tools/call", () => {
    it("calls Elasticsearch and shapes the triage-alerts response", async () => {
      mockAxios.onPost(ALERTS_PATH, {
        data: {
          hits: {
            total: { value: 2 },
            hits: [
              {
                _id: "alert-1",
                _index: ".alerts-security.alerts-default",
                _source: {
                  "@timestamp": "2026-05-01T00:00:00Z",
                  "kibana.alert.rule.name": "Suspicious PowerShell",
                  "kibana.alert.rule.uuid": "rule-1",
                  "kibana.alert.severity": "high",
                  "kibana.alert.risk_score": 73,
                  "kibana.alert.workflow_status": "open",
                  "kibana.alert.reason": "encoded payload",
                  host: { name: "host-1" },
                  user: { name: "alice" },
                },
              },
              {
                _id: "alert-2",
                _index: ".alerts-security.alerts-default",
                _source: {
                  "@timestamp": "2026-05-01T00:01:00Z",
                  "kibana.alert.rule.name": "LSASS dump",
                  "kibana.alert.rule.uuid": "rule-2",
                  "kibana.alert.severity": "critical",
                  "kibana.alert.risk_score": 90,
                  "kibana.alert.workflow_status": "open",
                  "kibana.alert.reason": "procdump on lsass",
                },
              },
            ],
          },
          aggregations: {
            by_severity: {
              buckets: [
                { key: "high", doc_count: 1 },
                { key: "critical", doc_count: 1 },
              ],
            },
            by_rule: {
              buckets: [
                { key: "Suspicious PowerShell", doc_count: 1 },
                { key: "LSASS dump", doc_count: 1 },
              ],
            },
            by_host: {
              buckets: [{ key: "host-1", doc_count: 1 }],
            },
          },
        },
      });

      const harness = await bootHarness();
      try {
        const result = await harness.client.callTool({
          name: "triage-alerts",
          arguments: { days: 7, severity: "high" },
        });

        expect(result.isError).toBeFalsy();
        const content = result.content as { type: "text"; text: string }[];
        const body = JSON.parse(content[0].text) as {
          total: number;
          alerts: { id: string; rule: string }[];
          bySeverity: Record<string, number>;
          params: { severity: string };
        };
        expect(body.total).toBe(2);
        expect(body.bySeverity).toEqual({ high: 1, critical: 1 });
        expect(body.alerts).toEqual([
          expect.objectContaining({
            id: "alert-1",
            rule: "Suspicious PowerShell",
          }),
          expect.objectContaining({
            id: "alert-2",
            rule: "LSASS dump",
          }),
        ]);
        expect(body.params.severity).toBe("high");

        const calls = mockAxios.history();
        expect(calls).toHaveLength(1);
        expect(calls[0].url).toBe(ALERTS_PATH);
        expect(calls[0].baseURL).toBe(ES_BASE_URL);
        expect(calls[0].method?.toLowerCase()).toBe("post");
        const sentBody = JSON.parse(calls[0].data as string) as {
          query: { bool: { must: { term?: { "kibana.alert.severity": string } }[] } };
        };
        expect(sentBody.query.bool.must).toContainEqual({
          term: { "kibana.alert.severity": "high" },
        });
      } finally {
        await harness.close();
      }
    });

    it("calls Kibana and shapes the manage-rules response", async () => {
      mockAxios.onGet(RULES_FIND_PATH, {
        data: {
          total: 1,
          page: 1,
          perPage: 20,
          data: [
            {
              id: "r-1",
              rule_id: "rid-1",
              name: "Suspicious PowerShell",
              description: "encoded execution",
              severity: "high",
              risk_score: 73,
              type: "query",
              enabled: true,
              query: 'process.name: "powershell.exe"',
              language: "kuery",
              tags: ["alpha", "beta"],
              created_at: "2026-04-01T00:00:00Z",
              updated_at: "2026-04-15T00:00:00Z",
              created_by: "alice",
              threat: [],
            },
          ],
        },
      });

      const harness = await bootHarness();
      try {
        const result = await harness.client.callTool({
          name: "manage-rules",
          arguments: { page: 1, perPage: 20 },
        });

        const content = result.content as { type: "text"; text: string }[];
        const body = JSON.parse(content[0].text) as {
          total: number;
          rules: { id: string; name: string }[];
          params: { page: number; perPage: number };
        };
        expect(body.total).toBe(1);
        expect(body.rules[0]).toMatchObject({
          id: "r-1",
          name: "Suspicious PowerShell",
        });

        const [request] = mockAxios.history();
        expect(request.method?.toLowerCase()).toBe("get");
        expect(request.url).toBe(RULES_FIND_PATH);
        expect(request.baseURL).toBe(KIBANA_BASE_URL);
        expect(request.params).toMatchObject({
          page: "1",
          per_page: "20",
        });
      } finally {
        await harness.close();
      }
    });

    it("normalises _cat/indices into the list-indices response", async () => {
      mockAxios.onGet(CAT_INDICES_PATH, {
        data: [
          {
            index: "logs-endpoint.events.process-default",
            health: "green",
            status: "open",
            "docs.count": "1234",
            "store.size": "10mb",
          },
          {
            index: ".alerts-security.alerts-default",
            health: "yellow",
            status: "open",
            "docs.count": "42",
            "store.size": "1mb",
          },
        ],
      });

      const harness = await bootHarness();
      try {
        const result = await harness.client.callTool({
          name: "list-indices",
          arguments: {},
        });
        const content = result.content as { type: "text"; text: string }[];
        const body = JSON.parse(content[0].text) as {
          index: string;
          docsCount: string;
        }[];
        expect(body).toEqual([
          {
            index: "logs-endpoint.events.process-default",
            health: "green",
            status: "open",
            docsCount: "1234",
            storeSize: "10mb",
          },
          {
            index: ".alerts-security.alerts-default",
            health: "yellow",
            status: "open",
            docsCount: "42",
            storeSize: "1mb",
          },
        ]);

        const [request] = mockAxios.history();
        expect(request.url).toBe(CAT_INDICES_PATH);
        expect(request.baseURL).toBe(ES_BASE_URL);
      } finally {
        await harness.close();
      }
    });

    it("forwards validate-query (esql) to the Elasticsearch _query endpoint", async () => {
      mockAxios.onPost(ESQL_PATH, { data: { columns: [], values: [] } });

      const harness = await bootHarness();
      try {
        const result = await harness.client.callTool({
          name: "validate-query",
          arguments: { query: "FROM logs-* | LIMIT 1", language: "esql" },
        });

        const content = result.content as { type: "text"; text: string }[];
        expect(JSON.parse(content[0].text)).toEqual({ valid: true });

        const [request] = mockAxios.history();
        expect(request.url).toBe(ESQL_PATH);
        expect(request.baseURL).toBe(ES_BASE_URL);
        const body = JSON.parse(request.data as string) as {
          query: string;
          fetch_size: number;
        };
        expect(body.query).toBe("FROM logs-* | LIMIT 1");
        expect(body.fetch_size).toBe(0);
      } finally {
        await harness.close();
      }
    });

    it("captures error messages from validate-query when ES rejects the query", async () => {
      mockAxios.onPost(ESQL_PATH, {
        status: 400,
        data: { error: { type: "parsing_exception", reason: "bad column" } },
      });

      const harness = await bootHarness();
      try {
        const result = await harness.client.callTool({
          name: "validate-query",
          arguments: { query: "FROM bogus", language: "esql" },
        });

        const content = result.content as { type: "text"; text: string }[];
        const parsed = JSON.parse(content[0].text) as {
          valid: boolean;
          error?: string;
        };
        expect(parsed.valid).toBe(false);
        expect(parsed.error).toContain("Elasticsearch [primary] 400");
        expect(parsed.error).toContain("parsing_exception");
      } finally {
        await harness.close();
      }
    });

    it("reshapes the Kibana user profile response", async () => {
      mockAxios.onGet(USER_PROFILE_PATH, {
        data: {
          user: { username: "alice" },
          data: { avatar: { initials: "AL", color: "#fa0" } },
        },
      });

      const harness = await bootHarness();
      try {
        const result = await harness.client.callTool({
          name: "get-user-profile",
          arguments: {},
        });
        const content = result.content as { type: "text"; text: string }[];
        const body = JSON.parse(content[0].text) as {
          username: string;
          avatar: { initials: string; color: string };
        };
        expect(body).toEqual({
          username: "alice",
          avatar: { initials: "AL", color: "#fa0" },
        });

        const [request] = mockAxios.history();
        expect(request.url).toBe(USER_PROFILE_PATH);
        expect(request.baseURL).toBe(KIBANA_BASE_URL);
        expect(request.params).toEqual({ dataPath: "avatar" });
        expect(request.headers?.["Authorization"]).toBe("ApiKey test-key");
      } finally {
        await harness.close();
      }
    });

    it("falls back to an empty profile when Kibana rejects the request", async () => {
      mockAxios.onGet(USER_PROFILE_PATH, {
        status: 401,
        data: "unauthorized",
      });

      const harness = await bootHarness();
      try {
        const result = await harness.client.callTool({
          name: "get-user-profile",
          arguments: {},
        });
        const content = result.content as { type: "text"; text: string }[];
        expect(JSON.parse(content[0].text)).toEqual({
          username: "",
          avatar: {},
        });
      } finally {
        await harness.close();
      }
    });

    it("forwards an HTTP error from Elasticsearch as an MCP-level tool error", async () => {
      mockAxios.onPost(ALERTS_PATH, {
        status: 503,
        data: { error: { type: "service_unavailable" } },
      });

      const harness = await bootHarness();
      try {
        const result = await harness.client.callTool({
          name: "triage-alerts",
          arguments: {},
        });

        // When the tool callback throws, the MCP server returns
        // `isError: true` and the error message becomes the content.
        expect(result.isError).toBe(true);
        const content = result.content as { type: "text"; text: string }[];
        expect(content[0].text).toContain("Elasticsearch [primary] 503");

        const [request] = mockAxios.history();
        expect(request.url).toBe(ALERTS_PATH);
        expect(request.baseURL).toBe(ES_BASE_URL);
      } finally {
        await harness.close();
      }
    });

    it("routes Elasticsearch and Kibana traffic to their configured base URLs in a single threat-hunt call", async () => {
      // threat-hunt fans out to: list-indices (ES _cat) + execute-esql (ES
      // _query) + investigate-entity (ES _search). Pair it with a Kibana
      // call from another tool to assert the two clients are wired
      // independently to their own base URLs.
      mockAxios.onGet(CAT_INDICES_PATH, {
        data: [
          {
            index: "logs-endpoint.events.process-default",
            health: "green",
            status: "open",
            "docs.count": "1",
            "store.size": "1mb",
          },
        ],
      });
      mockAxios.onPost(ESQL_PATH, { data: { columns: [], values: [] } });
      mockAxios.onGet(RULES_FIND_PATH, {
        data: { total: 0, page: 1, perPage: 20, data: [] },
      });

      const harness = await bootHarness();
      try {
        await harness.client.callTool({
          name: "threat-hunt",
          arguments: { query: "FROM logs-* | LIMIT 1" },
        });
        await harness.client.callTool({
          name: "manage-rules",
          arguments: {},
        });

        const requestsByUrl = new Map(
          mockAxios.history().map((req) => [req.url, req])
        );

        // Every Elasticsearch path landed on the ES base URL.
        expect(requestsByUrl.get(CAT_INDICES_PATH)?.baseURL).toBe(ES_BASE_URL);
        expect(requestsByUrl.get(ESQL_PATH)?.baseURL).toBe(ES_BASE_URL);

        // The Kibana path landed on the Kibana base URL — never on the ES one.
        expect(requestsByUrl.get(RULES_FIND_PATH)?.baseURL).toBe(
          KIBANA_BASE_URL
        );

        // Sanity check: nothing crossed wires.
        for (const req of mockAxios.history()) {
          if (req.url?.startsWith("/api/") || req.url?.startsWith("/internal/")) {
            expect(req.baseURL).toBe(KIBANA_BASE_URL);
          } else {
            expect(req.baseURL).toBe(ES_BASE_URL);
          }
        }
      } finally {
        await harness.close();
      }
    });
  });

  describe("startup", () => {
    it("crashes with a clear error when no cluster config is set", () => {
      // `createCredentialClient()` reads `process.env` at call time, not at
      // import time, so we don't need to re-import the module here.
      const previousJson = process.env.CLUSTERS_JSON;
      delete process.env.CLUSTERS_JSON;
      try {
        expect(() => createServer()).toThrowError(/No clusters configured/);
      } finally {
        process.env.CLUSTERS_JSON = previousJson;
      }
    });
  });
});
