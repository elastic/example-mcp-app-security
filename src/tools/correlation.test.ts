/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { registerCorrelationTools } from "./correlation.js";
import {
  createMockMcpServer,
  parseToolText,
  type MockMcpServer,
} from "../test/helpers/mockMcpServer.js";
import { noopAnalyticsClient } from "../test/helpers/mockAnalytics.js";
import type { CorrelationService } from "../elastic/service/correlationService.js";

// ---------------------------------------------------------------------------
// Local mock — NOT added to shared mockServices.ts (off-limits)
// ---------------------------------------------------------------------------

function makeMockCorrelationService(): CorrelationService {
  return {
    diamondSearch: vi.fn(),
    diamondSearchScored: vi.fn(),
    getReports: vi.fn(),
  } as unknown as CorrelationService;
}

// ---------------------------------------------------------------------------
// Resource URIs
// ---------------------------------------------------------------------------

const CORRELATION_URI = "ui://correlation/mcp-app.html";
const CORRELATION_INPUT_URI = "ui://correlation-input/mcp-app.html";
const CORRELATION_REPORT_URI = "ui://correlation-report/mcp-app.html";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("registerCorrelationTools", () => {
  let server: MockMcpServer;
  let correlationService: CorrelationService;

  beforeEach(() => {
    server = createMockMcpServer();
    correlationService = makeMockCorrelationService();
    vi.spyOn(fs, "existsSync").mockReturnValue(false);
    vi.spyOn(fs, "readFileSync").mockReturnValue("<html>correlation</html>");
    registerCorrelationTools(server as unknown as McpServer, {
      correlationService,
      analytics: noopAnalyticsClient,
    });
  });

  it("registers all 5 correlation tools plus the 3 UI resources", () => {
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "diamond_search",
        "get_report",
        "diamond_search_analyst",
        "correlation_input_check",
        "render_correlation",
      ].sort()
    );
    expect([...server.resources.keys()].sort()).toEqual(
      [CORRELATION_URI, CORRELATION_INPUT_URI, CORRELATION_REPORT_URI].sort()
    );
  });

  // -------------------------------------------------------------------------
  // diamond_search — blind result, no scores in output
  // -------------------------------------------------------------------------

  describe("diamond_search", () => {
    it("returns candidate stubs without scores and attaches tradecraft", async () => {
      vi.mocked(correlationService.diamondSearch).mockResolvedValueOnce({
        candidates: [
          { report_id: "rpt-1", title: "APT28 Zebrocy", vendor: "elastic", url: "https://example.com/1" },
        ],
        total: 1,
        degraded: false,
        vertices_queried: ["adversary", "capability"],
      });

      const out = await server.tool("diamond_search").callback({
        adversary: "APT28",
        capability: "Zebrocy downloader",
      });

      expect(correlationService.diamondSearch).toHaveBeenCalledWith({
        vertex_queries: {
          adversary: "APT28",
          capability: "Zebrocy downloader",
          infrastructure: undefined,
          victim: undefined,
        },
        iocs: undefined,
        size: undefined,
      });

      const body = parseToolText<{
        candidates: Array<{ report_id: string; title: string; vendor: string; url: string }>;
        meta: { total: number; degraded: boolean; vertices_queried: string[] };
        tradecraft: unknown;
      }>(out);

      expect(body.candidates).toHaveLength(1);
      expect(body.candidates[0].report_id).toBe("rpt-1");
      // Blind path: no vertex_scores key in the stubs
      expect((body.candidates[0] as Record<string, unknown>).vertex_scores).toBeUndefined();
      expect(body.meta.total).toBe(1);
      expect(body.meta.degraded).toBe(false);
      expect(body.tradecraft).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // diamond_search_analyst — scored stubs
  // -------------------------------------------------------------------------

  describe("diamond_search_analyst", () => {
    it("returns scored stubs with vertex_scores and coverage signal", async () => {
      vi.mocked(correlationService.diamondSearchScored).mockResolvedValueOnce({
        candidates: [
          {
            report_id: "rpt-2",
            title: "Sofacy Campaign",
            vendor: "elastic",
            url: "https://example.com/2",
            vertex_scores: { adversary: 0.92, capability: 0.87 },
            overlap: 2,
            max_score: 0.92,
          },
        ],
        total: 1,
        degraded: false,
        vertices_queried: ["adversary", "capability"],
        coverage: { queried: 2, avg_overlap: 2, thin: false },
      });

      const out = await server.tool("diamond_search_analyst").callback({
        adversary: "APT28",
        capability: "Sofacy",
      });

      expect(correlationService.diamondSearchScored).toHaveBeenCalledOnce();

      const body = parseToolText<{
        candidates: Array<{ report_id: string; vertex_scores: Record<string, number>; overlap: number }>;
        coverage: { queried: number; avg_overlap: number; thin: boolean };
        tradecraft: unknown;
      }>(out);

      expect(body.candidates).toHaveLength(1);
      expect(body.candidates[0].vertex_scores).toEqual({ adversary: 0.92, capability: 0.87 });
      expect(body.candidates[0].overlap).toBe(2);
      expect(body.coverage.thin).toBe(false);
      expect(body.tradecraft).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // get_report — delegates to service and returns reports array
  // -------------------------------------------------------------------------

  describe("get_report", () => {
    it("returns the full reports fetched by the service", async () => {
      vi.mocked(correlationService.getReports).mockResolvedValueOnce([
        {
          report_id: "rpt-1",
          title: "APT28 Zebrocy",
          vendor: "elastic",
          url: "https://example.com/1",
          body_text: "The actor used Zebrocy...",
        },
      ]);

      const out = await server.tool("get_report").callback({ report_ids: ["rpt-1"] });

      expect(correlationService.getReports).toHaveBeenCalledWith(["rpt-1"]);

      const body = parseToolText<{ reports: Array<{ report_id: string; body_text: string }> }>(out);
      expect(body.reports).toHaveLength(1);
      expect(body.reports[0].report_id).toBe("rpt-1");
      expect(body.reports[0].body_text).toBe("The actor used Zebrocy...");
    });
  });

  // -------------------------------------------------------------------------
  // correlation_input_check — pure display gate, no service calls
  // -------------------------------------------------------------------------

  describe("correlation_input_check", () => {
    it("returns a gate payload with kind=correlation_input_check and no service calls", async () => {
      const out = await server.tool("correlation_input_check").callback({
        adversary: { query: "APT28", signal: "HIGH" },
        capability: { query: "Zebrocy", signal: "PARTIAL" },
      });

      // No service methods should have been called — pure display gate
      expect(correlationService.diamondSearch).not.toHaveBeenCalled();
      expect(correlationService.diamondSearchScored).not.toHaveBeenCalled();
      expect(correlationService.getReports).not.toHaveBeenCalled();

      const body = parseToolText<{
        kind: string;
        vertices: Record<string, { query: string; signal: string }>;
        summary: string;
      }>(out);

      expect(body.kind).toBe("correlation_input_check");
      expect(body.vertices.adversary).toEqual({ query: "APT28", signal: "HIGH" });
      expect(body.vertices.capability).toEqual({ query: "Zebrocy", signal: "PARTIAL" });
      expect(body.summary).toContain("ADV HIGH");
      expect(body.summary).toContain("CAP PARTIAL");
    });

    it("renders the no-signal message when no vertices are provided", async () => {
      const out = await server.tool("correlation_input_check").callback({});

      const body = parseToolText<{ kind: string; summary: string }>(out);
      expect(body.kind).toBe("correlation_input_check");
      expect(body.summary).toContain("No vertex signal provided");
    });
  });

  // -------------------------------------------------------------------------
  // render_correlation — pure pass-through, no service calls
  // -------------------------------------------------------------------------

  describe("render_correlation", () => {
    it("renders kind=correlation_report from host findings without calling any service method", async () => {
      const findings = {
        leads: [
          {
            candidate_ids: ["rpt-1"],
            title: "APT28 campaign overlap",
            relationship: "same_actor" as const,
            confidence: "high" as const,
            vertex_signal: {
              adversary: "high" as const,
              capability: "high" as const,
              infrastructure: "partial" as const,
              victim: "none" as const,
            },
            bluf: "Strong actor overlap.",
            evidence: [
              {
                vertex: "adversary" as const,
                weight: "smoking_gun" as const,
                text: "Alias Fancy Bear confirmed.",
              },
            ],
            gaps: "Infrastructure not corroborated.",
            consolidated_candidates: [],
          },
        ],
        no_match: [],
        synthesis: {
          bluf: "High confidence same-actor correlation.",
          correlation_signal: "high" as const,
          reasoning: "Two matching vertices with smoking-gun evidence.",
          gaps: "None critical.",
          next_steps: [{ priority: "high" as const, text: "Pivot on adversary infrastructure." }],
          case_title: "Test Case",
        },
      };

      const out = await server.tool("render_correlation").callback({ findings });

      // Pure pass-through — no service methods invoked
      expect(correlationService.diamondSearch).not.toHaveBeenCalled();
      expect(correlationService.diamondSearchScored).not.toHaveBeenCalled();
      expect(correlationService.getReports).not.toHaveBeenCalled();

      const body = parseToolText<{
        kind: string;
        findings: typeof findings;
        summary: string;
      }>(out);

      expect(body.kind).toBe("correlation_report");
      expect(body.findings.leads).toHaveLength(1);
      expect(body.findings.synthesis.correlation_signal).toBe("high");
      expect(body.summary).toContain("1 lead");
      expect(body.summary).toContain("signal: high");
    });
  });

  // -------------------------------------------------------------------------
  // UI resources
  // -------------------------------------------------------------------------

  describe("UI resources", () => {
    it("reads the correlation HTML resource", async () => {
      const out = await server.resource(CORRELATION_URI).readCallback();
      expect(out.contents[0].text).toBe("<html>correlation</html>");
    });

    it("reads the correlation-input HTML resource", async () => {
      const out = await server.resource(CORRELATION_INPUT_URI).readCallback();
      expect(out.contents[0].text).toBe("<html>correlation</html>");
    });

    it("reads the correlation-report HTML resource", async () => {
      const out = await server.resource(CORRELATION_REPORT_URI).readCallback();
      expect(out.contents[0].text).toBe("<html>correlation</html>");
    });
  });
});
