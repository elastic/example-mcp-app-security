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
import type { CorrelationService, MatchedVertex } from "../elastic/service/correlationService.js";

// ---------------------------------------------------------------------------
// Local mock — NOT added to shared mockServices.ts (off-limits)
// ---------------------------------------------------------------------------

function makeMockCorrelationService(): CorrelationService {
  return {
    diamondSearch: vi.fn(),
    diamondSearchScored: vi.fn(),
    getReports: vi.fn(),
    runCorrelation: vi.fn(),
    getCorrelationRun: vi.fn(),
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

  it("registers all 7 correlation tools plus the 3 UI resources", () => {
    expect([...server.tools.keys()].sort()).toEqual(
      [
        "correlate",
        "get_correlation_run",
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
    it("returns candidate stubs with matched_vertices evidence (no scores) and attaches tradecraft", async () => {
      const matchedVertices: MatchedVertex[] = [
        { vertex: "adversary", summary: "APT28 / Fancy Bear, attributed to GRU Unit 26165" },
        { vertex: "capability", summary: "Zebrocy downloader used as first-stage implant" },
      ];

      vi.mocked(correlationService.diamondSearch).mockResolvedValueOnce({
        candidates: [
          {
            report_id: "rpt-1",
            title: "APT28 Zebrocy",
            vendor: "elastic",
            url: "https://example.com/1",
            matched_vertices: matchedVertices,
          },
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
        candidates: Array<{
          report_id: string;
          title: string;
          vendor: string;
          url: string;
          matched_vertices?: MatchedVertex[];
        }>;
        meta: { total: number; degraded: boolean; vertices_queried: string[] };
        tradecraft: unknown;
      }>(out);

      expect(body.candidates).toHaveLength(1);
      expect(body.candidates[0].report_id).toBe("rpt-1");

      // Blind path: matched_vertices with evidence text present, no numeric scores
      expect(body.candidates[0].matched_vertices).toEqual(matchedVertices);
      expect((body.candidates[0] as Record<string, unknown>).vertex_scores).toBeUndefined();

      expect(body.meta.total).toBe(1);
      expect(body.meta.degraded).toBe(false);
      expect(body.tradecraft).toBeDefined();
    });

    it("returns stubs without matched_vertices when service returns none (BM25 fallback)", async () => {
      vi.mocked(correlationService.diamondSearch).mockResolvedValueOnce({
        candidates: [
          { report_id: "rpt-bm25", title: "BM25 hit", vendor: "elastic", url: "https://example.com/bm25" },
        ],
        total: 1,
        degraded: true,
        vertices_queried: ["adversary"],
      });

      const out = await server.tool("diamond_search").callback({ adversary: "APT28" });

      const body = parseToolText<{
        candidates: Array<Record<string, unknown>>;
        meta: { degraded: boolean };
      }>(out);

      expect(body.meta.degraded).toBe(true);
      // BM25 stubs: no matched_vertices, no vertex_scores
      expect(body.candidates[0].matched_vertices).toBeUndefined();
      expect(body.candidates[0].vertex_scores).toBeUndefined();
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
  // correlate — triggers the workflow, returns a run_id
  // -------------------------------------------------------------------------

  describe("correlate", () => {
    it("triggers the workflow and returns the run_id", async () => {
      vi.mocked(correlationService.runCorrelation).mockResolvedValueOnce({
        run_id: "exec-123",
        workflow_id: "ti-correlation",
        depth: "full",
      });

      const out = await server.tool("correlate").callback({
        report_id: "fp-abc",
        depth: "full",
      });

      expect(correlationService.runCorrelation).toHaveBeenCalledWith({
        report_id: "fp-abc",
        raw_text: undefined,
        depth: "full",
        triage_pool: undefined,
        triage_floor: undefined,
      });

      const body = parseToolText<{ kind: string; run_id: string; depth: string }>(out);
      expect(body.kind).toBe("correlation_run_started");
      expect(body.run_id).toBe("exec-123");
      expect(body.depth).toBe("full");
    });
  });

  // -------------------------------------------------------------------------
  // get_correlation_run — poll + transform workflow findings to render shape
  // -------------------------------------------------------------------------

  describe("get_correlation_run", () => {
    it("reports pending when the run record does not exist yet", async () => {
      vi.mocked(correlationService.getCorrelationRun).mockResolvedValueOnce({
        found: false,
      });

      const out = await server.tool("get_correlation_run").callback({ run_id: "exec-x" });
      const body = parseToolText<{ found: boolean; status: string }>(out);
      expect(body.found).toBe(false);
      expect(body.status).toBe("pending");
    });

    it("resolves candidate titles to report ids via picks on completion", async () => {
      vi.mocked(correlationService.getCorrelationRun).mockResolvedValueOnce({
        found: true,
        run_id: "exec-9",
        status: "completed",
        depth: "full",
        picks: [
          { candidate_id: 0, fp: "fp-1", title: "APT28 Zebrocy" },
          { candidate_id: 1, fp: "fp-2", title: "Sofacy Infra" },
        ],
        findings: {
          leads: [
            {
              candidate_titles: ["APT28 Zebrocy", "Sofacy Infra"],
              title: "Actor overlap",
              relationship: "same_actor",
              confidence: "high",
              vertex_signal: { adversary: "high", capability: "high", infrastructure: "partial", victim: "none" },
              bluf: "Overlap.",
              evidence: [{ vertex: "adversary", weight: "smoking_gun", text: "Fancy Bear." }],
              gaps: "none",
            },
          ],
          no_match: [{ title: "Unrelated report" }],
          synthesis: {
            bluf: "b",
            correlation_signal: "high",
            reasoning: "r",
            gaps: "g",
            next_steps: [],
          },
        },
      });

      const out = await server.tool("get_correlation_run").callback({ run_id: "exec-9" });
      const body = parseToolText<{
        found: boolean;
        status: string;
        findings: {
          leads: Array<{ candidate_ids: string[]; candidate_titles?: string[] }>;
          no_match: Array<{ id: string; title: string }>;
          candidate_meta: Record<string, { title?: string }>;
        };
      }>(out);

      expect(body.found).toBe(true);
      expect(body.status).toBe("completed");
      // candidate_titles resolved to fingerprints, and the title array dropped.
      expect(body.findings.leads[0].candidate_ids).toEqual(["fp-1", "fp-2"]);
      expect(body.findings.leads[0].candidate_titles).toBeUndefined();
      // no_match falls back to the title string when unmatched by picks.
      expect(body.findings.no_match[0]).toEqual({ id: "Unrelated report", title: "Unrelated report" });
      // candidate_meta bridges id -> title for the renderer.
      expect(body.findings.candidate_meta["fp-1"]).toEqual({ title: "APT28 Zebrocy" });
    });

    it("resolves titles across typographic vs ASCII quote differences", async () => {
      vi.mocked(correlationService.getCorrelationRun).mockResolvedValueOnce({
        found: true,
        run_id: "exec-q",
        status: "completed",
        depth: "full",
        // Stored pick titles use curly apostrophes (as written in the corpus).
        picks: [
          { candidate_id: 0, fp: "fp-fish", title: "FishMonger\u2019s arsenal upgraded: SprySOCKS for Windows" },
          { candidate_id: 1, fp: "fp-isoon", title: "A comprehensive analysis of I-Soon\u2019s commercial offering" },
        ],
        findings: {
          leads: [
            {
              // Synthesis LLM re-emitted them with straight ASCII apostrophes.
              candidate_titles: ["FishMonger's arsenal upgraded: SprySOCKS for Windows"],
              title: "FishMonger lead",
              relationship: "same_actor",
              confidence: "moderate",
              vertex_signal: { adversary: "high", capability: "partial", infrastructure: "none", victim: "none" },
              bluf: "b",
              evidence: [],
              gaps: "g",
            },
            {
              candidate_titles: ["A comprehensive analysis of I-Soon's commercial offering"],
              title: "I-Soon lead",
              relationship: "same_actor",
              confidence: "low",
              vertex_signal: { adversary: "partial", capability: "none", infrastructure: "none", victim: "none" },
              bluf: "b2",
              evidence: [],
              gaps: "g2",
            },
          ],
          no_match: [],
          synthesis: { bluf: "b", correlation_signal: "moderate", reasoning: "r", gaps: "g", next_steps: [] },
        },
      });

      const out = await server.tool("get_correlation_run").callback({ run_id: "exec-q" });
      const body = parseToolText<{
        findings: { leads: Array<{ candidate_ids: string[] }> };
      }>(out);
      expect(body.findings.leads[0].candidate_ids).toEqual(["fp-fish"]);
      expect(body.findings.leads[1].candidate_ids).toEqual(["fp-isoon"]);
    });

    it("surfaces a loud miss when a candidate title does not resolve to a pick", async () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      vi.mocked(correlationService.getCorrelationRun).mockResolvedValueOnce({
        found: true,
        run_id: "exec-miss",
        status: "completed",
        depth: "full",
        picks: [{ candidate_id: 0, fp: "fp-1", title: "Known report" }],
        findings: {
          leads: [
            {
              candidate_titles: ["A title the LLM reworded and no pick matches"],
              title: "Reworded lead",
              relationship: "shared_tradecraft",
              confidence: "low",
              vertex_signal: { adversary: "none", capability: "partial", infrastructure: "none", victim: "none" },
              bluf: "b",
              evidence: [],
              gaps: "g",
            },
          ],
          no_match: [],
          synthesis: { bluf: "b", correlation_signal: "low", reasoning: "r", gaps: "g", next_steps: [] },
        },
      });

      const out = await server.tool("get_correlation_run").callback({ run_id: "exec-miss" });
      const body = parseToolText<{
        unresolved_candidate_titles: Array<{ where: string; index: number; title: string }>;
        summary: string;
        findings: { leads: Array<{ candidate_ids: string[] }> };
      }>(out);

      // Reported in the response …
      expect(body.unresolved_candidate_titles).toHaveLength(1);
      expect(body.unresolved_candidate_titles[0]).toMatchObject({ where: "lead", index: 0 });
      expect(body.summary).toContain("WARNING");
      // … logged loudly …
      expect(warnSpy).toHaveBeenCalledOnce();
      // … and still rendered (fallback to the title string).
      expect(body.findings.leads[0].candidate_ids).toEqual([
        "A title the LLM reworded and no pick matches",
      ]);
      warnSpy.mockRestore();
    });

    it("reports no unresolved titles on a clean resolve", async () => {
      vi.mocked(correlationService.getCorrelationRun).mockResolvedValueOnce({
        found: true,
        run_id: "exec-clean",
        status: "completed",
        depth: "full",
        picks: [{ candidate_id: 0, fp: "fp-1", title: "Known report" }],
        findings: {
          leads: [
            {
              candidate_titles: ["Known report"],
              title: "Clean lead",
              relationship: "same_actor",
              confidence: "high",
              vertex_signal: { adversary: "high", capability: "high", infrastructure: "none", victim: "none" },
              bluf: "b",
              evidence: [],
              gaps: "g",
            },
          ],
          no_match: [],
          synthesis: { bluf: "b", correlation_signal: "high", reasoning: "r", gaps: "g", next_steps: [] },
        },
      });

      const out = await server.tool("get_correlation_run").callback({ run_id: "exec-clean" });
      const body = parseToolText<{
        unresolved_candidate_titles: unknown[];
        summary: string;
      }>(out);
      expect(body.unresolved_candidate_titles).toHaveLength(0);
      expect(body.summary).not.toContain("WARNING");
    });

    it("returns null findings for non-full depth (no synthesis to render)", async () => {
      vi.mocked(correlationService.getCorrelationRun).mockResolvedValueOnce({
        found: true,
        run_id: "exec-cheap",
        status: "completed",
        depth: "cheap",
        counts: { pool: 42 },
      });

      const out = await server.tool("get_correlation_run").callback({ run_id: "exec-cheap" });
      const body = parseToolText<{ found: boolean; findings: unknown }>(out);
      expect(body.found).toBe(true);
      expect(body.findings).toBeNull();
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
