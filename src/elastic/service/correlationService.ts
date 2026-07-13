/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

import type { EsClient } from "../es-client/index.js";
import type { KibanaClient } from "../kibana-client/index.js";
import { DIAMOND_VERTICES } from "../../correlation/tradecraft.js";
import type { DiamondVertex } from "../../correlation/tradecraft.js";

// ---------------------------------------------------------------------------
// Constants — mirror kibana-threat-intel-poc constants
// ---------------------------------------------------------------------------

// Report corpus index pattern. Env-configurable so this app can point at the
// threat-intel-ingest corpus (`ti-reports*`, the default) or a different
// deployment's index without a code change. Set TI_REPORTS_INDEX_PATTERN to
// override (e.g. back to ".kibana-threat-reports*" for the IntelligenceHub corpus).
const THREAT_REPORTS_INDEX_PATTERN =
  process.env.TI_REPORTS_INDEX_PATTERN?.trim() || "ti-reports*";

// Authoritative correlation path: the `ti-correlation` Kibana Workflow does the
// retrieval → Sonnet triage → Opus synthesis and writes one run record per
// execution (`_id = execution id`) into the correlations index. The MCP app
// triggers the workflow and polls that index by run_id — it does NOT synthesize.
// Both are env-overridable to match a deployment's config.sh values.
const CORRELATIONS_INDEX =
  process.env.TI_CORRELATIONS_INDEX?.trim() || "ti-correlations";
const CORRELATION_WORKFLOW_ID =
  process.env.TI_CORRELATION_WORKFLOW_ID?.trim() || "ti-correlation";
// Kibana Workflows public route is date-versioned on 9.5.x (see deploy.sh).
const WORKFLOWS_API_VERSION = "2023-10-31";
const NOISE_FLOOR = 0.7;
const KNN_CANDIDATES_PER_VERTEX = 50;
const DEFAULT_SIZE = 20;
const MAX_SIZE = 50;
const HASH_IOC_TYPE = "hash" as const;
const NETWORK_IOC_TYPES = new Set(["ip", "domain", "url"]);

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface DiamondVertexQueries {
  adversary?: string;
  capability?: string;
  infrastructure?: string;
  victim?: string;
}

export interface AnchorIoc {
  type: string;
  value: string;
}

export interface DiamondSearchParams {
  /** Free-text vertex summaries from the host model's case summarisation. */
  vertex_queries?: DiamondVertexQueries;
  /** Optional IOC anchors (hash / ip / domain / url). */
  iocs?: AnchorIoc[];
  /** Maximum stubs to return. Default 20, cap 50. */
  size?: number;
}

export interface ReportStub {
  report_id: string;
  title: string;
  vendor: string;
  url: string;
}

/** A matched vertex with its evidence summary text (no score). */
export interface MatchedVertex {
  vertex: DiamondVertex;
  summary: string;
}

/**
 * A candidate stub for the BLIND autonomous path (diamond_search).
 * Carries which vertices matched and their evidence summaries — NO scores.
 * The model triages on evidence text, not similarity rank.
 */
export interface BlindReportStub {
  report_id: string;
  title: string;
  vendor: string;
  url: string;
  /** Vertices that scored >= NOISE_FLOOR, in DIAMOND_VERTICES order, with evidence text. */
  matched_vertices?: MatchedVertex[];
}

export interface DiamondSearchResult {
  candidates: BlindReportStub[];
  total: number;
  /** True when inference was unavailable and BM25 fallback was used. */
  degraded: boolean;
  vertices_queried: DiamondVertex[];
}

export interface ReportFull {
  report_id: string;
  title: string;
  vendor: string;
  url: string;
  body_text: string;
}

// ---------------------------------------------------------------------------
// Scored types — analyst-led transparent path (diamond_search_analyst)
// ---------------------------------------------------------------------------

/** Per-report vertex match scores (only vertices that scored >= NOISE_FLOOR). */
export type VertexScores = Partial<Record<DiamondVertex, number>>;

/** A candidate stub WITH scores — returned by the analyst-led search path. */
export interface ScoredStub {
  report_id: string;
  title: string;
  vendor: string;
  url: string;
  /** Scores for each vertex that matched above NOISE_FLOOR (0.7). Keys present only for matched vertices. */
  vertex_scores: VertexScores;
  /** Number of vertices that scored >= NOISE_FLOOR. */
  overlap: number;
  /** Highest score across all matched vertices. */
  max_score: number;
}

/**
 * Coverage signal for the backfill-suggestion nudge.
 * thin = true when: the search degraded to BM25, OR avg_overlap across returned
 * candidates is less than 2 matched vertices (threshold chosen to flag cases where
 * most candidates matched only a single vertex — weak retrieval signal).
 */
export interface CoverageSignal {
  /** Number of vertices that had a non-empty query. */
  queried: number;
  /** Mean overlap (matched vertices per candidate) across the returned candidates. 0 when no candidates. */
  avg_overlap: number;
  /** True when degraded OR avg_overlap < 2. Advisory: consider BM25 backfill. */
  thin: boolean;
}

export interface DiamondSearchScoredResult {
  candidates: ScoredStub[];
  total: number;
  /** True when inference was unavailable and BM25 fallback was used. Scores are absent when degraded. */
  degraded: boolean;
  vertices_queried: DiamondVertex[];
  coverage: CoverageSignal;
}

// ---------------------------------------------------------------------------
// Internal ES response shapes
// ---------------------------------------------------------------------------

interface EsHit<T> {
  _id: string;
  _score?: number | null;
  _source?: T;
}

interface EsSearchResponse<T> {
  hits: {
    total?: number | { value: number };
    hits: Array<EsHit<T>>;
  };
}

interface EsMsearchResponse<T> {
  responses: Array<
    | { hits: { hits: Array<EsHit<T>> }; error?: undefined }
    | { error: Record<string, unknown>; hits?: undefined }
  >;
}

interface SourceFields {
  "@timestamp"?: string;
  content?: { title?: string };
  source?: { name?: string; type?: string; url?: string };
  severity?: { level?: string };
  provenance?: { extracted_at?: string };
  extracted?: {
    diamond?: Partial<Record<DiamondVertex, { summary?: string }>>;
  };
}

interface SourceFieldsFull extends SourceFields {
  content?: { title?: string; body_text?: string };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const toStub = (hit: EsHit<SourceFields>): ReportStub => ({
  report_id: hit._id,
  title: hit._source?.content?.title?.trim() ?? hit._id,
  vendor: hit._source?.source?.name ?? hit._source?.source?.type ?? "unknown",
  url: hit._source?.source?.url ?? "",
});

const splitIocs = (
  iocs: AnchorIoc[]
): { hashValues: string[]; networkValues: string[] } => {
  const hashValues = new Set<string>();
  const networkValues = new Set<string>();
  for (const { type, value } of iocs) {
    if (!value) continue;
    if (type === HASH_IOC_TYPE) {
      hashValues.add(value.toLowerCase());
    } else if (NETWORK_IOC_TYPES.has(type)) {
      networkValues.add(value.toLowerCase());
    }
  }
  return { hashValues: [...hashValues], networkValues: [...networkValues] };
};

// ---------------------------------------------------------------------------
// Semantic per-vertex search (msearch via raw REST)
// ---------------------------------------------------------------------------

const runSemanticSearch = async (
  esClient: EsClient,
  queriedVertices: DiamondVertex[],
  vertexQueries: DiamondVertexQueries,
  size: number
): Promise<{ stubs: BlindReportStub[]; total: number; degraded: false }> => {
  // Build ndjson body: one header + body pair per vertex.
  const vertexSummaryFields = DIAMOND_VERTICES.map((v) => `extracted.diamond.${v}.summary`);
  const lines: string[] = [];
  for (const vertex of queriedVertices) {
    lines.push(
      JSON.stringify({
        index: THREAT_REPORTS_INDEX_PATTERN,
        ignore_unavailable: true,
      })
    );
    lines.push(
      JSON.stringify({
        query: {
          bool: {
            must: [
              {
                semantic: {
                  field: `extracted.diamond.${vertex}.summary`,
                  query: vertexQueries[vertex],
                },
              },
            ],
            filter: [{ term: { "extracted.diamond.suitable": true } }],
          },
        },
        size: KNN_CANDIDATES_PER_VERTEX,
        _source: [
          "content.title",
          "source.name",
          "source.type",
          "source.url",
          ...vertexSummaryFields,
        ],
      })
    );
  }
  const ndjson = lines.join("\n") + "\n";

  const resp = await esClient.post<EsMsearchResponse<SourceFields>>(
    "/_msearch",
    ndjson,
    { headers: { "Content-Type": "application/x-ndjson" } }
  );
  const msearch = resp.data;

  // Build score matrix: reportId → { source, scores: { vertex → score } }
  const matrix = new Map<
    string,
    { source: SourceFields; scores: Partial<Record<DiamondVertex, number>> }
  >();

  for (let i = 0; i < queriedVertices.length; i++) {
    const vertex = queriedVertices[i];
    const response = msearch.responses[i];
    if ("error" in response && response.error) {
      const errMsg = JSON.stringify(response.error).toLowerCase();
      if (errMsg.includes("inference") || errMsg.includes("service_unavailable")) {
        throw new Error(`inference_unavailable: ${JSON.stringify(response.error)}`);
      }
      // Non-inference errors: skip this vertex quietly.
      continue;
    }
    const hits = response.hits?.hits ?? [];
    for (const hit of hits) {
      if (!matrix.has(hit._id)) {
        matrix.set(hit._id, { source: hit._source ?? {}, scores: {} });
      }
      const entry = matrix.get(hit._id)!;
      entry.scores[vertex] = hit._score ?? 0;
    }
  }

  // Qualify: at least one vertex score >= NOISE_FLOOR.
  const candidates: Array<{ stub: BlindReportStub; overlap: number; maxScore: number }> = [];

  for (const [reportId, { source, scores }] of matrix) {
    const aboveFloor = DIAMOND_VERTICES.filter(
      (v) => scores[v] !== undefined && (scores[v] as number) >= NOISE_FLOOR
    );
    if (aboveFloor.length === 0) continue;
    const aboveScores = aboveFloor.map((v) => scores[v] as number);

    // Build matched_vertices in deterministic DIAMOND_VERTICES order, no scores.
    const matched_vertices: MatchedVertex[] = aboveFloor
      .filter((v) => {
        const summary = source.extracted?.diamond?.[v]?.summary;
        return summary != null && summary.length > 0;
      })
      .map((v) => ({
        vertex: v,
        summary: source.extracted!.diamond![v]!.summary as string,
      }));

    candidates.push({
      stub: {
        report_id: reportId,
        title: source.content?.title?.trim() ?? reportId,
        vendor: source.source?.name ?? source.source?.type ?? "unknown",
        url: source.source?.url ?? "",
        ...(matched_vertices.length > 0 ? { matched_vertices } : {}),
      },
      overlap: aboveFloor.length,
      maxScore: Math.max(...aboveScores),
    });
  }

  // Sort: overlap desc, maxScore desc — mirrors Mustard compact_output sort key.
  candidates.sort((a, b) =>
    b.overlap !== a.overlap ? b.overlap - a.overlap : b.maxScore - a.maxScore
  );

  return {
    stubs: candidates.slice(0, size).map((c) => c.stub),
    total: candidates.length,
    degraded: false,
  };
};

// ---------------------------------------------------------------------------
// BM25 fallback
// ---------------------------------------------------------------------------

const runBm25Fallback = async (
  esClient: EsClient,
  queriedVertices: DiamondVertex[],
  vertexQueries: DiamondVertexQueries,
  size: number
): Promise<{ stubs: BlindReportStub[]; total: number; degraded: true }> => {
  const combinedQuery = queriedVertices
    .map((v) => vertexQueries[v])
    .filter(Boolean)
    .join(" ");

  const resp = await esClient.post<EsSearchResponse<SourceFields>>(
    `/${THREAT_REPORTS_INDEX_PATTERN}/_search`,
    {
      size,
      track_total_hits: true,
      _source: ["content.title", "source.name", "source.type", "source.url"],
      query: {
        bool: {
          must: [
            {
              multi_match: {
                query: combinedQuery,
                fields: ["content.title_bm25^2", "content.body_text_bm25"],
              },
            },
          ],
          filter: [{ term: { "extracted.diamond.suitable": true } }],
        },
      },
    }
  );

  const hits = resp.data.hits.hits ?? [];
  const total =
    typeof resp.data.hits.total === "number"
      ? resp.data.hits.total
      : (resp.data.hits.total?.value ?? hits.length);

  return {
    stubs: hits.map(toStub),
    total,
    degraded: true,
  };
};

// ---------------------------------------------------------------------------
// Anchor search (exact hash/ioc_set_hash/actor — discriminating gate)
// ---------------------------------------------------------------------------

const runAnchorSearch = async (
  esClient: EsClient,
  iocs: AnchorIoc[],
  size: number,
  excludeIds: Set<string>
): Promise<ReportStub[]> => {
  const { hashValues, networkValues } = splitIocs(iocs);
  if (hashValues.length === 0 && networkValues.length === 0) return [];

  // Gate: at least one hash IOC must match (discriminating only; no network-only).
  if (hashValues.length === 0) return [];

  const gateDisc = [
    {
      nested: {
        path: "extracted.iocs",
        query: {
          bool: {
            must: [
              { term: { "extracted.iocs.type": HASH_IOC_TYPE } },
              { terms: { "extracted.iocs.value": hashValues } },
            ],
          },
        },
      },
    },
  ];

  const shouldClauses: Array<Record<string, unknown>> = [
    {
      constant_score: {
        filter: {
          nested: {
            path: "extracted.iocs",
            query: {
              bool: {
                must: [
                  { term: { "extracted.iocs.type": HASH_IOC_TYPE } },
                  { terms: { "extracted.iocs.value": hashValues } },
                ],
              },
            },
          },
        },
        boost: 4.0,
      },
    },
  ];

  if (networkValues.length > 0) {
    shouldClauses.push({
      constant_score: {
        filter: {
          nested: {
            path: "extracted.iocs",
            query: {
              bool: {
                must: [
                  { terms: { "extracted.iocs.type": [...NETWORK_IOC_TYPES] } },
                  { terms: { "extracted.iocs.value": networkValues } },
                ],
              },
            },
          },
        },
        boost: 1.5,
      },
    });
  }

  const mustNotClauses: Array<Record<string, unknown>> = excludeIds.size > 0
    ? [{ ids: { values: [...excludeIds] } }]
    : [];

  const resp = await esClient.post<EsSearchResponse<SourceFields>>(
    `/${THREAT_REPORTS_INDEX_PATTERN}/_search`,
    {
      size,
      track_total_hits: true,
      _source: ["content.title", "source.name", "source.type", "source.url"],
      query: {
        bool: {
          filter: [{ bool: { should: gateDisc, minimum_should_match: 1 } }],
          should: shouldClauses,
          minimum_should_match: 0,
          ...(mustNotClauses.length > 0 ? { must_not: mustNotClauses } : {}),
        },
      },
    }
  );

  return (resp.data.hits.hits ?? []).map(toStub);
};

// ---------------------------------------------------------------------------
// Scored semantic search — surfaces the score matrix instead of stripping it
// ---------------------------------------------------------------------------

const runSemanticSearchScored = async (
  esClient: EsClient,
  queriedVertices: DiamondVertex[],
  vertexQueries: DiamondVertexQueries,
  size: number
): Promise<{ candidates: ScoredStub[]; total: number; degraded: false }> => {
  const lines: string[] = [];
  for (const vertex of queriedVertices) {
    lines.push(
      JSON.stringify({
        index: THREAT_REPORTS_INDEX_PATTERN,
        ignore_unavailable: true,
      })
    );
    lines.push(
      JSON.stringify({
        query: {
          bool: {
            must: [
              {
                semantic: {
                  field: `extracted.diamond.${vertex}.summary`,
                  query: vertexQueries[vertex],
                },
              },
            ],
            filter: [{ term: { "extracted.diamond.suitable": true } }],
          },
        },
        size: KNN_CANDIDATES_PER_VERTEX,
        _source: ["content.title", "source.name", "source.type", "source.url"],
      })
    );
  }
  const ndjson = lines.join("\n") + "\n";

  const resp = await esClient.post<EsMsearchResponse<SourceFields>>(
    "/_msearch",
    ndjson,
    { headers: { "Content-Type": "application/x-ndjson" } }
  );
  const msearch = resp.data;

  const matrix = new Map<
    string,
    { source: SourceFields; scores: VertexScores }
  >();

  for (let i = 0; i < queriedVertices.length; i++) {
    const vertex = queriedVertices[i];
    const response = msearch.responses[i];
    if ("error" in response && response.error) {
      const errMsg = JSON.stringify(response.error).toLowerCase();
      if (errMsg.includes("inference") || errMsg.includes("service_unavailable")) {
        throw new Error(`inference_unavailable: ${JSON.stringify(response.error)}`);
      }
      continue;
    }
    const hits = response.hits?.hits ?? [];
    for (const hit of hits) {
      if (!matrix.has(hit._id)) {
        matrix.set(hit._id, { source: hit._source ?? {}, scores: {} });
      }
      const entry = matrix.get(hit._id)!;
      entry.scores[vertex] = hit._score ?? 0;
    }
  }

  const candidates: ScoredStub[] = [];

  for (const [reportId, { source, scores }] of matrix) {
    const aboveFloor = DIAMOND_VERTICES.filter(
      (v) => scores[v] !== undefined && (scores[v] as number) >= NOISE_FLOOR
    );
    if (aboveFloor.length === 0) continue;
    const aboveScores = aboveFloor.map((v) => scores[v] as number);
    // Include only scores at or above the noise floor in the returned vertex_scores.
    const filteredScores: VertexScores = {};
    for (const v of aboveFloor) {
      filteredScores[v] = scores[v];
    }
    candidates.push({
      report_id: reportId,
      title: source.content?.title?.trim() ?? reportId,
      vendor: source.source?.name ?? source.source?.type ?? "unknown",
      url: source.source?.url ?? "",
      vertex_scores: filteredScores,
      overlap: aboveFloor.length,
      max_score: Math.max(...aboveScores),
    });
  }

  candidates.sort((a, b) =>
    b.overlap !== a.overlap ? b.overlap - a.overlap : b.max_score - a.max_score
  );

  return {
    candidates: candidates.slice(0, size),
    total: candidates.length,
    degraded: false,
  };
};

// ---------------------------------------------------------------------------
// Public service
// ---------------------------------------------------------------------------

interface CorrelationServiceOptions {
  readonly esClient: EsClient;
  /** Required for the workflow-driven `correlate` path; retrieval tools work without it. */
  readonly kibanaClient?: KibanaClient;
}

export type CorrelationDepth = "free" | "cheap" | "med" | "full";

export interface RunCorrelationParams {
  /** Stored corpus report _id (content_fingerprint). Mutually exclusive with raw_text. */
  report_id?: string;
  /** Pasted case text. Mutually exclusive with report_id. */
  raw_text?: string;
  depth?: CorrelationDepth;
  triage_pool?: number;
  triage_floor?: number;
}

export interface RunCorrelationResult {
  run_id: string;
  workflow_id: string;
  depth: CorrelationDepth;
}

/** One triage pick as stored on the run record (title↔fp bridge for rendering). */
export interface CorrelationPick {
  candidate_id: number;
  fp: string;
  title?: string;
  /** Source vendor (source.name) — carried on the pick by the workflow build_picks step. */
  vendor?: string;
  /** Source article URL (source.url) — carried on the pick by the workflow build_picks step. */
  url?: string;
  hypothesis?: string;
  confidence?: number;
  justification?: string;
}

/** One fused-pool candidate (audit-only `candidates` array on the run record). The
 *  anchor-trail builder joins these to picks (by fp/id) and leads (by title). */
export interface CorrelationPoolCandidate {
  id: string;
  overlap?: number;
  has_anchor?: boolean;
  anchor_score?: number;
  /** Shares a distinctive code/execution token (extracted.code_tokens) with the case. */
  has_phrase_anchor?: boolean;
  phrase_score?: number;
  free_score?: number;
  diamond_max?: number;
  retrieval_source?: string;
}

/** Case anchors the workflow searched (audit-only `case.anchors`, enabled:false). */
export interface CorrelationCaseAnchors {
  hashes?: string[];
  network?: string[];
  artifacts?: string[];
  techniques?: string[];
  /** Distinctive code/execution tokens searched as exact "phrase anchors". */
  code_tokens?: string[];
  iocs?: Array<{ type?: string; value?: string; defanged?: string }>;
  artifact_objs?: Array<{ type?: string; value?: string; context?: string }>;
}

/** Verbatim `_source` of a ti-correlations run record (subset we surface). */
export interface CorrelationRunRecord {
  found: boolean;
  run_id?: string;
  status?: string;
  depth?: string;
  counts?: Record<string, number>;
  case?: {
    mode?: string;
    title?: string;
    anchors?: CorrelationCaseAnchors;
    /** Case's own per-vertex signal (NONE/PARTIAL/HIGH) — drives the case-signal diamond. */
    vertex_signal?: Record<string, string>;
  } & Record<string, unknown>;
  /** Workflow-shaped CorrelationFindings (leads reference candidates by title). */
  findings?: Record<string, unknown>;
  picks?: CorrelationPick[];
  /** Fused-pool candidates (audit-only) — drives the anchor trail. */
  candidates?: CorrelationPoolCandidate[];
  trace?: Record<string, unknown>;
  error?: string;
}

export class CorrelationService {
  constructor(private readonly options: CorrelationServiceOptions) {}

  /**
   * Trigger the `ti-correlation` Kibana Workflow (async). Returns immediately
   * with the execution id — the workflow runs in Task Manager (full depth can
   * take minutes; the POST does not block). Poll {@link getCorrelationRun} with
   * the returned run_id to read the authoritative findings.
   */
  async runCorrelation(params: RunCorrelationParams): Promise<RunCorrelationResult> {
    const { kibanaClient } = this.options;
    if (!kibanaClient) {
      throw new Error(
        "correlate requires a Kibana client — the correlation workflow is triggered via the Kibana Workflows API."
      );
    }
    const reportId = params.report_id?.trim() ?? "";
    const rawText = params.raw_text?.trim() ?? "";
    if (!reportId && !rawText) {
      throw new Error("correlate requires either report_id or raw_text.");
    }
    if (reportId && rawText) {
      throw new Error("correlate takes report_id OR raw_text, not both.");
    }
    const depth: CorrelationDepth = params.depth ?? "full";
    const inputs: Record<string, unknown> = {
      report_id: reportId,
      raw_text: rawText,
      depth,
      triage_pool: params.triage_pool ?? 120,
      triage_floor: params.triage_floor ?? 0.65,
    };
    const resp = await kibanaClient.post<{ workflowExecutionId: string }>(
      `/api/workflows/workflow/${CORRELATION_WORKFLOW_ID}/run`,
      { inputs },
      { headers: { "elastic-api-version": WORKFLOWS_API_VERSION } }
    );
    const runId = resp.data?.workflowExecutionId;
    if (!runId) {
      throw new Error(`workflow run did not return an execution id: ${JSON.stringify(resp.data)}`);
    }
    return { run_id: runId, workflow_id: CORRELATION_WORKFLOW_ID, depth };
  }

  /**
   * Read one correlation run record by run_id (= workflow execution id) from the
   * correlations index. Returns `{ found: false }` while the run is still in
   * flight (the doc is written by the workflow's terminal persist step) or if the
   * id is unknown.
   */
  async getCorrelationRun(runId: string): Promise<CorrelationRunRecord> {
    const { esClient } = this.options;
    const id = runId.trim();
    if (!id) throw new Error("get_correlation_run requires a run_id.");
    try {
      const resp = await esClient.get<{
        found: boolean;
        _source?: Record<string, unknown>;
      }>(`/${CORRELATIONS_INDEX}/_doc/${encodeURIComponent(id)}`);
      const source = resp.data?._source;
      if (!resp.data?.found || !source) return { found: false };
      return {
        found: true,
        run_id: source.run_id as string | undefined,
        status: source.status as string | undefined,
        depth: source.depth as string | undefined,
        counts: source.counts as Record<string, number> | undefined,
        case: source.case as CorrelationRunRecord["case"],
        findings: source.findings as Record<string, unknown> | undefined,
        picks: source.picks as CorrelationPick[] | undefined,
        candidates: source.candidates as CorrelationPoolCandidate[] | undefined,
        trace: source.trace as Record<string, unknown> | undefined,
        error: source.error as string | undefined,
      };
    } catch (err) {
      const msg = String((err as Error)?.message ?? "");
      // 404 = index/doc not present yet (run still in flight) → not-found, not fatal.
      if (msg.includes("404") || msg.includes("index_not_found")) {
        return { found: false };
      }
      throw err;
    }
  }

  /**
   * Diamond Model correlation search.
   *
   * Runs per-vertex semantic search (one msearch round trip) over
   * `extracted.diamond.{vertex}.summary`, qualifies candidates at NOISE_FLOOR
   * 0.70, and sorts by (overlap, max_score).  Optionally merges exact-hash
   * anchor hits at the front.  Degrades to BM25 when inference is unavailable.
   *
   * Returns stubs only — no scores exposed (blind-pack pattern).
   */
  async diamondSearch(params: DiamondSearchParams): Promise<DiamondSearchResult> {
    const { esClient } = this.options;
    const size = Math.min(params.size ?? DEFAULT_SIZE, MAX_SIZE);
    const vertexQueries = params.vertex_queries ?? {};

    const queriedVertices = DIAMOND_VERTICES.filter(
      (v) => (vertexQueries[v] ?? "").trim().length > 0
    );

    if (queriedVertices.length === 0) {
      return { candidates: [], total: 0, degraded: false, vertices_queried: [] };
    }

    let semanticResult: { stubs: BlindReportStub[]; total: number; degraded: boolean };
    try {
      semanticResult = await runSemanticSearch(esClient, queriedVertices, vertexQueries, size);
    } catch (err) {
      const msg = String((err as Error)?.message ?? "").toLowerCase();
      const isInferenceUnavailable =
        msg.includes("inference_unavailable") ||
        msg.includes("service_unavailable") ||
        msg.includes("503");

      if (isInferenceUnavailable) {
        semanticResult = await runBm25Fallback(esClient, queriedVertices, vertexQueries, size);
      } else {
        throw err;
      }
    }

    // Merge anchor hits (hash IOCs) at the front if provided.
    let candidates = semanticResult.stubs;
    if (params.iocs && params.iocs.length > 0) {
      const anchorHits = await runAnchorSearch(esClient, params.iocs, size, new Set());
      // De-duplicate: anchor-first, then semantic hits not already in anchors.
      const anchorIds = new Set(anchorHits.map((c) => c.report_id));
      const semanticOnly = candidates.filter((c) => !anchorIds.has(c.report_id));
      // Anchor hits carry no vertex summary data (BM25 path); matched_vertices omitted.
      candidates = [...(anchorHits as BlindReportStub[]), ...semanticOnly].slice(0, size);
    }

    return {
      candidates,
      total: semanticResult.total,
      degraded: semanticResult.degraded,
      vertices_queried: queriedVertices,
    };
  }

  /**
   * Analyst-led transparent Diamond Model correlation search.
   *
   * Identical retrieval logic to diamondSearch() but surfaces the full score
   * matrix (vertex_scores per candidate) instead of stripping it. Also computes
   * a coverage signal that drives the "consider BM25 backfill" nudge in the UI.
   *
   * coverage.thin = true when:
   *   - inference degraded to BM25 (scores unavailable), OR
   *   - avg_overlap across returned candidates < 2 (most candidates matched only
   *     one vertex — weak multi-vertex retrieval signal)
   *
   * The 2-vertex threshold is deterministic and documented here. It was chosen
   * to flag searches where single-vertex recall dominates, which tends to
   * produce noisier rankings than true multi-vertex overlap.
   */
  async diamondSearchScored(params: DiamondSearchParams): Promise<DiamondSearchScoredResult> {
    const { esClient } = this.options;
    const size = Math.min(params.size ?? DEFAULT_SIZE, MAX_SIZE);
    const vertexQueries = params.vertex_queries ?? {};

    const queriedVertices = DIAMOND_VERTICES.filter(
      (v) => (vertexQueries[v] ?? "").trim().length > 0
    );

    const emptyResult = (degraded: boolean): DiamondSearchScoredResult => ({
      candidates: [],
      total: 0,
      degraded,
      vertices_queried: queriedVertices,
      coverage: { queried: queriedVertices.length, avg_overlap: 0, thin: true },
    });

    if (queriedVertices.length === 0) {
      return emptyResult(false);
    }

    let semanticResult: { candidates: ScoredStub[]; total: number; degraded: boolean };
    try {
      semanticResult = await runSemanticSearchScored(esClient, queriedVertices, vertexQueries, size);
    } catch (err) {
      const msg = String((err as Error)?.message ?? "").toLowerCase();
      const isInferenceUnavailable =
        msg.includes("inference_unavailable") ||
        msg.includes("service_unavailable") ||
        msg.includes("503");

      if (isInferenceUnavailable) {
        // BM25 fallback: return stubs with empty vertex_scores.
        const bm25 = await runBm25Fallback(esClient, queriedVertices, vertexQueries, size);
        const bm25Scored: ScoredStub[] = bm25.stubs.map((s) => ({
          ...s,
          vertex_scores: {},
          overlap: 0,
          max_score: 0,
        }));
        return {
          candidates: bm25Scored,
          total: bm25.total,
          degraded: true,
          vertices_queried: queriedVertices,
          coverage: { queried: queriedVertices.length, avg_overlap: 0, thin: true },
        };
      } else {
        throw err;
      }
    }

    let candidates = semanticResult.candidates;
    if (params.iocs && params.iocs.length > 0) {
      const anchorStubs = await runAnchorSearch(esClient, params.iocs, size, new Set());
      const anchorIds = new Set(anchorStubs.map((c) => c.report_id));
      const anchorScored: ScoredStub[] = anchorStubs.map((s) => ({
        ...s,
        vertex_scores: {},
        overlap: 0,
        max_score: 0,
      }));
      const semanticOnly = candidates.filter((c) => !anchorIds.has(c.report_id));
      candidates = [...anchorScored, ...semanticOnly].slice(0, size);
    }

    const avg_overlap =
      candidates.length > 0
        ? candidates.reduce((sum, c) => sum + c.overlap, 0) / candidates.length
        : 0;

    const coverage: CoverageSignal = {
      queried: queriedVertices.length,
      avg_overlap,
      thin: semanticResult.degraded || avg_overlap < 2,
    };

    return {
      candidates,
      total: semanticResult.total,
      degraded: semanticResult.degraded,
      vertices_queried: queriedVertices,
      coverage,
    };
  }

  /**
   * Fetch full text for a list of report IDs.
   *
   * Returns content.body_text + title + vendor + url per report.
   * Uses a terms query on _id (ES rejects wildcard GET-by-id on data streams).
   */
  async getReports(reportIds: string[]): Promise<ReportFull[]> {
    if (reportIds.length === 0) return [];

    const { esClient } = this.options;

    const resp = await esClient.post<EsSearchResponse<SourceFieldsFull>>(
      `/${THREAT_REPORTS_INDEX_PATTERN}/_search`,
      {
        size: reportIds.length,
        query: { terms: { _id: reportIds } },
        _source: [
          "content.title",
          "content.body_text",
          "source.name",
          "source.type",
          "source.url",
        ],
      }
    );

    return (resp.data.hits.hits ?? []).map((hit) => ({
      report_id: hit._id,
      title: hit._source?.content?.title?.trim() ?? hit._id,
      vendor: hit._source?.source?.name ?? hit._source?.source?.type ?? "unknown",
      url: hit._source?.source?.url ?? "",
      body_text: hit._source?.content?.body_text ?? "",
    }));
  }
}
