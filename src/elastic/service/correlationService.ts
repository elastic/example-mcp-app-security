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
import { DIAMOND_VERTICES } from "../../correlation/tradecraft.js";
import type { DiamondVertex } from "../../correlation/tradecraft.js";

// ---------------------------------------------------------------------------
// Constants — mirror kibana-threat-intel-poc constants
// ---------------------------------------------------------------------------

const THREAT_REPORTS_INDEX_PATTERN = ".kibana-threat-reports*";
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

export interface DiamondSearchResult {
  candidates: ReportStub[];
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
): Promise<{ stubs: ReportStub[]; total: number; degraded: false }> => {
  // Build ndjson body: one header + body pair per vertex.
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
  const candidates: Array<{ stub: ReportStub; overlap: number; maxScore: number }> = [];

  for (const [reportId, { source, scores }] of matrix) {
    const aboveFloor = DIAMOND_VERTICES.filter(
      (v) => scores[v] !== undefined && (scores[v] as number) >= NOISE_FLOOR
    );
    if (aboveFloor.length === 0) continue;
    const aboveScores = aboveFloor.map((v) => scores[v] as number);
    candidates.push({
      stub: {
        report_id: reportId,
        title: source.content?.title?.trim() ?? reportId,
        vendor: source.source?.name ?? source.source?.type ?? "unknown",
        url: source.source?.url ?? "",
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
): Promise<{ stubs: ReportStub[]; total: number; degraded: true }> => {
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
}

export class CorrelationService {
  constructor(private readonly options: CorrelationServiceOptions) {}

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

    let semanticResult: { stubs: ReportStub[]; total: number; degraded: boolean };
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
      candidates = [...anchorHits, ...semanticOnly].slice(0, size);
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
