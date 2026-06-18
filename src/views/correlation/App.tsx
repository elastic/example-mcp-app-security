/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useEffect, useState } from "react";
import { extractToolText } from "../../shared/extract-tool-text";
import { useMcpApp, useMcpAppEvents } from "../../shared/hooks/useMcpApp";
import { McpAppProvider } from "../../shared/hooks/McpAppProvider";
import { useAnalytics } from "../../shared/hooks/useAnalytics";
import { AppGlyph } from "../../shared/components/icons/icons";
import "./styles.css";

// ---------------------------------------------------------------------------
// Types — mirror correlationService scored types (no import of server code)
// ---------------------------------------------------------------------------

type DiamondVertex = "adversary" | "capability" | "infrastructure" | "victim";

interface VertexScores {
  adversary?: number;
  capability?: number;
  infrastructure?: number;
  victim?: number;
}

interface ScoredStub {
  report_id: string;
  title: string;
  vendor: string;
  url: string;
  vertex_scores: VertexScores;
  overlap: number;
  max_score: number;
}

interface CoverageSignal {
  queried: number;
  avg_overlap: number;
  thin: boolean;
}

interface AnalystSearchResult {
  candidates: ScoredStub[];
  meta: {
    total: number;
    degraded: boolean;
    vertices_queried: DiamondVertex[];
  };
  coverage: CoverageSignal;
}

// ---------------------------------------------------------------------------
// Diamond geometry — ported from Kibana correlation_report.tsx
// viewBox: 0 0 160 160; nodes at ADV(top), INF(left), CAP(right), VIC(bottom)
// Collapsed size: 56px (matches Kibana's 80px < 100px label-hidden branch)
// ---------------------------------------------------------------------------

const VERTICES: ReadonlyArray<DiamondVertex> = [
  "adversary",
  "infrastructure",
  "capability",
  "victim",
];

const VERTEX_ABBREV: Record<DiamondVertex, string> = {
  adversary: "ADV",
  capability: "CAP",
  infrastructure: "INF",
  victim: "VIC",
};

type EdgeCoords = [number, number, number, number];

const DIAMOND_NODES: ReadonlyArray<{ vertex: DiamondVertex; cx: number; cy: number }> = [
  { vertex: "adversary", cx: 80, cy: 18 },
  { vertex: "infrastructure", cx: 18, cy: 80 },
  { vertex: "capability", cx: 142, cy: 80 },
  { vertex: "victim", cx: 80, cy: 142 },
];

const DIAMOND_EDGES: ReadonlyArray<EdgeCoords> = [
  [80, 18, 18, 80],
  [80, 18, 142, 80],
  [18, 80, 80, 142],
  [142, 80, 80, 142],
];

// Score thresholds for vertex color intensity (all scores are already >= NOISE_FLOOR 0.7)
const SCORE_HIGH = 0.9;

function vertexColor(score: number | undefined): string {
  if (score === undefined) return "#30302f"; // no match — muted
  if (score >= SCORE_HIGH) return "#40c790"; // strong match — green
  return "#f0b840"; // above noise floor but below high — amber
}

function vertexTextFill(score: number | undefined): string {
  if (score === undefined) return "#474745";
  if (score >= SCORE_HIGH) return "#ffffff";
  return "#1f1f1e"; // amber background needs dark text
}

interface CollapsedDiamondProps {
  vertex_scores: VertexScores;
  size?: number;
}

function CollapsedDiamond({ vertex_scores, size = 56 }: CollapsedDiamondProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 160 160"
      role="img"
      aria-label="Diamond Model correlation match"
      className="corr-diamond-svg"
    >
      {DIAMOND_EDGES.map(([x1, y1, x2, y2], i) => (
        <line
          key={i}
          x1={x1}
          y1={y1}
          x2={x2}
          y2={y2}
          stroke="#474745"
          strokeWidth={2}
        />
      ))}
      {DIAMOND_NODES.map(({ vertex, cx, cy }) => {
        const score = vertex_scores[vertex];
        return (
          <g key={vertex}>
            <circle cx={cx} cy={cy} r={18} fill={vertexColor(score)} />
            <text
              x={cx}
              y={cy}
              textAnchor="middle"
              dominantBaseline="middle"
              fontSize={10}
              fontWeight={700}
              fill={vertexTextFill(score)}
              aria-hidden="true"
            >
              {VERTEX_ABBREV[vertex]}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Coverage nudge banner
// ---------------------------------------------------------------------------

interface CoverageBannerProps {
  coverage: CoverageSignal;
  onDismiss: () => void;
}

function CoverageBanner({ coverage, onDismiss }: CoverageBannerProps) {
  const reason = coverage.avg_overlap < 2
    ? "low vertex overlap across candidates"
    : "inference unavailable — BM25 fallback used";
  return (
    <div className="corr-coverage-banner" role="alert">
      <span className="corr-coverage-banner-icon" aria-hidden="true">⚠</span>
      <span className="corr-coverage-banner-text">
        Diamond retrieval coverage is thin ({reason}) — consider a BM25 keyword backfill
        to surface additional candidates.
      </span>
      <button
        className="corr-coverage-banner-dismiss"
        onClick={onDismiss}
        aria-label="Dismiss coverage warning"
      >
        ×
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Candidate row — now with checkbox for selection
// ---------------------------------------------------------------------------

interface CandidateRowProps {
  stub: ScoredStub;
  rank: number;
  selected: boolean;
  onToggle: (id: string) => void;
}

function CandidateRow({ stub, rank, selected, onToggle }: CandidateRowProps) {
  const hasUrl = stub.url.length > 0;
  return (
    <div
      className={`corr-candidate-row${selected ? " corr-candidate-row-selected" : ""}`}
      onClick={() => onToggle(stub.report_id)}
      role="checkbox"
      aria-checked={selected}
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === " " || e.key === "Enter") onToggle(stub.report_id); }}
    >
      <span className="corr-candidate-rank" aria-label={`Rank ${rank}`}>
        {rank}
      </span>

      <CollapsedDiamond vertex_scores={stub.vertex_scores} size={56} />

      <div className="corr-candidate-meta">
        <div className="corr-candidate-title">
          {hasUrl ? (
            <a
              href={stub.url}
              target="_blank"
              rel="noopener noreferrer"
              className="corr-candidate-link"
              onClick={(e) => e.stopPropagation()}
            >
              {stub.title}
            </a>
          ) : (
            <span className="corr-candidate-title-text">{stub.title}</span>
          )}
        </div>
        <div className="corr-candidate-footer">
          <span className="corr-candidate-vendor">{stub.vendor}</span>
          <VertexScorePills scores={stub.vertex_scores} />
        </div>
      </div>

      <div className="corr-candidate-overlap" title="Matched vertices">
        <span className="corr-overlap-count">{stub.overlap}</span>
        <span className="corr-overlap-label">vtx</span>
      </div>

      <span
        className={`corr-candidate-check${selected ? " corr-candidate-check-on" : ""}`}
        aria-hidden="true"
      >
        {selected ? "✓" : ""}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Vertex score pills — compact inline cues
// ---------------------------------------------------------------------------

interface VertexScorePillsProps {
  scores: VertexScores;
}

function VertexScorePills({ scores }: VertexScorePillsProps) {
  const matched = VERTICES.filter((v) => scores[v] !== undefined);
  if (matched.length === 0) return null;
  return (
    <span className="corr-score-pills">
      {matched.map((v) => {
        const score = scores[v]!;
        const high = score >= SCORE_HIGH;
        return (
          <span
            key={v}
            className={`corr-score-pill ${high ? "corr-score-pill-high" : "corr-score-pill-mid"}`}
            title={`${VERTEX_ABBREV[v]}: ${score.toFixed(2)}`}
          >
            {VERTEX_ABBREV[v]} {score.toFixed(2)}
          </span>
        );
      })}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Empty / idle states
// ---------------------------------------------------------------------------

function IdleState() {
  return (
    <div className="corr-idle">
      <div className="corr-idle-diamond" aria-hidden="true">
        <CollapsedDiamond
          vertex_scores={{}}
          size={72}
        />
      </div>
      <div className="corr-idle-title">Correlation Triage</div>
      <div className="corr-idle-hint">
        Call <code>diamond_search_analyst</code> to surface ranked threat report candidates
        with per-vertex match scores.
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main App
// ---------------------------------------------------------------------------

export function App() {
  return (
    <McpAppProvider name="correlation" version="1.0.0">
      <AppContent />
    </McpAppProvider>
  );
}

function AppContent() {
  const [result, setResult] = useState<AnalystSearchResult | null>(null);
  const [coverageDismissed, setCoverageDismissed] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [synthesizing, setSynthesizing] = useState(false);

  const { connected, getApp } = useMcpApp();
  const { trackEvent } = useAnalytics();

  useEffect(() => {
    trackEvent({ eventType: "view_rendered", viewId: "threat-hunt" });
  }, [trackEvent]);

  useMcpAppEvents({
    onToolResult: (toolResult) => {
      try {
        const text = extractToolText(toolResult);
        if (!text) return;
        const data = JSON.parse(text);
        if (data && Array.isArray(data.candidates) && data.coverage && data.meta) {
          setResult(data as AnalystSearchResult);
          setCoverageDismissed(false);
          setSelectedIds(new Set());
        }
      } catch {
        // Not a correlation result — ignore.
      }
    },
  });

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const handleSynthesize = useCallback(async () => {
    const app = getApp();
    if (!app || selectedIds.size === 0) return;
    setSynthesizing(true);

    const ids = [...selectedIds];
    const idsJson = JSON.stringify(ids);
    const message =
      `PROCEED — deep-dive correlation on report_ids ${idsJson}: ` +
      `call get_report for their full text, synthesize per the synthesis rubric, ` +
      `then call render_correlation with the resulting CorrelationFindings.`;

    try {
      await app.sendMessage({
        role: "user",
        content: [{ type: "text", text: message }],
      });
    } catch {
      await app.updateModelContext({
        content: [{ type: "text", text: message }],
      });
    } finally {
      setSynthesizing(false);
    }
  }, [getApp, selectedIds]);

  if (!connected) {
    return (
      <div className="corr-app">
        <div className="corr-loading">
          <div className="corr-spinner" />
          <span>Connecting to server...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="corr-app">
      <header className="corr-header">
        <div className="corr-header-brand">
          <span className="corr-header-glyph" aria-hidden="true">
            <AppGlyph />
          </span>
          <h1 className="corr-header-title">Correlation Triage</h1>
        </div>
        {result && (
          <div className="corr-header-meta">
            <span className="corr-header-count">
              {result.candidates.length} of {result.meta.total} candidates
            </span>
            {result.meta.degraded && (
              <span className="corr-header-pill corr-header-pill-warn">BM25</span>
            )}
            {result.meta.vertices_queried.length > 0 && (
              <span className="corr-header-pill corr-header-pill-info">
                {result.meta.vertices_queried.map((v) => VERTEX_ABBREV[v]).join(" · ")}
              </span>
            )}
          </div>
        )}
      </header>

      <div className="corr-body">
        {result && result.coverage.thin && !coverageDismissed && (
          <CoverageBanner
            coverage={result.coverage}
            onDismiss={() => setCoverageDismissed(true)}
          />
        )}

        {!result ? (
          <IdleState />
        ) : result.candidates.length === 0 ? (
          <div className="corr-empty">
            <div className="corr-empty-title">No candidates found</div>
            <div className="corr-empty-hint">
              Try adjusting your vertex queries or adding IOC anchors.
            </div>
          </div>
        ) : (
          <>
            <div className="corr-list">
              <div className="corr-list-header">
                <span className="corr-list-col-rank" aria-hidden="true">#</span>
                <span className="corr-list-col-diamond" aria-hidden="true">Match</span>
                <span className="corr-list-col-report">Report</span>
                <span className="corr-list-col-overlap">Vtx</span>
                <span className="corr-list-col-sel" aria-hidden="true" />
              </div>
              {result.candidates.map((stub, i) => (
                <CandidateRow
                  key={stub.report_id}
                  stub={stub}
                  rank={i + 1}
                  selected={selectedIds.has(stub.report_id)}
                  onToggle={toggleSelect}
                />
              ))}
            </div>

            {selectedIds.size > 0 && (
              <div className="corr-synth-bar">
                <span className="corr-synth-bar-count">
                  {selectedIds.size} report{selectedIds.size !== 1 ? "s" : ""} selected
                </span>
                <button
                  className="corr-synth-btn"
                  onClick={handleSynthesize}
                  disabled={synthesizing}
                >
                  {synthesizing ? "Synthesizing…" : "Synthesize selected"}
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
