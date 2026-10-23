/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useMemo, useRef, useState } from "react";
import { extractToolText } from "../../shared/extract-tool-text";
import { useMcpApp, useMcpAppEvents } from "../../shared/hooks/useMcpApp";
import { McpAppProvider } from "../../shared/hooks/McpAppProvider";
import { useAnalytics } from "../../shared/hooks/useAnalytics";
import { useFullscreen } from "../../shared/hooks/useFullscreen";
import { AppGlyph, FullscreenIcon, ExitFullscreenIcon } from "../../shared/components/icons/icons";
import "./styles.css";

// ---------------------------------------------------------------------------
// Types — mirror CorrelationFindings schema (no import of server/kibana code)
// ---------------------------------------------------------------------------

type DiamondVertex = "adversary" | "capability" | "infrastructure" | "victim";
type VertexSignal = "high" | "partial" | "none";
type EvidenceWeight =
  | "smoking_gun"
  | "supporting"
  | "non_discriminatory"
  | "counter"
  | "decisive_counter";
type Relationship = "same_campaign" | "same_actor" | "shared_tradecraft";
type CorrelationSignal = "high" | "moderate" | "low" | "none";
type Confidence = "high" | "moderate" | "low";
type Priority = "high" | "moderate";

interface VertexSignalMap {
  adversary: VertexSignal;
  capability: VertexSignal;
  infrastructure: VertexSignal;
  victim: VertexSignal;
}

interface EvidenceItem {
  vertex: DiamondVertex;
  weight: EvidenceWeight;
  text: string;
}

interface ConsolidatedCandidate {
  id: string;
  title: string;
  reason: string;
}

interface Lead {
  candidate_ids: string[];
  title: string;
  relationship: Relationship;
  confidence: Confidence;
  vertex_signal: VertexSignalMap;
  bluf: string;
  evidence: EvidenceItem[];
  gaps: string;
  consolidated_candidates: ConsolidatedCandidate[];
}

interface NoMatch {
  id: string;
  title: string;
  vendor?: string;
}

interface Synthesis {
  bluf: string;
  correlation_signal: CorrelationSignal;
  reasoning: string;
  gaps: string;
  next_steps: Array<{ priority: Priority; text: string }>;
  inferential_hops?: number;
  atomic_ioc_overlap?: { assessed: boolean; note?: string };
  case_title?: string;
}

interface CandidateMetaEntry {
  title?: string;
  vendor?: string;
  url?: string;
}

interface TraceStage {
  stage: string;
  tier?: "sonnet" | "opus" | null;
  input_tokens?: number | string;
  output_tokens?: number | string;
  candidates?: number | string;
  anchors?: number | string;
  started_at?: string;
  ended_at?: string;
}

interface Trace {
  total_input_tokens?: number | string;
  total_output_tokens?: number | string;
  stages?: TraceStage[];
}

interface RunMeta {
  run_id?: string;
  depth?: string;
  status?: string;
}

interface AnchorsSearched {
  hashes: string[];
  network: string[];
  artifacts: string[];
  techniques: string[];
  code_tokens?: string[];
}

interface AnchorTrailEntry {
  fp: string;
  anchor_score: number;
  overlap: number;
  title?: string;
  vendor?: string;
  url?: string;
  triage_confidence?: number;
  justification?: string;
  outcome: "lead" | "picked_no_lead" | "dropped_at_triage";
  lead_title?: string;
  relationship?: string;
  lead_confidence?: string;
}

interface CorrelationFindings {
  leads: Lead[];
  no_match: NoMatch[];
  synthesis: Synthesis;
  case_vertex_signal?: VertexSignalMap;
  candidate_labels?: Record<string, string>;
  candidate_meta?: Record<string, CandidateMetaEntry>;
  // Run-level context folded in by get_correlation_run (see workflowFindingsToRenderShape).
  counts?: Record<string, number>;
  trace?: Trace;
  run_meta?: RunMeta;
  anchors_searched?: AnchorsSearched;
  anchor_trail?: AnchorTrailEntry[];
  phrase_anchor_trail?: AnchorTrailEntry[];
}

interface ReportPayload {
  kind: "correlation_report";
  findings: CorrelationFindings;
  summary: string;
}

// ---------------------------------------------------------------------------
// Constants
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

const VERTEX_LABEL: Record<DiamondVertex, string> = {
  adversary: "Adversary",
  capability: "Capability",
  infrastructure: "Infrastructure",
  victim: "Victim",
};

const RELATIONSHIP_LABEL: Record<Relationship, string> = {
  same_campaign: "Same campaign",
  same_actor: "Same actor",
  shared_tradecraft: "Shared tradecraft",
};

const WEIGHT_LABEL: Record<EvidenceWeight, string> = {
  smoking_gun: "Smoking gun",
  supporting: "Supporting",
  non_discriminatory: "Non-discriminatory",
  counter: "Counter",
  decisive_counter: "Decisive counter",
};

// ---------------------------------------------------------------------------
// Color helpers
// ---------------------------------------------------------------------------

function signalColor(signal: CorrelationSignal | Confidence | VertexSignal): string {
  if (signal === "high") return "#40c790";
  if (signal === "moderate" || signal === "partial") return "#f0b840";
  if (signal === "low") return "#f87171";
  return "#474745";
}

function weightColor(weight: EvidenceWeight): string {
  if (weight === "smoking_gun" || weight === "supporting") return "#40c790";
  if (weight === "non_discriminatory") return "#f0b840";
  return "#f87171";
}

function vertexNodeFill(signal: VertexSignal): string {
  if (signal === "high") return "#40c790";
  if (signal === "partial") return "#f0b840";
  return "#30302f";
}

function vertexNodeText(signal: VertexSignal): string {
  if (signal === "high") return "#ffffff";
  if (signal === "partial") return "#1f1f1e";
  return "#474745";
}

// ---------------------------------------------------------------------------
// Shared SVG diamond (reused from triage view; vertex_signal encoding)
// ---------------------------------------------------------------------------

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

interface DiamondProps {
  vertexSignal: VertexSignalMap;
  size?: number;
}

function DiamondSvg({ vertexSignal, size = 80 }: DiamondProps) {
  const showLabels = size >= 80;
  // Nodes (r=16) reach past the 0–160 box, so pad the viewBox and scale the
  // pixel size to match — keeps the diamond's apparent size while giving the
  // circles room so they don't clip at the container edges.
  const PAD = 10;
  const vb = 160 + PAD * 2;
  const px = Math.round(size * (vb / 160));
  return (
    <svg
      width={px}
      height={px}
      viewBox={`${-PAD} ${-PAD} ${vb} ${vb}`}
      role="img"
      aria-label="Diamond Model correlation signal"
      className="crr-diamond-svg"
    >
      {DIAMOND_EDGES.map(([x1, y1, x2, y2], i) => (
        <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#474745" strokeWidth={1.5} />
      ))}
      {DIAMOND_NODES.map(({ vertex, cx, cy }) => {
        const sig = vertexSignal[vertex];
        return (
          <g key={vertex}>
            <circle cx={cx} cy={cy} r={16} fill={vertexNodeFill(sig)} />
            {showLabels && (
              <text
                x={cx}
                y={cy}
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize={9}
                fontWeight={700}
                fill={vertexNodeText(sig)}
                aria-hidden="true"
              >
                {VERTEX_ABBREV[vertex]}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// WeightDots — 1 (single) or 2 (double) colored dots encoding evidence weight
// ---------------------------------------------------------------------------

interface WeightDotsProps {
  weight: EvidenceWeight;
}

function WeightDots({ weight }: WeightDotsProps) {
  const color = weightColor(weight);
  const label = WEIGHT_LABEL[weight];
  const isDouble = weight === "smoking_gun" || weight === "decisive_counter";
  return (
    <span
      className="crr-weight-dots"
      role="img"
      aria-label={label}
      title={label}
    >
      <span className="crr-dot" style={{ background: color }} aria-hidden="true" />
      {isDouble && <span className="crr-dot" style={{ background: color }} aria-hidden="true" />}
    </span>
  );
}

// ---------------------------------------------------------------------------
// EvidenceSection — evidence items grouped by vertex, supporting vs counter
// ---------------------------------------------------------------------------

const SUPPORTING_WEIGHTS = new Set<EvidenceWeight>(["smoking_gun", "supporting", "non_discriminatory"]);

interface EvidenceSectionProps {
  evidence: EvidenceItem[];
  vertexSignal: VertexSignalMap;
}

function EvidenceSection({ evidence, vertexSignal }: EvidenceSectionProps) {
  const vertexGroups = useMemo(() => {
    const groups: Partial<Record<DiamondVertex, EvidenceItem[]>> = {};
    for (const item of evidence) {
      const v = item.vertex as DiamondVertex;
      const existing = groups[v];
      if (existing) {
        existing.push(item);
      } else {
        groups[v] = [item];
      }
    }
    const ORDER: Record<VertexSignal, number> = { high: 2, partial: 1, none: 0 };
    const populated = (Object.keys(groups) as DiamondVertex[]).sort((a, b) => {
      const diff = ORDER[vertexSignal[b]] - ORDER[vertexSignal[a]];
      return diff !== 0 ? diff : VERTICES.indexOf(a) - VERTICES.indexOf(b);
    });
    return populated.map((v) => ({ vertex: v, items: groups[v]! }));
  }, [evidence, vertexSignal]);

  if (vertexGroups.length === 0) return null;

  return (
    <div className="crr-evidence-section">
      {vertexGroups.map(({ vertex, items }, gi) => {
        const supporting = items.filter((e) => SUPPORTING_WEIGHTS.has(e.weight));
        const counter = items.filter((e) => !SUPPORTING_WEIGHTS.has(e.weight));
        return (
          <div key={vertex} className={gi > 0 ? "crr-evidence-vertex-group crr-evidence-vertex-group-spaced" : "crr-evidence-vertex-group"}>
            <div className="crr-evidence-vertex-label">{VERTEX_LABEL[vertex]}</div>
            {supporting.length > 0 && (
              <div className="crr-evidence-items">
                {supporting.map((item, i) => (
                  <div key={i} className="crr-evidence-item">
                    <span className="crr-evidence-gutter">
                      <WeightDots weight={item.weight} />
                    </span>
                    <span className="crr-evidence-text">{item.text}</span>
                  </div>
                ))}
              </div>
            )}
            {counter.length > 0 && (
              <div className="crr-counter-block">
                <div className="crr-counter-label">Counter evidence</div>
                <div className="crr-evidence-items">
                  {counter.map((item, i) => (
                    <div key={i} className="crr-evidence-item">
                      <span className="crr-evidence-gutter">
                        <WeightDots weight={item.weight} />
                      </span>
                      <span className="crr-evidence-text">{item.text}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// LeadCard — collapsible accordion per lead
// ---------------------------------------------------------------------------

interface LeadCardProps {
  lead: Lead;
  index: number;
  candidateMeta?: Record<string, CandidateMetaEntry>;
  candidateLabels?: Record<string, string>;
}

function LeadCard({ lead, index, candidateMeta, candidateLabels }: LeadCardProps) {
  const [open, setOpen] = useState(false);

  const emDashIdx = lead.title.indexOf(" — ");
  const titleMain = emDashIdx >= 0 ? lead.title.slice(0, emDashIdx) : lead.title;
  const titleSub = emDashIdx >= 0 ? lead.title.slice(emDashIdx + 3) : undefined;

  const confColor = signalColor(lead.confidence);
  const confLabel = lead.confidence === "high" ? "High" : lead.confidence === "moderate" ? "Moderate" : "Low";

  const sources = useMemo(() => {
    const seen = new Set<string>();
    return lead.candidate_ids.flatMap((id) => {
      const meta = candidateMeta?.[id];
      const key = meta?.url ?? meta?.vendor ?? id;
      if (seen.has(key)) return [];
      seen.add(key);
      return [{ id, vendor: meta?.vendor, url: meta?.url }];
    });
  }, [lead.candidate_ids, candidateMeta]);

  return (
    <div className="crr-lead-card" data-index={index}>
      <button
        className="crr-lead-header"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        {!open && (
          <DiamondSvg vertexSignal={lead.vertex_signal} size={56} />
        )}
        <div className="crr-lead-header-meta">
          <div className="crr-lead-badges">
            <span className="crr-badge crr-badge-hollow">
              {RELATIONSHIP_LABEL[lead.relationship]}
            </span>
            <span className="crr-badge crr-badge-hollow" style={{ borderColor: `${confColor}40` }}>
              <span className="crr-conf-dot" style={{ background: confColor }} aria-label={confLabel} role="img" />
              {confLabel}
            </span>
          </div>
          <div className="crr-lead-title-main">{titleMain}</div>
          {titleSub && <div className="crr-lead-title-sub">{titleSub}</div>}
        </div>
        <span className="crr-lead-chevron" aria-hidden="true">{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="crr-lead-body">
          {/* BLUF */}
          <p className="crr-lead-bluf">{lead.bluf}</p>

          {/* Sources */}
          {sources.length > 0 && (
            <div className="crr-sources">
              <span className="crr-sources-label">Sources ({sources.length})</span>
              <div className="crr-source-chips">
                {sources.map(({ id, vendor, url }) => {
                  const label = candidateLabels?.[id];
                  const chipText = label ? `${label} ${vendor ?? id}` : vendor ?? id;
                  return url ? (
                    <a key={id} href={url} target="_blank" rel="noopener noreferrer" className="crr-source-chip">
                      {chipText}
                    </a>
                  ) : (
                    <span key={id} className="crr-source-chip">{chipText}</span>
                  );
                })}
              </div>
            </div>
          )}

          {/* Full diamond when open */}
          <div className="crr-lead-diamond-center">
            <DiamondSvg vertexSignal={lead.vertex_signal} size={120} />
          </div>

          {/* Evidence */}
          <EvidenceSection evidence={lead.evidence} vertexSignal={lead.vertex_signal} />

          {/* Gaps */}
          {lead.gaps && (
            <div className="crr-lead-gaps">
              <span className="crr-gaps-label">Gaps: </span>
              <span className="crr-gaps-text">{lead.gaps}</span>
            </div>
          )}

          {/* Consolidated */}
          {lead.consolidated_candidates.length > 0 && (
            <div className="crr-consolidated">
              <div className="crr-consolidated-label">Consolidated reports</div>
              {lead.consolidated_candidates.map((c) => {
                const cUrl = candidateMeta?.[c.id]?.url;
                return (
                  <div key={c.id} className="crr-consolidated-item">
                    {cUrl ? (
                      <a href={cUrl} target="_blank" rel="noopener noreferrer" className="crr-consolidated-title">{c.title}</a>
                    ) : (
                      <span className="crr-consolidated-title">{c.title}</span>
                    )}
                    <span className="crr-consolidated-reason">{c.reason}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// NoMatchSection — compact ruled-out list
// ---------------------------------------------------------------------------

interface NoMatchSectionProps {
  noMatch: NoMatch[];
}

function NoMatchSection({ noMatch }: NoMatchSectionProps) {
  return (
    <div className="crr-no-match-card">
      <div className="crr-section-title">Ruled out</div>
      {noMatch.length === 0 ? (
        <div className="crr-no-match-empty">No candidates were ruled out.</div>
      ) : (
        <div className="crr-no-match-list">
          {noMatch.map((item) => (
            <div key={item.id} className="crr-no-match-item">
              <span className="crr-no-match-title">{item.title}</span>
              {item.vendor && <span className="crr-no-match-vendor"> — {item.vendor}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SynthesisCard — collapsible
// ---------------------------------------------------------------------------

interface SynthesisCardProps {
  synthesis: Synthesis;
}

function SynthesisCard({ synthesis }: SynthesisCardProps) {
  const [open, setOpen] = useState(false);
  const color = signalColor(synthesis.correlation_signal);
  const signalLabel =
    synthesis.correlation_signal === "high" ? "High" :
    synthesis.correlation_signal === "moderate" ? "Moderate" :
    synthesis.correlation_signal === "low" ? "Low" : "None";

  return (
    <div className="crr-synthesis-card">
      <button className="crr-synthesis-header" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className="crr-dot crr-dot-lg" style={{ background: color }} role="img" aria-label={`Signal: ${signalLabel}`} />
        <span className="crr-section-title crr-synthesis-title">Analysis</span>
        <span className="crr-lead-chevron" aria-hidden="true">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="crr-synthesis-body">
          <div className="crr-synthesis-subsection">
            <div className="crr-subsection-label">Reasoning</div>
            <p className="crr-synthesis-text">{synthesis.reasoning}</p>
          </div>
          {synthesis.gaps && (
            <div className="crr-synthesis-subsection">
              <div className="crr-subsection-label">Gaps</div>
              <p className="crr-synthesis-text">{synthesis.gaps}</p>
            </div>
          )}
          {synthesis.inferential_hops !== undefined && (
            <div className="crr-synthesis-stat">
              <span className="crr-stat-label">Inferential hops</span>
              <span className="crr-stat-value">{synthesis.inferential_hops}</span>
            </div>
          )}
          {synthesis.atomic_ioc_overlap !== undefined && (
            <div className="crr-synthesis-stat">
              <span className="crr-stat-label">Atomic IOC overlap</span>
              <span className="crr-stat-value">
                {synthesis.atomic_ioc_overlap.assessed ? "Assessed" : "Not assessed"}
                {synthesis.atomic_ioc_overlap.note ? ` — ${synthesis.atomic_ioc_overlap.note}` : ""}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// NextStepsCard — collapsible
// ---------------------------------------------------------------------------

interface NextStepsCardProps {
  nextSteps: Synthesis["next_steps"];
}

function NextStepsCard({ nextSteps }: NextStepsCardProps) {
  const [open, setOpen] = useState(false);
  if (nextSteps.length === 0) return null;
  return (
    <div className="crr-next-steps-card">
      <button className="crr-synthesis-header" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className="crr-section-title">Next Steps</span>
        <span className="crr-lead-chevron" aria-hidden="true">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="crr-synthesis-body">
          {nextSteps.map((step, i) => {
            const color = step.priority === "high" ? "#40c790" : "#f0b840";
            const label = step.priority === "high" ? "High priority" : "Moderate priority";
            return (
              <div key={i} className="crr-evidence-item">
                <span className="crr-evidence-gutter">
                  <span className="crr-dot" style={{ background: color }} role="img" aria-label={label} />
                </span>
                <span className="crr-evidence-text">{step.text}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// CaseSignalProfile — per-vertex dot strip
// ---------------------------------------------------------------------------

interface CaseSignalProfileProps {
  caseVertexSignal: VertexSignalMap;
}

function CaseSignalProfile({ caseVertexSignal }: CaseSignalProfileProps) {
  return (
    <div className="crr-case-signal-strip">
      {VERTICES.map((v) => {
        const sig = caseVertexSignal[v];
        const color = signalColor(sig);
        return (
          <div key={v} className="crr-case-signal-item">
            <span className="crr-dot" style={{ background: color }} role="img" aria-label={`${VERTEX_LABEL[v]}: ${sig}`} />
            <span className="crr-case-signal-abbrev">{VERTEX_ABBREV[v]}</span>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Idle state
// ---------------------------------------------------------------------------

function IdleState() {
  const emptySignal: VertexSignalMap = { adversary: "none", capability: "none", infrastructure: "none", victim: "none" };
  return (
    <div className="crr-idle">
      <div className="crr-idle-diamond" aria-hidden="true">
        <DiamondSvg vertexSignal={emptySignal} size={72} />
      </div>
      <div className="crr-idle-title">Correlation Report</div>
      <div className="crr-idle-hint">
        Select reports in the triage view and click{" "}
        <em>Synthesize selected</em> — the model will call{" "}
        <code>render_correlation</code> to display findings here.
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CountsStrip — retrieval → triage → synthesis funnel + run metadata
// ---------------------------------------------------------------------------

function CountsStrip({ counts, runMeta }: { counts?: Record<string, number>; runMeta?: RunMeta }) {
  if (!counts && !runMeta) return null;
  const items: Array<{ label: string; value: string | number }> = [];
  if (counts) {
    if (counts.candidates !== undefined) items.push({ label: "Candidates", value: counts.candidates });
    if (counts.picks !== undefined) items.push({ label: "Triage picks", value: counts.picks });
    if (counts.leads !== undefined) items.push({ label: "Leads", value: counts.leads });
    if (counts.no_match !== undefined) items.push({ label: "No-match", value: counts.no_match });
  }
  if (runMeta?.depth) items.push({ label: "Depth", value: runMeta.depth });
  if (items.length === 0) return null;
  return (
    <div className="crr-counts-strip">
      {items.map((it) => (
        <div key={it.label} className="crr-count-stat">
          <span className="crr-count-value">{it.value}</span>
          <span className="crr-count-label">{it.label}</span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PipelineCostCard — per-tier token spend + est. cost (collapsible)
// ---------------------------------------------------------------------------

// Anthropic list prices, USD per 1M tokens (in / out). Estimate only — managed
// EIS billing may differ; captioned as such in the card.
const PRICES: Record<"sonnet" | "opus", { in: number; out: number }> = {
  sonnet: { in: 3, out: 15 },
  opus: { in: 15, out: 75 },
};

const STAGE_LABEL: Record<string, string> = {
  extract_core: "Case extraction",
  extract_diamond: "Case diamond",
  retrieval: "Retrieval",
  triage: "Triage",
  synthesis: "Synthesis",
};
const STAGE_MODEL: Record<string, string> = {
  extract_core: "Claude Sonnet (raw_text IOCs/behaviors)",
  extract_diamond: "Claude Opus (raw_text vertices)",
  retrieval: "Elasticsearch (kNN + BM25 + anchors)",
  triage: "Claude Sonnet",
  synthesis: "Claude Opus",
};

function num(v: number | string | undefined): number {
  const n = typeof v === "string" ? Number(v) : v;
  return Number.isFinite(n as number) ? (n as number) : 0;
}
function money(n: number): string {
  return `$${n.toFixed(2)}`;
}
function stageCost(s: TraceStage): number {
  if (!s.tier) return 0;
  const p = PRICES[s.tier];
  return (num(s.input_tokens) * p.in + num(s.output_tokens) * p.out) / 1_000_000;
}
// Duration in ms from the stage's ISO timestamps; null when either mark is absent
// (e.g. a tier that was gated off for the run's depth).
function stageDurationMs(s: TraceStage): number | null {
  if (!s.started_at || !s.ended_at) return null;
  const a = Date.parse(s.started_at);
  const b = Date.parse(s.ended_at);
  if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return null;
  return b - a;
}
function fmtDuration(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function PipelineCostCard({ trace }: { trace?: Trace }) {
  const [open, setOpen] = useState(false);
  const stages = Array.isArray(trace?.stages) ? trace!.stages : [];
  if (stages.length === 0) return null;

  const totalIn = stages.reduce((a, s) => a + num(s.input_tokens), 0);
  const totalOut = stages.reduce((a, s) => a + num(s.output_tokens), 0);
  const totalCost = stages.reduce((a, s) => a + stageCost(s), 0);
  const totalMs = stages.reduce((a, s) => a + (stageDurationMs(s) ?? 0), 0);
  const anyDuration = stages.some((s) => stageDurationMs(s) != null);
  const fmt = (n: number) => (n === 0 ? "—" : n.toLocaleString());

  return (
    <div className="crr-synthesis-card">
      <button className="crr-synthesis-header" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className="crr-section-title">Pipeline &amp; cost</span>
        <span className="crr-pipeline-summary">
          {(totalIn + totalOut).toLocaleString()} tokens · ~{money(totalCost)} est.
          {anyDuration ? ` · ${fmtDuration(totalMs)}` : ""}
        </span>
        <span className="crr-lead-chevron" aria-hidden="true">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="crr-synthesis-body">
          <table className="crr-pipeline-table">
            <thead>
              <tr>
                <th>Stage</th>
                <th className="crr-num">Tokens in</th>
                <th className="crr-num">Tokens out</th>
                <th className="crr-num">Duration</th>
                <th className="crr-num">Est. cost</th>
              </tr>
            </thead>
            <tbody>
              {stages.map((s) => {
                const detail =
                  s.stage === "retrieval"
                    ? `${num(s.candidates)} candidates · ${num(s.anchors)} anchor hits`
                    : STAGE_MODEL[s.stage] ?? "";
                return (
                  <tr key={s.stage}>
                    <td>
                      <div className="crr-pipeline-stage">{STAGE_LABEL[s.stage] ?? s.stage}</div>
                      <div className="crr-pipeline-detail">{detail}</div>
                    </td>
                    <td className="crr-num">{fmt(num(s.input_tokens))}</td>
                    <td className="crr-num">{fmt(num(s.output_tokens))}</td>
                    <td className="crr-num">{fmtDuration(stageDurationMs(s))}</td>
                    <td className="crr-num">{s.tier ? money(stageCost(s)) : "$0.00"}</td>
                  </tr>
                );
              })}
              <tr className="crr-pipeline-total">
                <td>Total</td>
                <td className="crr-num">{totalIn.toLocaleString()}</td>
                <td className="crr-num">{totalOut.toLocaleString()}</td>
                <td className="crr-num">{anyDuration ? fmtDuration(totalMs) : "—"}</td>
                <td className="crr-num">{money(totalCost)}</td>
              </tr>
            </tbody>
          </table>
          <div className="crr-pipeline-caption">
            Est. cost at Anthropic list prices (Sonnet $3/$15, Opus $15/$75 per 1M in/out) — managed EIS
            billing may differ. Retrieval is Elasticsearch-only. Source: ti-correlations trace.
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// AnchorTrailCard — what exact anchors were searched, which reports they matched,
// and how each match fared through triage → synthesis (collapsible; diagnostic).
// ---------------------------------------------------------------------------

const OUTCOME_LABEL: Record<AnchorTrailEntry["outcome"], string> = {
  lead: "Lead",
  picked_no_lead: "Triaged, no lead",
  dropped_at_triage: "Dropped at triage",
};
const OUTCOME_CLASS: Record<AnchorTrailEntry["outcome"], string> = {
  lead: "crr-outcome-lead",
  picked_no_lead: "crr-outcome-picked",
  dropped_at_triage: "crr-outcome-dropped",
};

function AnchorChips({ label, values }: { label: string; values: string[] }) {
  if (!values || values.length === 0) return null;
  return (
    <div className="crr-anchor-chip-row">
      <span className="crr-anchor-chip-label">{label}</span>
      <div className="crr-anchor-chips">
        {values.map((v, i) => (
          <span className="crr-anchor-chip" key={`${v}-${i}`}>{v}</span>
        ))}
      </div>
    </div>
  );
}

function TrailRows({ rows, scoreLabel }: { rows: AnchorTrailEntry[]; scoreLabel: string }) {
  return (
    <div className="crr-anchor-trail-list">
      {rows.map((r, i) => (
        <div className="crr-anchor-trail-row" key={r.fp || i}>
          <div className="crr-anchor-trail-head">
            <span className={`crr-outcome-badge ${OUTCOME_CLASS[r.outcome]}`}>
              {OUTCOME_LABEL[r.outcome]}
            </span>
            <span className="crr-anchor-trail-title">
              {r.url ? (
                <a href={r.url} target="_blank" rel="noreferrer">{r.title ?? r.fp}</a>
              ) : (
                r.title ?? r.fp
              )}
            </span>
            {r.vendor && <span className="crr-anchor-trail-vendor">{r.vendor}</span>}
          </div>
          <div className="crr-anchor-trail-meta">
            <span>{scoreLabel} {r.anchor_score}</span>
            <span>· diamond overlap {r.overlap}</span>
            {r.triage_confidence != null && (
              <span>· triage {(r.triage_confidence * 100).toFixed(0)}%</span>
            )}
            {r.outcome === "lead" && r.relationship && (
              <span>· synthesis: {r.relationship.replace(/_/g, " ")} ({r.lead_confidence})</span>
            )}
          </div>
          {r.justification && (
            <div className="crr-anchor-trail-just">“{r.justification}”</div>
          )}
        </div>
      ))}
    </div>
  );
}

function AnchorTrailCard({
  anchors,
  trail,
  phraseTrail,
}: {
  anchors?: AnchorsSearched;
  trail?: AnchorTrailEntry[];
  phraseTrail?: AnchorTrailEntry[];
}) {
  const [open, setOpen] = useState(false);
  const codeTokens = anchors?.code_tokens ?? [];
  const searched = anchors
    ? (anchors.hashes.length + anchors.network.length + anchors.artifacts.length + anchors.techniques.length + codeTokens.length)
    : 0;
  const rows = trail ?? [];
  const phraseRows = phraseTrail ?? [];
  if (searched === 0 && rows.length === 0 && phraseRows.length === 0) return null;
  const matched = rows.length + phraseRows.length;
  const leadCount = [...rows, ...phraseRows].filter((r) => r.outcome === "lead").length;

  return (
    <div className="crr-synthesis-card">
      <button className="crr-synthesis-header" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <span className="crr-section-title">Anchor trail</span>
        <span className="crr-pipeline-summary">
          {searched} anchor{searched !== 1 ? "s" : ""} searched · {matched} matched · {leadCount} in a lead
        </span>
        <span className="crr-lead-chevron" aria-hidden="true">{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div className="crr-synthesis-body">
          {anchors && searched > 0 && (
            <div className="crr-anchors-searched">
              <div className="crr-pipeline-detail" style={{ marginBottom: 8 }}>
                Case anchors backfilled into the exact-match retrieval clause:
              </div>
              <AnchorChips label="hashes" values={anchors.hashes} />
              <AnchorChips label="network" values={anchors.network} />
              <AnchorChips label="artifacts" values={anchors.artifacts} />
              <AnchorChips label="techniques" values={anchors.techniques} />
              <AnchorChips label="code tokens" values={codeTokens} />
            </div>
          )}

          <div className="crr-anchor-trail-subhead">IOC / artifact anchors</div>
          {rows.length > 0 ? (
            <TrailRows rows={rows} scoreLabel="anchor weight" />
          ) : (
            <div className="crr-pipeline-detail">
              No corpus report shared an exact IOC/artifact anchor with the case.
            </div>
          )}

          <div className="crr-anchor-trail-subhead" style={{ marginTop: 14 }}>
            Code-token (phrase) anchors
          </div>
          {phraseRows.length > 0 ? (
            <TrailRows rows={phraseRows} scoreLabel="phrase weight" />
          ) : (
            <div className="crr-pipeline-detail">
              {codeTokens.length > 0
                ? "No corpus report shared a distinctive code token with the case."
                : "The case exposed no distinctive code tokens to phrase-match."}
            </div>
          )}

          <div className="crr-pipeline-caption">
            Anchors = shared file-hash IOCs + discriminating artifacts (network IOCs / techniques are boosts).
            Code-token anchors match distinctive execution tokens (e.g. [Class]::Method()) exactly against
            corpus extracted.code_tokens. Trail joins retrieval hits → triage picks → synthesis leads. Source: ti-correlations run record.
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main App
// ---------------------------------------------------------------------------

export function App() {
  return (
    <McpAppProvider name="correlation-report" version="1.0.0">
      <AppContent />
    </McpAppProvider>
  );
}

function AppContent() {
  const [payload, setPayload] = useState<ReportPayload | null>(null);

  const { connected, getApp } = useMcpApp();
  const { trackEvent } = useAnalytics();
  const fullscreen = useFullscreen(getApp);
  const autoExpandedRef = useRef(false);

  useEffect(() => {
    trackEvent({ eventType: "view_rendered", viewId: "correlation-report" });
  }, [trackEvent]);

  useMcpAppEvents({
    onToolResult: (toolResult) => {
      try {
        const text = extractToolText(toolResult);
        if (!text) return;
        const data = JSON.parse(text);
        if (data?.kind === "correlation_report" && data.findings) {
          setPayload(data as ReportPayload);
        }
      } catch {
        // Not a correlation report — ignore.
      }
    },
  });

  // The report is dense — when findings first arrive, request the host's
  // larger surface (fullscreen display mode → side panel) instead of leaving
  // it in the inline chat card. Best-effort: hosts that require a user gesture
  // ignore it, and the header toggle is the manual fallback.
  useEffect(() => {
    if (payload?.findings && !autoExpandedRef.current) {
      autoExpandedRef.current = true;
      if (!fullscreen.isFullscreen) fullscreen.toggle();
    }
  }, [payload, fullscreen]);

  if (!connected) {
    return (
      <div className="crr-app">
        <div className="crr-loading">
          <div className="crr-spinner" />
          <span>Connecting to server...</span>
        </div>
      </div>
    );
  }

  const findings = payload?.findings;

  return (
    <div className="crr-app">
      <header className="crr-header">
        <div className="crr-header-brand">
          <span className="crr-header-glyph" aria-hidden="true">
            <AppGlyph />
          </span>
          <h1 className="crr-header-title">
            {findings?.synthesis.case_title ?? "Correlation Report"}
          </h1>
        </div>
        <div className="crr-header-meta">
          {findings && (
            <>
              <span
                className="crr-signal-badge"
                style={{ color: signalColor(findings.synthesis.correlation_signal) }}
              >
                {findings.synthesis.correlation_signal.toUpperCase()}
              </span>
              <span className="crr-header-count">
                {findings.leads.length} lead{findings.leads.length !== 1 ? "s" : ""}
              </span>
            </>
          )}
          <button
            type="button"
            className="crr-header-icon-btn"
            onClick={fullscreen.toggle}
            title={fullscreen.isFullscreen ? "Exit fullscreen" : "Open in panel"}
            aria-label={fullscreen.isFullscreen ? "Exit fullscreen" : "Open in panel"}
          >
            {fullscreen.isFullscreen ? <ExitFullscreenIcon /> : <FullscreenIcon />}
          </button>
        </div>
      </header>

      <div className="crr-body">
        {!findings ? (
          <IdleState />
        ) : (
          <div className="crr-report">
            {/* Case BLUF */}
            <div className="crr-bluf-card">
              <span
                className="crr-dot crr-dot-lg crr-bluf-dot"
                style={{ background: signalColor(findings.synthesis.correlation_signal) }}
                role="img"
                aria-label={`Correlation signal: ${findings.synthesis.correlation_signal}`}
              />
              <div className="crr-bluf-body">
                <div className="crr-bluf-label">BLUF</div>
                <p className="crr-bluf-text">{findings.synthesis.bluf}</p>
              </div>
            </div>

            {/* Retrieval → triage → synthesis funnel */}
            <CountsStrip counts={findings.counts} runMeta={findings.run_meta} />

            {/* Case vertex signal */}
            {findings.case_vertex_signal && (
              <div className="crr-case-signal-card">
                <div className="crr-section-title">Case signal profile</div>
                <div className="crr-case-signal-desc">Per-vertex signal from the case under analysis.</div>
                <CaseSignalProfile caseVertexSignal={findings.case_vertex_signal} />
              </div>
            )}

            {/* Leads */}
            <div className="crr-section-title crr-leads-title">
              Leads ({findings.leads.length})
            </div>
            <div className="crr-leads-list">
              {findings.leads.map((lead, i) => (
                <LeadCard
                  key={lead.candidate_ids[0] ?? i}
                  lead={lead}
                  index={i}
                  candidateMeta={findings.candidate_meta}
                  candidateLabels={findings.candidate_labels}
                />
              ))}
            </div>

            {/* No match */}
            <NoMatchSection noMatch={findings.no_match} />

            {/* Analysis (synthesis detail) */}
            <SynthesisCard synthesis={findings.synthesis} />

            {/* Next steps */}
            <NextStepsCard nextSteps={findings.synthesis.next_steps} />

            {/* Anchor trail (diagnostic; collapsed) — searched → matched → synthesis */}
            <AnchorTrailCard
              anchors={findings.anchors_searched}
              trail={findings.anchor_trail}
              phraseTrail={findings.phrase_anchor_trail}
            />

            {/* Pipeline & cost (diagnostic; collapsed) */}
            <PipelineCostCard trace={findings.trace} />

            {findings.run_meta?.run_id && (
              <div className="crr-run-footer">
                run {findings.run_meta.run_id}
                {findings.run_meta.status ? ` · ${findings.run_meta.status}` : ""}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
