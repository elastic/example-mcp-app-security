/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useMemo, useState } from "react";
import { extractToolText } from "../../shared/extract-tool-text";
import { useMcpApp, useMcpAppEvents } from "../../shared/hooks/useMcpApp";
import { McpAppProvider } from "../../shared/hooks/McpAppProvider";
import { useAnalytics } from "../../shared/hooks/useAnalytics";
import { AppGlyph } from "../../shared/components/icons/icons";
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

interface CorrelationFindings {
  leads: Lead[];
  no_match: NoMatch[];
  synthesis: Synthesis;
  case_vertex_signal?: VertexSignalMap;
  candidate_labels?: Record<string, string>;
  candidate_meta?: Record<string, CandidateMetaEntry>;
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
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 160 160"
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

  const { connected } = useMcpApp();
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
        if (data?.kind === "correlation_report" && data.findings) {
          setPayload(data as ReportPayload);
        }
      } catch {
        // Not a correlation report — ignore.
      }
    },
  });

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
        {findings && (
          <div className="crr-header-meta">
            <span
              className="crr-signal-badge"
              style={{ color: signalColor(findings.synthesis.correlation_signal) }}
            >
              {findings.synthesis.correlation_signal.toUpperCase()}
            </span>
            <span className="crr-header-count">
              {findings.leads.length} lead{findings.leads.length !== 1 ? "s" : ""}
            </span>
          </div>
        )}
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
          </div>
        )}
      </div>
    </div>
  );
}
