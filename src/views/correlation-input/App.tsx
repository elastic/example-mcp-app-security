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
// Types
// ---------------------------------------------------------------------------

type SignalLevel = "HIGH" | "PARTIAL" | "NONE";

interface VertexInput {
  query: string;
  signal: SignalLevel;
}

type DiamondVertex = "adversary" | "capability" | "infrastructure" | "victim";

interface InputCheckPayload {
  kind: "correlation_input_check";
  vertices: Partial<Record<DiamondVertex, VertexInput>>;
  summary: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VERTEX_ORDER: ReadonlyArray<DiamondVertex> = [
  "adversary",
  "capability",
  "infrastructure",
  "victim",
];

const VERTEX_LABEL: Record<DiamondVertex, string> = {
  adversary: "Adversary",
  capability: "Capability",
  infrastructure: "Infrastructure",
  victim: "Victim",
};

const VERTEX_ABBREV: Record<DiamondVertex, string> = {
  adversary: "ADV",
  capability: "CAP",
  infrastructure: "INF",
  victim: "VIC",
};

// ---------------------------------------------------------------------------
// Stoplight — per-vertex signal indicator
// ---------------------------------------------------------------------------

const SIGNAL_COLOR: Record<SignalLevel, string> = {
  HIGH: "#40c790",
  PARTIAL: "#f0b840",
  NONE: "#474745",
};

const SIGNAL_TEXT_COLOR: Record<SignalLevel, string> = {
  HIGH: "#40c790",
  PARTIAL: "#f0b840",
  NONE: "#817f78",
};

const SIGNAL_LABEL: Record<SignalLevel, string> = {
  HIGH: "HIGH",
  PARTIAL: "PARTIAL",
  NONE: "NONE",
};

interface StoplightProps {
  signal: SignalLevel;
}

function Stoplight({ signal }: StoplightProps) {
  const color = SIGNAL_COLOR[signal];
  return (
    <span
      className="gate-stoplight"
      style={{ background: color, boxShadow: signal !== "NONE" ? `0 0 6px ${color}55` : "none" }}
      aria-label={`Signal: ${signal}`}
      role="img"
    />
  );
}

// ---------------------------------------------------------------------------
// Diamond glyph — shows all 4 vertices lit by signal (reuses 1a encoding)
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

function signalToVertexColor(signal: SignalLevel | undefined): string {
  if (!signal || signal === "NONE") return "#30302f";
  if (signal === "HIGH") return "#40c790";
  return "#f0b840";
}

function signalToTextFill(signal: SignalLevel | undefined): string {
  if (!signal || signal === "NONE") return "#474745";
  if (signal === "HIGH") return "#ffffff";
  return "#1f1f1e";
}

interface InputDiamondProps {
  vertices: Partial<Record<DiamondVertex, VertexInput>>;
  size?: number;
}

function InputDiamond({ vertices, size = 72 }: InputDiamondProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 160 160"
      role="img"
      aria-label="Diamond Model input signal overview"
      className="gate-diamond-svg"
    >
      {DIAMOND_EDGES.map(([x1, y1, x2, y2], i) => (
        <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="#474745" strokeWidth={2} />
      ))}
      {DIAMOND_NODES.map(({ vertex, cx, cy }) => {
        const signal = vertices[vertex]?.signal;
        return (
          <g key={vertex}>
            <circle cx={cx} cy={cy} r={18} fill={signalToVertexColor(signal)} />
            <text
              x={cx}
              y={cy}
              textAnchor="middle"
              dominantBaseline="middle"
              fontSize={10}
              fontWeight={700}
              fill={signalToTextFill(signal)}
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
// Vertex row — stoplight + abbrev + signal label + query text (expandable)
// ---------------------------------------------------------------------------

interface VertexRowProps {
  vertex: DiamondVertex;
  input: VertexInput;
}

function VertexRow({ vertex, input }: VertexRowProps) {
  const [expanded, setExpanded] = useState(false);
  const hasQuery = input.query.trim().length > 0;
  const truncated = input.query.length > 140 && !expanded;
  const displayText = truncated ? input.query.slice(0, 140).trimEnd() + "…" : input.query;
  const signalColor = SIGNAL_TEXT_COLOR[input.signal];

  return (
    <div className={`gate-vertex-row gate-vertex-${input.signal.toLowerCase()}`}>
      <div className="gate-vertex-left">
        <Stoplight signal={input.signal} />
        <div className="gate-vertex-id">
          <span className="gate-vertex-abbrev">{VERTEX_ABBREV[vertex]}</span>
          <span className="gate-vertex-name">{VERTEX_LABEL[vertex]}</span>
        </div>
        <span
          className="gate-signal-badge"
          style={{ color: signalColor, borderColor: `${signalColor}40`, background: `${signalColor}10` }}
        >
          {SIGNAL_LABEL[input.signal]}
        </span>
      </div>

      <div className="gate-vertex-query">
        {hasQuery ? (
          <>
            <span className="gate-vertex-query-text">{displayText}</span>
            {input.query.length > 140 && (
              <button
                className="gate-expand-btn"
                onClick={() => setExpanded((v) => !v)}
                aria-label={expanded ? "Collapse query" : "Expand query"}
              >
                {expanded ? "less" : "more"}
              </button>
            )}
          </>
        ) : (
          <span className="gate-vertex-query-empty">— omitted</span>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main App
// ---------------------------------------------------------------------------

export function App() {
  return (
    <McpAppProvider name="correlation-input" version="1.0.0">
      <AppContent />
    </McpAppProvider>
  );
}

function AppContent() {
  const [payload, setPayload] = useState<InputCheckPayload | null>(null);
  const [proceeding, setProceeding] = useState(false);
  const [dismissed, setDismissed] = useState(false);

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
        if (data?.kind === "correlation_input_check" && data.vertices) {
          setPayload(data as InputCheckPayload);
          setProceeding(false);
          setDismissed(false);
        }
      } catch {
        // Not a gate payload — ignore.
      }
    },
  });

  const handleProceed = useCallback(async () => {
    const app = getApp();
    if (!app || !payload) return;
    setProceeding(true);

    // Build a concise proceed message that gives the LLM everything it needs
    // to call diamond_search_analyst without the analyst retyping anything.
    const vertexLines = VERTEX_ORDER
      .filter((v) => payload.vertices[v] && payload.vertices[v]!.signal !== "NONE" && payload.vertices[v]!.query.trim())
      .map((v) => `  ${VERTEX_ABBREV[v]}: ${payload.vertices[v]!.query.trim()}`);

    const message = vertexLines.length > 0
      ? `PROCEED — call diamond_search_analyst with the following vertex queries:\n${vertexLines.join("\n")}`
      : "PROCEED — call diamond_search_analyst with the vertex queries from the correlation_input_check you just ran.";

    try {
      await app.sendMessage({
        role: "user",
        content: [{ type: "text", text: message }],
      });
    } catch {
      // sendMessage may be unsupported by some hosts; fall back gracefully.
      await app.updateModelContext({
        content: [{ type: "text", text: message }],
      });
    } finally {
      setProceeding(false);
    }
  }, [getApp, payload]);

  const handleRevise = useCallback(() => {
    setDismissed(true);
  }, []);

  if (!connected) {
    return (
      <div className="gate-app">
        <div className="gate-loading">
          <div className="gate-spinner" />
          <span>Connecting to server...</span>
        </div>
      </div>
    );
  }

  if (dismissed) {
    return (
      <div className="gate-app">
        <div className="gate-dismissed">
          <div className="gate-dismissed-title">Revising input</div>
          <div className="gate-dismissed-hint">
            Provide additional case context in the conversation. The model will
            re-summarize and call <code>correlation_input_check</code> again when ready.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="gate-app">
      <header className="gate-header">
        <div className="gate-header-brand">
          <span className="gate-header-glyph" aria-hidden="true">
            <AppGlyph />
          </span>
          <h1 className="gate-header-title">Input Signal Gate</h1>
        </div>
        {payload && (
          <div className="gate-header-meta">
            <InputDiamond vertices={payload.vertices} size={40} />
          </div>
        )}
      </header>

      <div className="gate-body">
        {!payload ? (
          <div className="gate-idle">
            <div className="gate-idle-diamond" aria-hidden="true">
              <InputDiamond vertices={{}} size={72} />
            </div>
            <div className="gate-idle-title">Correlation Input Gate</div>
            <div className="gate-idle-hint">
              Call <code>correlation_input_check</code> with your per-vertex summaries
              and signal ratings to review before searching.
            </div>
          </div>
        ) : (
          <>
            <div className="gate-vertex-list">
              {VERTEX_ORDER.map((vertex) => {
                const input = payload.vertices[vertex];
                // Show all 4 rows; absent vertices shown as NONE.
                return (
                  <VertexRow
                    key={vertex}
                    vertex={vertex}
                    input={input ?? { query: "", signal: "NONE" }}
                  />
                );
              })}
            </div>

            <div className="gate-footer">
              <div className="gate-footer-question">
                Proceed with this search?
              </div>
              <div className="gate-footer-actions">
                <button
                  className="gate-btn gate-btn-primary"
                  onClick={handleProceed}
                  disabled={proceeding}
                >
                  {proceeding ? "Searching…" : "Search this case"}
                </button>
                <button
                  className="gate-btn gate-btn-ghost"
                  onClick={handleRevise}
                  disabled={proceeding}
                >
                  I'll revise first
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
