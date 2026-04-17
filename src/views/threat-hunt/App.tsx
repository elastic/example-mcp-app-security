/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useEffect, useCallback, useRef } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme, timeAgo } from "../../shared/theme";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import { SeverityBadge } from "../../shared/severity";
import type { EsqlResult } from "../../shared/types";
import { QueryEditor } from "./components/QueryEditor";
import { ResultsTable } from "./components/ResultsTable";
import { InvestigationGraph, type GNode, type GEdge } from "./components/InvestigationGraph";
import { CardGraph } from "./components/CardGraph";
import "./styles.css";

export function App() {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<EsqlResult | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [executing, setExecuting] = useState(false);
  const [hasExecuted, setHasExecuted] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const [graphNodes, setGraphNodes] = useState<GNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GEdge[]>([]);
  const [graphActive, setGraphActive] = useState(false);
  const [graphView, setGraphView] = useState<"card" | "force">("card");
  const [selectedNode, setSelectedNode] = useState<GNode | null>(null);
  const [nodeDetail, setNodeDetail] = useState<Record<string, unknown> | null>(null);
  const [nodeDetailLoading, setNodeDetailLoading] = useState(false);

  const executeQuery = useCallback(async (q: string) => {
    if (!appRef.current || !q.trim()) return;
    setExecuting(true);
    setQueryError(null);
    setResults(null);
    setHasExecuted(true);
    try {
      const result = await appRef.current.callServerTool({ name: "execute-esql", arguments: { query: q } });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text) as { error?: string } & EsqlResult;
        if (data.error) setQueryError(data.error);
        else setResults(data);
      }
    } catch (e) { setQueryError(e instanceof Error ? e.message : String(e)); }
    finally { setExecuting(false); }
  }, []);

  const addEntityToGraph = useCallback((type: string, value: string) => {
    setGraphActive(true);
    const rootId = `${type}:${value}`;
    setGraphNodes((prev) => {
      if (prev.some((n) => n.id === rootId)) return prev;
      return [...prev, { id: rootId, type: type as GNode["type"], value }];
    });
  }, []);

  const expandEntity = useCallback(async (type: string, value: string) => {
    if (!appRef.current) return;

    const rootId = `${type}:${value}`;
    setGraphNodes((prev) => prev.map((n) => n.id === rootId ? { ...n, loading: true } : n));

    try {
      const result = await appRef.current.callServerTool({
        name: "investigate-entity",
        arguments: { entityType: type, entityValue: value },
      });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text) as { nodes: GNode[]; edges: GEdge[] };
        setGraphNodes((prev) => {
          const existing = new Set(prev.map((n) => n.id));
          const updated = prev.map((n) => n.id === rootId ? { ...n, loading: false, expanded: true } : n);
          for (const node of data.nodes) {
            if (!existing.has(node.id)) {
              updated.push(node);
              existing.add(node.id);
            }
          }
          return updated;
        });
        setGraphEdges((prev) => {
          const existingKeys = new Set(prev.map((e) => `${typeof e.source === "string" ? e.source : e.source.id}->${typeof e.target === "string" ? e.target : e.target.id}`));
          const newEdges = data.edges.filter((e) => !existingKeys.has(`${e.source}->${e.target}`));
          return [...prev, ...newEdges];
        });
      }
    } catch (e) {
      console.error("Investigation failed:", e);
      setGraphNodes((prev) => prev.map((n) => n.id === rootId ? { ...n, loading: false } : n));
    }
  }, []);

  const selectNode = useCallback(async (node: GNode) => {
    setSelectedNode(node);
    setNodeDetail(null);
    setNodeDetailLoading(true);
    if (!appRef.current) { setNodeDetailLoading(false); return; }
    try {
      const result = await appRef.current.callServerTool({
        name: "get-entity-detail",
        arguments: { entityType: node.type, entityValue: node.value },
      });
      const text = extractCallResult(result);
      if (text) setNodeDetail(JSON.parse(text));
    } catch { /* ignore */ }
    finally { setNodeDetailLoading(false); }
  }, []);

  const collapseEntity = useCallback((node: GNode) => {
    setGraphNodes((prev) => {
      const childIds = new Set<string>();
      setGraphEdges((edges) => {
        for (const e of edges) {
          const src = typeof e.source === "string" ? e.source : e.source.id;
          const tgt = typeof e.target === "string" ? e.target : e.target.id;
          if (src === node.id) childIds.add(tgt);
        }
        return edges.filter((e) => {
          const src = typeof e.source === "string" ? e.source : e.source.id;
          return src !== node.id;
        });
      });
      return prev
        .filter((n) => !childIds.has(n.id) || n.expanded)
        .map((n) => n.id === node.id ? { ...n, expanded: false } : n);
    });
  }, []);

  useEffect(() => {
    const app = new McpApp({ name: "threat-hunt", version: "0.1.0" });
    appRef.current = app;
    applyTheme(app);

    let pendingQuery: string | null = null;
    let pendingEntity: { type: string; value: string } | null = null;
    let isConnected = false;

    const runPending = () => {
      if (!isConnected) return;
      if (pendingEntity) {
        const e = pendingEntity;
        pendingEntity = null;
        addEntityToGraph(e.type, e.value);
      }
      if (pendingQuery) {
        const q = pendingQuery;
        pendingQuery = null;
        executeQuery(q);
      }
    };

    app.ontoolresult = (result) => {
      try {
        const text = extractToolText(result);
        if (text) {
          const data = JSON.parse(text);
          if (data.params?.query) {
            const q = String(data.params.query).trim();
            setQuery(q);
            pendingQuery = q;
          }
          if (data.params?.entity) {
            pendingEntity = data.params.entity;
          }
        }
      } catch { /* ignore */ }
      runPending();
    };

    app.connect().then(() => {
      setConnected(true);
      isConnected = true;
      setTimeout(runPending, 300);
    });

    return () => { app.close(); };
  }, [executeQuery, addEntityToGraph]);

  if (!connected) {
    return <div className="app-layout"><div className="loading-state"><div className="loading-spinner" />Connecting...</div></div>;
  }

  const alertNodeIds = new Set(graphNodes.filter((n) => n.type === "alert").map((n) => n.id));
  const alertLinkedIds = new Set<string>();
  for (const e of graphEdges) {
    const src = typeof e.source === "string" ? e.source : e.source.id;
    const tgt = typeof e.target === "string" ? e.target : e.target.id;
    if (alertNodeIds.has(src)) alertLinkedIds.add(tgt);
    if (alertNodeIds.has(tgt)) alertLinkedIds.add(src);
  }

  return (
    <div className="app-layout">
      <header className="filter-bar" style={{ flexWrap: "nowrap", gap: 8, overflow: "hidden" }}>
        <span className="filter-bar-title" style={{ flexShrink: 0 }}>Threat Hunt</span>
        <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--accent)", flexShrink: 0 }}>ES|QL</span>
        {graphActive && (
          <span style={{ fontSize: 10, color: "var(--text-dim)", flexShrink: 0 }}>
            {graphNodes.length} entities
          </span>
        )}
        <span style={{ flex: 1 }} />
        {graphActive && (
          <button className="btn btn-sm btn-ghost" style={{ flexShrink: 0 }} onClick={() => { setGraphNodes([]); setGraphEdges([]); setGraphActive(false); }}>
            Clear
          </button>
        )}
        <button className="btn btn-sm btn-ghost" style={{ flexShrink: 0 }} onClick={() => {
          const next = !isFullscreen;
          try { appRef.current?.requestDisplayMode({ mode: next ? "fullscreen" : "inline" }); } catch {}
          setIsFullscreen(next);
        }}>
          {isFullscreen ? "\u2715" : "\u26F6"}
        </button>
      </header>

      <div className="hunt-body">
        {graphActive && (
          <div className="graph-pane">
            <div style={{ position: "absolute", top: 8, left: 12, zIndex: 10, display: "flex", gap: 4 }}>
              <button className={`btn btn-sm ${graphView === "card" ? "btn-primary" : "btn-ghost"}`}
                onClick={() => setGraphView("card")}>Cards</button>
              <button className={`btn btn-sm ${graphView === "force" ? "btn-primary" : "btn-ghost"}`}
                onClick={() => setGraphView("force")}>Network</button>
            </div>
            {graphView === "card" ? (
              <CardGraph nodes={graphNodes} edges={graphEdges}
                onExpand={(n) => expandEntity(n.type, n.value)}
                onSelect={selectNode}
                alertLinkedIds={alertLinkedIds} />
            ) : (
              <InvestigationGraph nodes={graphNodes} edges={graphEdges}
                onExpand={(n) => expandEntity(n.type, n.value)}
                onCollapse={collapseEntity}
                alertLinkedIds={alertLinkedIds} />
            )}

            {/* Node Detail Panel */}
            {selectedNode && (
              <NodeDetailPanel node={selectedNode} detail={nodeDetail} loading={nodeDetailLoading}
                onClose={() => setSelectedNode(null)} />
            )}
          </div>
        )}

        <div className="hunt-query-pane">
          <QueryEditor query={query} onChange={setQuery} onExecute={() => executeQuery(query)} executing={executing} />
          {queryError && <div className="query-error">{queryError}</div>}
          <ResultsTable results={results} executing={executing} hasExecuted={hasExecuted} queryError={queryError}
            onEntityClick={(type, value) => addEntityToGraph(type, value)} />
        </div>
      </div>
    </div>
  );
}

/* ─── Node Detail Panel ─── */

const TYPE_LABELS: Record<string, { icon: string; label: string; color: string }> = {
  alert: { icon: "\u26A0", label: "Alert", color: "var(--severity-critical)" },
  user: { icon: "\u{1F464}", label: "User", color: "#5c7cfa" },
  host: { icon: "\u{1F5A5}", label: "Host", color: "#40c790" },
  process: { icon: "\u2699", label: "Process", color: "#b07cfa" },
  ip: { icon: "\u{1F310}", label: "IP Address", color: "#f0b840" },
};

interface DetailField { label: string; value: string; mono?: boolean }
interface DetailEvent { timestamp: string; action: string; detail: string }

function NodeDetailPanel({ node, detail, loading, onClose }: {
  node: GNode; detail: Record<string, unknown> | null; loading: boolean;
  onClose: () => void;
}) {
  const cfg = TYPE_LABELS[node.type] || TYPE_LABELS.host;
  const fields = (detail as { fields?: DetailField[] } | null)?.fields || [];
  const events = (detail as { events?: DetailEvent[] } | null)?.events || [];

  const sevField = fields.find(f => f.label === "Severity");
  const sevColor = sevField?.value === "critical" ? "var(--severity-critical)" :
    sevField?.value === "high" ? "var(--severity-high)" :
    sevField?.value === "medium" ? "var(--severity-medium)" : null;

  return (
    <div style={{
      position: "absolute", top: 0, right: 0, bottom: 0, width: 340,
      background: "var(--bg-secondary)", borderLeft: `3px solid ${cfg.color}`,
      zIndex: 20, overflow: "auto",
      animation: "slideInRight 0.2s ease-out",
      boxShadow: "var(--shadow-lg)",
    }}>
      {/* Header */}
      <div style={{ padding: "16px 16px 14px", borderBottom: "1px solid var(--border-subtle)", background: "var(--bg-primary)" }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{
              width: 40, height: 40, borderRadius: "50%",
              border: `2.5px solid ${cfg.color}`,
              background: `${cfg.color}15`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 20, flexShrink: 0,
            }}>{cfg.icon}</span>
            <div>
              <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.6px", color: cfg.color, marginBottom: 2 }}>{cfg.label}</div>
              <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text-primary)", wordBreak: "break-all", lineHeight: 1.3 }}>{node.value}</div>
            </div>
          </div>
          <button className="btn btn-sm btn-ghost" onClick={onClose} style={{ flexShrink: 0 }}>&times;</button>
        </div>
        {sevColor && (
          <div style={{ marginTop: 8, padding: "4px 10px", borderRadius: 20, background: `${sevColor}15`, border: `1px solid ${sevColor}30`, display: "inline-flex", alignItems: "center", gap: 4, fontSize: 10, fontWeight: 700, color: sevColor }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: sevColor }} />
            {sevField?.value?.toUpperCase()}
          </div>
        )}
      </div>

      {/* Content */}
      {loading ? (
        <div className="loading-state" style={{ padding: 40 }}><div className="loading-spinner" style={{ width: 18, height: 18 }} /> Loading details...</div>
      ) : (
        <div style={{ padding: "12px 16px" }}>
          {/* Fields */}
          {fields.map((f, i) => (
            <div key={i} style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-dim)", marginBottom: 2 }}>{f.label}</div>
              <div style={{
                fontSize: 12, color: "var(--text-primary)", lineHeight: 1.5,
                fontFamily: f.mono ? "var(--font-mono)" : "inherit",
                wordBreak: "break-all", whiteSpace: "pre-wrap",
              }}>{f.value || "\u2014"}</div>
            </div>
          ))}

          {/* Events timeline */}
          {events.length > 0 && (
            <div style={{ marginTop: 16, paddingTop: 12, borderTop: "1px solid var(--border-subtle)" }}>
              <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-dim)", marginBottom: 8 }}>
                Recent Activity ({events.length})
              </div>
              {events.map((ev, i) => (
                <div key={i} style={{
                  display: "flex", gap: 8, padding: "6px 0",
                  borderLeft: `2px solid ${cfg.color}30`, paddingLeft: 10, marginLeft: 4,
                  marginBottom: 2,
                }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.4 }}>{ev.detail}</div>
                    <div style={{ fontSize: 9, color: "var(--text-dim)", fontFamily: "var(--font-mono)", marginTop: 1 }}>
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : ""}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
