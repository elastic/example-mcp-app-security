import React, { useState, useEffect, useCallback, useRef } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme } from "../../shared/theme";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
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

  const investigateEntity = useCallback(async (type: string, value: string) => {
    if (!appRef.current) return;
    setGraphActive(true);

    const rootId = `${type}:${value}`;
    setGraphNodes((prev) => {
      if (prev.some((n) => n.id === rootId)) return prev.map((n) => n.id === rootId ? { ...n, loading: true } : n);
      return [...prev, { id: rootId, type: type as GNode["type"], value, loading: true }];
    });

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
        investigateEntity(e.type, e.value);
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
  }, [executeQuery, investigateEntity]);

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
      <header className="filter-bar" style={{ flexWrap: "wrap" }}>
        <span className="filter-bar-title">Threat Hunt</span>
        <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--accent)" }}>ES|QL</span>
        {graphActive && (
          <>
            <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: "auto" }}>
              {graphNodes.length} entities &middot; {graphEdges.length} connections
              {alertNodeIds.size > 0 && <span style={{ color: "var(--severity-critical)", marginLeft: 6 }}>{alertNodeIds.size} alerts</span>}
            </span>
            <button className="btn btn-sm btn-ghost" onClick={() => { setGraphNodes([]); setGraphEdges([]); setGraphActive(false); }}>
              Clear Graph
            </button>
          </>
        )}
        <button className="btn btn-sm btn-ghost" style={{ flexShrink: 0, marginLeft: graphActive ? 0 : "auto" }} onClick={() => {
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
                onExpand={(n) => investigateEntity(n.type, n.value)}
                alertLinkedIds={alertLinkedIds} />
            ) : (
              <InvestigationGraph nodes={graphNodes} edges={graphEdges}
                onExpand={(n) => investigateEntity(n.type, n.value)}
                onCollapse={collapseEntity}
                alertLinkedIds={alertLinkedIds} />
            )}
          </div>
        )}

        <div className="hunt-query-pane">
          <QueryEditor query={query} onChange={setQuery} onExecute={() => executeQuery(query)} executing={executing} />
          {queryError && <div className="query-error">{queryError}</div>}
          <ResultsTable results={results} executing={executing} hasExecuted={hasExecuted} queryError={queryError}
            onEntityClick={(type, value) => investigateEntity(type, value)} />
        </div>
      </div>
    </div>
  );
}
