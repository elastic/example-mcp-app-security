/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

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

const AppGlyph = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <path d="M23.9506 12.4984C23.9527 11.5265 23.6542 10.5777 23.0961 9.78204C22.538 8.98635 21.7475 8.38267 20.8329 8.05369C20.9165 7.62975 20.9586 7.19872 20.9588 6.76664C20.9593 5.33599 20.5061 3.94206 19.6645 2.78515C18.8228 1.62826 17.6361 0.767973 16.2748 0.327936C14.9135 -0.112099 13.4478 -0.109226 12.0882 0.336144C10.7287 0.781513 9.54534 1.64645 8.70826 2.80664C8.09097 2.32848 7.33466 2.06452 6.55389 2.05472C5.77314 2.04491 5.01045 2.2898 4.38134 2.75229C3.75222 3.21479 3.29095 3.86969 3.0674 4.61782C2.84384 5.36595 2.87015 6.16656 3.14238 6.8984C2.22542 7.23206 1.43269 7.83861 0.870884 8.63641C0.309073 9.43422 0.00515049 10.385 2.34805e-05 11.3608C-0.00305405 12.3366 0.296461 13.2893 0.857326 14.0879C1.41819 14.8864 2.21282 15.4914 3.13179 15.8195C3.05214 16.2435 3.01275 16.6741 3.01414 17.1054C3.01158 18.5358 3.46368 19.9298 4.30518 21.0864C5.14666 22.2429 6.33397 23.1021 7.69564 23.5398C9.05729 23.9775 10.5228 23.9711 11.8806 23.5214C13.2384 23.0718 14.4181 22.2022 15.2494 21.0384C15.8649 21.5186 16.6204 21.7849 17.4009 21.7969C18.1815 21.8089 18.9447 21.566 19.5747 21.1049C20.2047 20.6438 20.6669 19.9898 20.8915 19.242C21.1161 18.4944 21.0906 17.6938 20.8188 16.9619C21.734 16.6265 22.5246 16.0189 23.0845 15.2211C23.6442 14.4232 23.9465 13.4731 23.9506 12.4984ZM9.27296 3.52899C10.0442 2.40726 11.1788 1.586 12.4853 1.20381C13.7919 0.821635 15.1902 0.901957 16.4444 1.43121C17.6986 1.96048 18.7316 2.90626 19.3694 4.10891C20.0071 5.31156 20.2104 6.69741 19.9447 8.03252L14.6576 12.6631L9.41649 10.2749L8.39297 8.09017L9.27296 3.52899ZM6.62238 2.94075C7.24393 2.94062 7.84828 3.14484 8.34238 3.52193L7.54943 7.60311L3.95885 6.75487C3.80314 6.32609 3.75287 5.86614 3.81229 5.41386C3.87172 4.96158 4.03908 4.53022 4.30026 4.15621C4.56145 3.78221 4.90878 3.47653 5.31293 3.26499C5.71708 3.05344 6.1662 2.94224 6.62238 2.94075ZM0.925906 11.3713C0.931192 10.5387 1.19621 9.72838 1.68401 9.05351C2.17182 8.37865 2.85807 7.87284 3.64708 7.60664L7.58826 8.53722L8.51296 10.5149L3.47414 15.0725C2.72441 14.7865 2.07928 14.2793 1.62421 13.6184C1.16915 12.9574 0.925627 12.1738 0.925906 11.3713ZM14.7012 20.3348C13.9892 21.3831 12.9599 22.1753 11.7643 22.5953C10.5688 23.0152 9.27013 23.0407 8.05905 22.668C6.84795 22.2953 5.78828 21.5441 5.03568 20.5247C4.28307 19.5053 3.8772 18.2714 3.87767 17.0042C3.87822 16.6092 3.91764 16.2152 3.99532 15.8278L9.14826 11.1643L14.4094 13.5619L15.5741 15.7878L14.7012 20.3348ZM17.3341 20.9231C16.7144 20.9209 16.1126 20.7142 15.6224 20.3348L16.4035 16.2666L19.9918 17.1054C20.1479 17.5339 20.1986 17.9934 20.1396 18.4455C20.0808 18.8976 19.914 19.3289 19.6534 19.7031C19.3928 20.0772 19.0461 20.3831 18.6425 20.5951C18.2388 20.8069 17.79 20.9187 17.3341 20.9207V20.9231ZM20.3035 16.2513L16.3529 15.3278L15.3035 13.3278L20.4706 8.80075C21.2209 9.08447 21.8672 9.58986 22.3234 10.2497C22.7796 10.9096 23.0242 11.6926 23.0247 12.4948C23.0173 13.3258 22.7512 14.1336 22.2635 14.8065C21.7759 15.4792 21.0908 15.9834 20.3035 16.2489V16.2513Z" fill="currentColor"/>
  </svg>
);

const FullscreenIcon = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M2 6V2h4" /><path d="M14 6V2h-4" /><path d="M2 10v4h4" /><path d="M14 10v4h-4" />
  </svg>
);

const ExitFullscreenIcon = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M6 2v4H2" /><path d="M10 2v4h4" /><path d="M6 14v-4H2" /><path d="M10 14v-4h4" />
  </svg>
);

/**
 * Default state for the view. Seeds a realistic hunt scenario so the page
 * isn't empty on first load — the user sees a query, a populated results
 * table, and the investigation graph already expanded for the primary host.
 * The scenario matches the "domain-controller compromise" storyline used
 * across the fixtures (win-dc-01 + LSASS memory dump).
 */
const DEFAULT_QUERY = `FROM logs-*
| WHERE host.name == "win-dc-01"
| STATS count = COUNT(*) BY user.name, process.name
| SORT count DESC
| LIMIT 10`;

const DEFAULT_RESULTS: EsqlResult = {
  columns: [
    { name: "user.name", type: "keyword" },
    { name: "process.name", type: "keyword" },
    { name: "host.name", type: "keyword" },
    { name: "count", type: "long" },
  ],
  values: [
    ["svc_backup", "powershell.exe", "win-dc-01", 147],
    ["svc_backup", "procdump.exe", "win-dc-01", 42],
    ["admin.backup", "powershell.exe", "win-dc-01", 38],
    ["svc_backup", "cmd.exe", "win-dc-01", 29],
    ["admin.backup", "rundll32.exe", "win-dc-01", 21],
    ["svc_backup", "net.exe", "win-dc-01", 17],
    ["admin.backup", "wmic.exe", "win-dc-01", 14],
    ["svc_backup", "reg.exe", "win-dc-01", 11],
  ],
};

const DEFAULT_GRAPH_NODES: GNode[] = [
  { id: "host:win-dc-01",          type: "host",    value: "win-dc-01",        expanded: true },
  { id: "user:svc_backup",         type: "user",    value: "svc_backup",       expanded: true },
  { id: "user:admin.backup",       type: "user",    value: "admin.backup" },
  { id: "process:powershell.exe",  type: "process", value: "powershell.exe" },
  { id: "process:procdump.exe",    type: "process", value: "procdump.exe" },
  { id: "ip:185.220.101.42",       type: "ip",      value: "185.220.101.42" },
  { id: "alert:al-1001",           type: "alert",   value: "LSASS memory dump" },
  { id: "host:fs01",               type: "host",    value: "fs01" },
];

const DEFAULT_GRAPH_EDGES: GEdge[] = [
  { source: "host:win-dc-01", target: "user:svc_backup",        label: "ran-as" },
  { source: "host:win-dc-01", target: "user:admin.backup",      label: "ran-as" },
  { source: "host:win-dc-01", target: "process:powershell.exe", label: "executed" },
  { source: "host:win-dc-01", target: "process:procdump.exe",   label: "executed" },
  { source: "host:win-dc-01", target: "ip:185.220.101.42",      label: "connected-to" },
  { source: "host:win-dc-01", target: "alert:al-1001",          label: "triggered" },
  { source: "user:svc_backup", target: "host:fs01",             label: "accessed" },
];

export function App() {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  const [query, setQuery] = useState(DEFAULT_QUERY);
  const [results, setResults] = useState<EsqlResult | null>(DEFAULT_RESULTS);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [executing, setExecuting] = useState(false);
  const [hasExecuted, setHasExecuted] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);

  const [graphNodes, setGraphNodes] = useState<GNode[]>(DEFAULT_GRAPH_NODES);
  const [graphEdges, setGraphEdges] = useState<GEdge[]>(DEFAULT_GRAPH_EDGES);
  const [graphActive, setGraphActive] = useState(true);
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

  /**
   * Seed the investigation graph with a pre-built example so users can see the
   * visualization without having to click entities in a results table. This is
   * especially useful when the view is driven by a playbook that only issues
   * ES|QL queries — the graph pane would otherwise stay hidden. The example
   * mirrors the "domain-controller compromise" storyline used in the fixtures:
   * a host hub with user/process/IP/alert neighbors and a lateral pivot to a
   * second host.
   */
  const loadExampleInvestigation = useCallback(() => {
    const rootId = "host:win-dc-01";
    const nodes: GNode[] = [
      { id: rootId, type: "host", value: "win-dc-01", expanded: true },
      { id: "user:svc_backup", type: "user", value: "svc_backup", expanded: true },
      { id: "user:admin.backup", type: "user", value: "admin.backup" },
      { id: "process:powershell.exe", type: "process", value: "powershell.exe" },
      { id: "process:procdump.exe", type: "process", value: "procdump.exe" },
      { id: "ip:185.220.101.42", type: "ip", value: "185.220.101.42" },
      { id: "alert:al-1001", type: "alert", value: "LSASS memory dump" },
      { id: "host:fs01", type: "host", value: "fs01" },
    ];
    const edges: GEdge[] = [
      { source: rootId, target: "user:svc_backup", label: "ran-as" },
      { source: rootId, target: "user:admin.backup", label: "ran-as" },
      { source: rootId, target: "process:powershell.exe", label: "executed" },
      { source: rootId, target: "process:procdump.exe", label: "executed" },
      { source: rootId, target: "ip:185.220.101.42", label: "connected-to" },
      { source: rootId, target: "alert:al-1001", label: "triggered" },
      { source: "user:svc_backup", target: "host:fs01", label: "accessed" },
    ];
    setGraphNodes(nodes);
    setGraphEdges(edges);
    setGraphActive(true);
    setSelectedNode(null);
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
    const app = new McpApp({ name: "threat-hunt", version: "1.0.0" });
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
    return (
      <div className="hunt-app">
        <div className="loading-state">
          <div className="loading-spinner" />
          <span>Connecting to server...</span>
        </div>
      </div>
    );
  }

  const alertNodeIds = new Set(graphNodes.filter((n) => n.type === "alert").map((n) => n.id));
  const alertLinkedIds = new Set<string>();
  for (const e of graphEdges) {
    const src = typeof e.source === "string" ? e.source : e.source.id;
    const tgt = typeof e.target === "string" ? e.target : e.target.id;
    if (alertNodeIds.has(src)) alertLinkedIds.add(tgt);
    if (alertNodeIds.has(tgt)) alertLinkedIds.add(src);
  }

  const clearGraph = () => {
    setGraphNodes([]);
    setGraphEdges([]);
    setGraphActive(false);
    setSelectedNode(null);
  };

  return (
    <div className="hunt-app">
      <header className="hunt-header">
        <div className="hunt-header-left">
          <div className="hunt-header-brand">
            <span className="hunt-header-glyph" aria-hidden="true"><AppGlyph /></span>
            <h1 className="hunt-header-title">Threat Hunt</h1>
          </div>
          <div className="hunt-header-pills">
            <span className="hunt-esql-pill">ES|QL</span>
            {graphActive && (
              <span className="hunt-entities-pill">
                <span className="hunt-entities-pill-dot" />
                {graphNodes.length} {graphNodes.length === 1 ? "entity" : "entities"}
              </span>
            )}
          </div>
        </div>
        <div className="hunt-header-actions">
          {!graphActive && (
            <button
              className="hunt-header-ghost-btn"
              onClick={loadExampleInvestigation}
              title="Show an example investigation graph"
            >
              Example graph
            </button>
          )}
          {graphActive && (
            <button className="hunt-header-ghost-btn" onClick={clearGraph} title="Clear investigation graph">
              Clear
            </button>
          )}
          <button
            type="button"
            className="hunt-header-icon-btn"
            onClick={() => {
              const next = !isFullscreen;
              try { appRef.current?.requestDisplayMode({ mode: next ? "fullscreen" : "inline" }); } catch {}
              setIsFullscreen(next);
            }}
            title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
            aria-label={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
          >
            {isFullscreen ? <ExitFullscreenIcon /> : <FullscreenIcon />}
          </button>
        </div>
      </header>

      <div className="hunt-body">
        {/* Filter (ES|QL query editor) sits directly under the header. */}
        <QueryEditor query={query} onChange={setQuery} onExecute={() => executeQuery(query)} executing={executing} />
        {queryError && <div className="query-error">{queryError}</div>}

        {/* Visualization (on top) + results table share a single bordered block. */}
        <div className="hunt-viz-results-block">
          {graphActive && (() => {
            // Title shows "Exploring: <root>" where root is the first expanded
            // node (or the first node if none are expanded). Matches Figma 3-3041.
            const rootNode = graphNodes.find((n) => n.expanded) || graphNodes[0];
            return (
              <div className="graph-pane">
                <div className="graph-pane-title">
                  {rootNode ? `Exploring: ${rootNode.value}` : "Investigation graph"}
                </div>

                <div className="graph-pane-toolbar">
                  <div className="graph-pane-view-toggle" role="tablist">
                    <button
                      role="tab"
                      aria-selected={graphView === "card"}
                      className={`graph-pane-view-option${graphView === "card" ? " active" : ""}`}
                      onClick={() => setGraphView("card")}
                    >Cards</button>
                    <button
                      role="tab"
                      aria-selected={graphView === "force"}
                      className={`graph-pane-view-option${graphView === "force" ? " active" : ""}`}
                      onClick={() => setGraphView("force")}
                    >Network</button>
                  </div>
                </div>

                <div className="graph-pane-canvas">
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
                </div>

                <div className="graph-pane-legend" aria-hidden="true">
                  <span className="graph-pane-legend-item">
                    <span className="graph-pane-legend-dot" style={{ background: "#e05757" }} />alert
                  </span>
                  <span className="graph-pane-legend-item">
                    <span className="graph-pane-legend-dot" style={{ background: "#5c7cfa" }} />user
                  </span>
                  <span className="graph-pane-legend-item">
                    <span className="graph-pane-legend-dot" style={{ background: "#4cbfa6" }} />host
                  </span>
                  <span className="graph-pane-legend-item">
                    <span className="graph-pane-legend-dot" style={{ background: "#a085e0" }} />process
                  </span>
                  <span className="graph-pane-legend-item">
                    <span className="graph-pane-legend-dot" style={{ background: "#d1a54a" }} />ip
                  </span>
                </div>

                {selectedNode && (
                  <NodeDetailPanel node={selectedNode} detail={nodeDetail} loading={nodeDetailLoading}
                    onClose={() => setSelectedNode(null)} />
                )}
              </div>
            );
          })()}

          <ResultsTable results={results} executing={executing} hasExecuted={hasExecuted} queryError={queryError}
            onEntityClick={(type, value) => addEntityToGraph(type, value)} />
        </div>
      </div>
    </div>
  );
}

/* ─── Node Detail Panel ─── */

const TYPE_LABELS: Record<string, { icon: string; label: string; color: string }> = {
  alert: { icon: "\u26A0", label: "Alert", color: "#f04040" },
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
  const sevKey = sevField?.value as "critical" | "high" | "medium" | "low" | undefined;
  const sevColor = sevKey === "critical" ? "#f04040" :
    sevKey === "high" ? "#ff8a50" :
    sevKey === "medium" ? "#f0b840" :
    sevKey === "low" ? "#40c790" : null;

  return (
    <div className="node-detail-panel" style={{ borderLeftColor: cfg.color }}>
      <div className="node-detail-panel-header">
        <div className="node-detail-panel-head-row">
          <div className="node-detail-panel-identity">
            <span
              className="node-detail-panel-icon"
              style={{ borderColor: cfg.color, background: `${cfg.color}15` }}
            >{cfg.icon}</span>
            <div className="node-detail-panel-identity-text">
              <div className="node-detail-panel-kind" style={{ color: cfg.color }}>{cfg.label}</div>
              <div className="node-detail-panel-value">{node.value}</div>
            </div>
          </div>
          <button className="node-detail-panel-close" onClick={onClose} aria-label="Close">×</button>
        </div>
        {sevColor && sevKey && (
          <span className={`sev-chip sev-chip-${sevKey}`} style={{ marginTop: 10 }}>
            <span className="sev-chip-dot" />
            <span className="sev-chip-label">{sevKey[0].toUpperCase() + sevKey.slice(1)}</span>
          </span>
        )}
      </div>

      {loading ? (
        <div className="loading-state" style={{ padding: 40 }}>
          <div className="loading-spinner" style={{ width: 18, height: 18 }} />
          <span>Loading details...</span>
        </div>
      ) : (
        <div className="node-detail-panel-body">
          {fields.map((f, i) => (
            <div key={i} className="node-detail-field">
              <div className="node-detail-field-label">{f.label}</div>
              <div className={`node-detail-field-value${f.mono ? " mono" : ""}`}>{f.value || "—"}</div>
            </div>
          ))}

          {events.length > 0 && (
            <div className="node-detail-events">
              <div className="node-detail-events-title">
                Recent Activity <span className="node-detail-events-count">{events.length}</span>
              </div>
              <div className="node-detail-events-list">
                {events.map((ev, i) => (
                  <div key={i} className="node-detail-event-row" style={{ borderLeftColor: `${cfg.color}50` }}>
                    <div className="node-detail-event-detail">{ev.detail}</div>
                    <div className="node-detail-event-ts">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : ""}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
