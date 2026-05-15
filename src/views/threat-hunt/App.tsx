/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useCallback, useRef, useState } from "react";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import type { EsqlResult } from "../../shared/types";
import { useFullscreen } from "../../shared/hooks/useFullscreen";
import { useMcpApp } from "../../shared/hooks/useMcpApp";
import { AppGlyph, FullscreenIcon, ExitFullscreenIcon } from "../../shared/components/icons/icons";
import { QueryEditor } from "./components/QueryEditor";
import { ResultsTable } from "./components/ResultsTable";
// TODO: re-enable the force-directed Network view once it's stable.
// import { InvestigationGraph } from "./components/InvestigationGraph";
import type { GNode, GEdge } from "./components/InvestigationGraph";
import { CardGraph } from "./components/CardGraph";
import "./styles.css";

export function App() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<EsqlResult | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [executing, setExecuting] = useState(false);
  const [hasExecuted, setHasExecuted] = useState(false);

  const [graphNodes, setGraphNodes] = useState<GNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GEdge[]>([]);
  const [graphActive, setGraphActive] = useState(false);
  // The force-directed "Network" view is hidden for now — it gets messy fast
  // when hunting across many alerts/users/hosts. We default to the Cards view
  // and leave the toggle out of the UI until the network layout is improved.
  const [selectedNode, setSelectedNode] = useState<GNode | null>(null);
  const [nodeDetail, setNodeDetail] = useState<Record<string, unknown> | null>(null);
  const [nodeDetailLoading, setNodeDetailLoading] = useState(false);

  // Pending query/entity references survive across renders so the
  // ontoolresult callback can stash work that came in before connect()
  // resolved, and the onConnect callback can flush it.
  const pendingRef = useRef<{ query: string | null; entity: { type: string; value: string } | null }>({
    query: null,
    entity: null,
  });

  // Forward declaration of the running flush function — populated below once
  // `executeQuery` and `addEntityToGraph` have been defined. Using a ref
  // sidesteps the temporal dead zone between `useMcpApp`'s callbacks (which
  // need to call flush) and the closures themselves (which need `getApp`).
  const flushPendingRef = useRef<() => void>(() => {});

  const { connected, getApp } = useMcpApp({
    name: "threat-hunt",
    version: "1.0.0",
    onToolResult: (result) => {
      try {
        const text = extractToolText(result);
        if (text) {
          const data = JSON.parse(text);
          if (data.params?.query) {
            const q = String(data.params.query).trim();
            setQuery(q);
            pendingRef.current.query = q;
          }
          if (data.params?.entity) {
            pendingRef.current.entity = data.params.entity;
          }
        }
      } catch { /* ignore */ }
      flushPendingRef.current();
    },
    onConnect: () => {
      // Final flush after the grace window — picks up anything that arrived
      // before connect() resolved.
      flushPendingRef.current();
    },
  });

  const fullscreen = useFullscreen(getApp);

  const executeQuery = useCallback(async (q: string) => {
    const app = getApp();
    if (!app || !q.trim()) return;
    setExecuting(true);
    setQueryError(null);
    setResults(null);
    setHasExecuted(true);
    try {
      const result = await app.callServerTool({ name: "execute-esql", arguments: { query: q } });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text) as { error?: string } & EsqlResult;
        if (data.error) setQueryError(data.error);
        else {
          setResults(data);
          const rowCount = Array.isArray(data.values) ? data.values.length : 0;
          if (rowCount === 0) {
            setGraphNodes([]);
            setGraphEdges([]);
            setGraphActive(false);
            setSelectedNode(null);
          }
        }
      }
    } catch (e) { setQueryError(e instanceof Error ? e.message : String(e)); }
    finally { setExecuting(false); }
  // `getApp` is a stable accessor returned by `useMcpApp` — safe to omit from deps.
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
    const app = getApp();
    if (!app) return;

    const rootId = `${type}:${value}`;
    setGraphNodes((prev) => prev.map((n) => n.id === rootId ? { ...n, loading: true } : n));

    try {
      const result = await app.callServerTool({
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
    const app = getApp();
    if (!app) { setNodeDetailLoading(false); return; }
    try {
      const result = await app.callServerTool({
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

  // collapseEntity was used by the hidden InvestigationGraph (force-directed)
  // view; restore alongside that component when re-enabling the Network view.

  // Bind the live flush function so the `useMcpApp` callbacks declared above
  // can call it via `flushPendingRef.current()` without TDZ issues.
  flushPendingRef.current = () => {
    const pending = pendingRef.current;
    if (pending.entity) {
      const e = pending.entity;
      pending.entity = null;
      addEntityToGraph(e.type, e.value);
    }
    if (pending.query) {
      const q = pending.query;
      pending.query = null;
      executeQuery(q);
    }
  };

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
            onClick={fullscreen.toggle}
            title={fullscreen.isFullscreen ? "Exit fullscreen" : "Fullscreen"}
            aria-label={fullscreen.isFullscreen ? "Exit fullscreen" : "Fullscreen"}
          >
            {fullscreen.isFullscreen ? <ExitFullscreenIcon /> : <FullscreenIcon />}
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

                <div className="graph-pane-canvas">
                  <CardGraph nodes={graphNodes} edges={graphEdges}
                    onExpand={(n) => expandEntity(n.type, n.value)}
                    onSelect={selectNode}
                    alertLinkedIds={alertLinkedIds} />
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
