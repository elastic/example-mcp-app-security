import React, { useState, useEffect, useRef, useCallback } from "react";
import type { GNode, GEdge } from "./InvestigationGraph";

interface Props {
  nodes: GNode[];
  edges: GEdge[];
  onExpand: (node: GNode) => void;
  alertLinkedIds?: Set<string>;
}

const TYPE_STYLES: Record<string, { color: string; bg: string; icon: string; label: string }> = {
  user: { color: "#5c7cfa", bg: "rgba(92,124,250,0.08)", icon: "\u{1F464}", label: "USER" },
  host: { color: "#40c790", bg: "rgba(64,199,144,0.08)", icon: "\u{1F5A5}", label: "HOST" },
  ip: { color: "#f0b840", bg: "rgba(240,184,64,0.08)", icon: "\u{1F310}", label: "IP" },
  process: { color: "#b07cfa", bg: "rgba(176,124,250,0.08)", icon: "\u2699", label: "PROCESS" },
  alert: { color: "#f04040", bg: "rgba(240,64,64,0.08)", icon: "\u26A0", label: "ALERT" },
};

const CARD_W = 180;
const CARD_H = 68;
const H_GAP = 60;
const V_GAP = 16;

interface LayoutNode {
  node: GNode;
  x: number;
  y: number;
  depth: number;
  children: LayoutNode[];
}

function buildLayout(nodes: GNode[], edges: GEdge[]): { layoutNodes: LayoutNode[]; width: number; height: number } {
  if (nodes.length === 0) return { layoutNodes: [], width: 0, height: 0 };

  const adjacency = new Map<string, { target: string; label: string }[]>();
  for (const e of edges) {
    const src = typeof e.source === "string" ? e.source : e.source.id;
    const tgt = typeof e.target === "string" ? e.target : e.target.id;
    if (!adjacency.has(src)) adjacency.set(src, []);
    adjacency.get(src)!.push({ target: tgt, label: e.label });
  }

  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  // Find root: first expanded node, or first node
  const root = nodes.find((n) => n.expanded) || nodes[0];
  const visited = new Set<string>();
  const depthGroups = new Map<number, LayoutNode[]>();

  function walk(nodeId: string, depth: number): LayoutNode | null {
    if (visited.has(nodeId)) return null;
    visited.add(nodeId);
    const n = nodeMap.get(nodeId);
    if (!n) return null;

    const layoutNode: LayoutNode = { node: n, x: 0, y: 0, depth, children: [] };

    if (!depthGroups.has(depth)) depthGroups.set(depth, []);
    depthGroups.get(depth)!.push(layoutNode);

    const adj = adjacency.get(nodeId) || [];
    for (const { target } of adj) {
      const child = walk(target, depth + 1);
      if (child) layoutNode.children.push(child);
    }

    return layoutNode;
  }

  walk(root.id, 0);

  // Also add any disconnected nodes
  for (const n of nodes) {
    if (!visited.has(n.id)) {
      walk(n.id, 0);
    }
  }

  // Position: left-to-right, each depth gets a column
  const allLayout: LayoutNode[] = [];
  let maxWidth = 0;
  let maxHeight = 0;

  const sortedDepths = Array.from(depthGroups.keys()).sort((a, b) => a - b);
  for (const depth of sortedDepths) {
    const group = depthGroups.get(depth)!;
    // Sort: alerts first, then by count descending
    group.sort((a, b) => {
      if (a.node.type === "alert" && b.node.type !== "alert") return -1;
      if (b.node.type === "alert" && a.node.type !== "alert") return 1;
      const ac = Number((a.node.metadata as Record<string, unknown> | undefined)?.count || 0);
      const bc = Number((b.node.metadata as Record<string, unknown> | undefined)?.count || 0);
      return bc - ac;
    });

    const x = depth * (CARD_W + H_GAP) + 20;
    const totalH = group.length * (CARD_H + V_GAP) - V_GAP;
    const startY = 20;

    for (let i = 0; i < group.length; i++) {
      const ln = group[i];
      ln.x = x;
      ln.y = startY + i * (CARD_H + V_GAP);
      allLayout.push(ln);
      maxWidth = Math.max(maxWidth, ln.x + CARD_W + 20);
      maxHeight = Math.max(maxHeight, ln.y + CARD_H + 20);
    }
  }

  return { layoutNodes: allLayout, width: maxWidth, height: maxHeight };
}

export function CardGraph({ nodes, edges, onExpand, alertLinkedIds }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const { layoutNodes, width, height } = buildLayout(nodes, edges);

  // Edge lookup for drawing
  const edgeLabelMap = new Map<string, string>();
  for (const e of edges) {
    const src = typeof e.source === "string" ? e.source : e.source.id;
    const tgt = typeof e.target === "string" ? e.target : e.target.id;
    edgeLabelMap.set(`${src}->${tgt}`, e.label);
    edgeLabelMap.set(`${tgt}->${src}`, e.label);
  }

  const posMap = new Map<string, { x: number; y: number }>();
  for (const ln of layoutNodes) {
    posMap.set(ln.node.id, { x: ln.x, y: ln.y });
  }

  if (nodes.length === 0) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-dim)", fontSize: 13 }}>
        Click an entity in results to start investigating
      </div>
    );
  }

  const rootNode = nodes.find((n) => n.expanded) || nodes[0];

  return (
    <div ref={containerRef} style={{ width: "100%", height: "100%", overflow: "auto", position: "relative" }}>
      {/* Title */}
      <div style={{ position: "sticky", top: 0, left: 0, zIndex: 10, padding: "10px 60px 6px 14px", background: "linear-gradient(var(--bg-primary), var(--bg-primary) 80%, transparent)" }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text-primary)" }}>Exploring: {rootNode.value}</div>
        <div style={{ fontSize: 10, color: "var(--text-dim)" }}>{nodes.length} entities &bull; Click nodes to expand &rarr;</div>
      </div>

      <div style={{ position: "relative", minWidth: width, minHeight: height, padding: "0 0 20px 0" }}>
        {/* Edge lines */}
        <svg style={{ position: "absolute", inset: 0, pointerEvents: "none" }} width={width} height={height}>
          {edges.map((e, i) => {
            const src = typeof e.source === "string" ? e.source : e.source.id;
            const tgt = typeof e.target === "string" ? e.target : e.target.id;
            const sp = posMap.get(src);
            const tp = posMap.get(tgt);
            if (!sp || !tp) return null;

            const isAlert = alertLinkedIds?.has(src) || alertLinkedIds?.has(tgt);
            const x1 = sp.x + CARD_W;
            const y1 = sp.y + CARD_H / 2;
            const x2 = tp.x;
            const y2 = tp.y + CARD_H / 2;
            const mx = (x1 + x2) / 2;

            return (
              <g key={i}>
                <path d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
                  fill="none" stroke={isAlert ? "rgba(240,64,64,0.5)" : "rgba(255,255,255,0.12)"}
                  strokeWidth={isAlert ? 2 : 1.5} strokeDasharray={isAlert ? "6 3" : undefined} />
                <text x={mx} y={Math.min(y1, y2) + (Math.abs(y2 - y1) / 2) - 5}
                  fill="rgba(255,255,255,0.2)" fontSize={8} textAnchor="middle">{e.label}</text>
              </g>
            );
          })}
        </svg>

        {/* Cards */}
        {layoutNodes.map((ln) => {
          const { node } = ln;
          const style = TYPE_STYLES[node.type] || TYPE_STYLES.host;
          const isAlertLinked = alertLinkedIds?.has(node.id) || node.type === "alert";
          const count = (node.metadata as Record<string, unknown> | undefined)?.count;

          return (
            <div key={node.id} style={{
              position: "absolute", left: ln.x, top: ln.y,
              width: CARD_W, minHeight: CARD_H,
              background: "var(--bg-secondary)",
              border: `1.5px solid ${isAlertLinked ? "#f04040" : style.color}`,
              borderRadius: 10, padding: "7px 10px",
              boxShadow: isAlertLinked ? "0 0 14px rgba(240,64,64,0.2)" : "var(--shadow-sm)",
              zIndex: 2,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{
                  display: "inline-flex", alignItems: "center", justifyContent: "center",
                  width: 24, height: 24, borderRadius: 5,
                  background: style.bg, fontSize: 13,
                }}>{style.icon}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <span style={{ fontSize: 8, fontWeight: 700, letterSpacing: "0.5px", color: style.color }}>{style.label}</span>
                    {isAlertLinked && node.type !== "alert" && (
                      <span style={{ fontSize: 7, color: "#f04040", background: "rgba(240,64,64,0.12)", padding: "0 3px", borderRadius: 2, fontWeight: 700 }}>INC</span>
                    )}
                  </div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={node.value}>
                    {node.value}
                  </div>
                </div>
                {count !== undefined && (
                  <span style={{ fontSize: 11, fontWeight: 800, color: style.color, background: style.bg, padding: "1px 6px", borderRadius: 5 }}>
                    {Number(count)}
                  </span>
                )}
              </div>

              {!node.expanded && !node.loading && (
                <button onClick={() => onExpand(node)} style={{
                  display: "flex", alignItems: "center", justifyContent: "center",
                  width: "100%", padding: "2px 0", marginTop: 4,
                  background: style.bg, border: `1px solid ${style.color}30`,
                  borderRadius: 4, cursor: "pointer", color: style.color,
                  fontSize: 13, fontWeight: 700,
                }}>+</button>
              )}

              {node.loading && (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", marginTop: 4, gap: 4, fontSize: 8, color: "var(--text-muted)" }}>
                  <div className="loading-spinner" style={{ width: 10, height: 10, borderWidth: 1.5 }} /> expanding...
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div style={{ position: "sticky", bottom: 0, left: 0, padding: "6px 14px", display: "flex", gap: 10, fontSize: 9, color: "var(--text-dim)", background: "linear-gradient(transparent, var(--bg-primary) 30%)", zIndex: 3 }}>
        {Object.entries(TYPE_STYLES).map(([type, s]) => (
          <span key={type} style={{ display: "flex", alignItems: "center", gap: 3 }}>
            <span style={{ fontSize: 11 }}>{s.icon}</span> {type}
          </span>
        ))}
      </div>
    </div>
  );
}
