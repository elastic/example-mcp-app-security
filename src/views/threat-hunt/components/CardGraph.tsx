/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useMemo, useRef, useEffect, useState } from "react";
import type { GNode, GEdge } from "./InvestigationGraph";

interface Props {
  nodes: GNode[];
  edges: GEdge[];
  onExpand: (node: GNode) => void;
  onSelect?: (node: GNode) => void;
  alertLinkedIds?: Set<string>;
}

// Palette tuned to app's dark theme (see InvestigationGraph for the shared reference)
const TYPE_CONFIG: Record<string, { color: string; icon: string; order: number }> = {
  alert:   { color: "#e05757", icon: "\u26A0",     order: 0 },
  user:    { color: "#5c7cfa", icon: "\u{1F464}",  order: 1 },
  host:    { color: "#4cbfa6", icon: "\u{1F5A5}",  order: 2 },
  process: { color: "#a085e0", icon: "\u2699",     order: 3 },
  ip:      { color: "#d1a54a", icon: "\u{1F310}",  order: 4 },
};

const GRAPH_BG = "#262626"; // matches .graph-pane background so node badges punch cleanly
const NODE_FILL = "#1f1f1e";
const NODE_FILL_ALT = "#262626";
const BORDER = "#474745";
const TEXT_MUTED = "#817f78";
const TEXT_SECONDARY = "#adaca1";
const ACCENT = "#5c7cfa";
const ALERT_RED = "#e05757";

// Node / badge sizes were bumped up for legibility — previous values
// (NODE_R 22, BADGE_R 9, "+" 16px) felt cramped in the Figma dot-grid pane.
const NODE_R = 30;
const COL_W = 170;
const ROW_H = 96;
const BADGE_R = 12;
const EXPAND_R = 12;      // "+" indicator radius (diameter = 24)
const MAX_PER_GROUP = 4;

interface LayoutItem {
  node: GNode;
  x: number;
  y: number;
  alertCount: number;
}

interface GroupItem {
  type: string;
  count: number;
  x: number;
  y: number;
  hidden: GNode[];
}

export function CardGraph({ nodes, edges, onExpand, onSelect, alertLinkedIds }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dims, setDims] = useState({ width: 800, height: 400 });
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const [dragOffsets, setDragOffsets] = useState<Map<string, { dx: number; dy: number }>>(new Map());
  const draggingRef = useRef<{ id: string; startX: number; startY: number; origDx: number; origDy: number } | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const obs = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      setDims({ width: Math.max(400, width), height: Math.max(250, height) });
    });
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  const { layoutItems, groups, canvasW, canvasH, edgeLines } = useMemo(() => {
    if (nodes.length === 0) return { layoutItems: [], groups: [], canvasW: 0, canvasH: 0, edgeLines: [] };

    const adj = new Map<string, Set<string>>();
    for (const e of edges) {
      const s = typeof e.source === "string" ? e.source : e.source.id;
      const t = typeof e.target === "string" ? e.target : e.target.id;
      if (!adj.has(s)) adj.set(s, new Set());
      if (!adj.has(t)) adj.set(t, new Set());
      adj.get(s)!.add(t);
      adj.get(t)!.add(s);
    }

    // Count alerts per node
    const alertCounts = new Map<string, number>();
    for (const n of nodes) {
      if (n.type === "alert") continue;
      let count = 0;
      const neighbors = adj.get(n.id);
      if (neighbors) {
        for (const nid of neighbors) {
          if (nodes.find(nn => nn.id === nid && nn.type === "alert")) count++;
        }
      }
      alertCounts.set(n.id, count);
    }

    // Group by type, then sort by order
    const byType = new Map<string, GNode[]>();
    for (const n of nodes) {
      const t = n.type;
      if (!byType.has(t)) byType.set(t, []);
      byType.get(t)!.push(n);
    }

    const typeOrder = Array.from(byType.entries()).sort(([a], [b]) =>
      (TYPE_CONFIG[a]?.order ?? 99) - (TYPE_CONFIG[b]?.order ?? 99)
    );

    const items: LayoutItem[] = [];
    const grps: GroupItem[] = [];
    const posMap = new Map<string, { x: number; y: number }>();
    let col = 0;

    for (const [type, typeNodes] of typeOrder) {
      // Sort: expanded first, then by alert count, then by event count
      typeNodes.sort((a, b) => {
        if (a.expanded && !b.expanded) return -1;
        if (!a.expanded && b.expanded) return 1;
        const ac = alertCounts.get(a.id) || 0;
        const bc = alertCounts.get(b.id) || 0;
        if (ac !== bc) return bc - ac;
        const am = Number((a.metadata as Record<string, unknown> | undefined)?.count || 0);
        const bm = Number((b.metadata as Record<string, unknown> | undefined)?.count || 0);
        return bm - am;
      });

      const visible = typeNodes.slice(0, MAX_PER_GROUP);
      const overflow = typeNodes.slice(MAX_PER_GROUP);

      const x = 60 + col * COL_W;

      for (let i = 0; i < visible.length; i++) {
        const n = visible[i];
        const y = 60 + i * ROW_H;
        items.push({ node: n, x, y, alertCount: alertCounts.get(n.id) || 0 });
        posMap.set(n.id, { x, y });
      }

      if (overflow.length > 0) {
        const y = 60 + visible.length * ROW_H;
        grps.push({ type, count: overflow.length, x, y, hidden: overflow });
        for (const n of overflow) {
          posMap.set(n.id, { x, y });
        }
      }

      col++;
    }

    // Build edges
    const lines: { x1: number; y1: number; x2: number; y2: number; label: string; isAlert: boolean; srcId: string; tgtId: string }[] = [];
    for (const e of edges) {
      const s = typeof e.source === "string" ? e.source : e.source.id;
      const t = typeof e.target === "string" ? e.target : e.target.id;
      const sp = posMap.get(s);
      const tp = posMap.get(t);
      if (!sp || !tp || (sp.x === tp.x && sp.y === tp.y)) continue;
      lines.push({
        x1: sp.x, y1: sp.y, x2: tp.x, y2: tp.y,
        label: e.label,
        srcId: s, tgtId: t,
        isAlert: alertLinkedIds?.has(s) || alertLinkedIds?.has(t) || false,
      });
    }

    const maxX = Math.max(...items.map(i => i.x), ...grps.map(g => g.x)) + COL_W;
    const maxY = Math.max(...items.map(i => i.y), ...grps.map(g => g.y)) + ROW_H + 20;

    return { layoutItems: items, groups: grps, canvasW: maxX, canvasH: Math.max(maxY, 200), edgeLines: lines };
  }, [nodes, edges, alertLinkedIds]);

  // Apply drag offsets to layout and edges
  const getPos = (id: string, baseX: number, baseY: number) => {
    const off = dragOffsets.get(id);
    return { x: baseX + (off?.dx || 0), y: baseY + (off?.dy || 0) };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    const d = draggingRef.current;
    if (!d) return;
    const dx = d.origDx + (e.clientX - d.startX);
    const dy = d.origDy + (e.clientY - d.startY);
    setDragOffsets((prev) => new Map(prev).set(d.id, { dx, dy }));
  };

  const handleMouseUp = () => {
    draggingRef.current = null;
  };

  const startDrag = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    const existing = dragOffsets.get(id);
    draggingRef.current = { id, startX: e.clientX, startY: e.clientY, origDx: existing?.dx || 0, origDy: existing?.dy || 0 };
  };

  if (nodes.length === 0) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: TEXT_MUTED, fontSize: 13, background: "transparent" }}>
        Click an entity in results to start investigating
      </div>
    );
  }

  // Compute focused connections
  const focusedNeighbors = useMemo(() => {
    if (!focusedId) return null;
    const neighbors = new Set<string>([focusedId]);
    for (const e of edges) {
      const s = typeof e.source === "string" ? e.source : e.source.id;
      const t = typeof e.target === "string" ? e.target : e.target.id;
      if (s === focusedId) neighbors.add(t);
      if (t === focusedId) neighbors.add(s);
    }
    return neighbors;
  }, [focusedId, edges]);

  return (
    <div ref={containerRef} onMouseMove={handleMouseMove} onMouseUp={handleMouseUp} onMouseLeave={handleMouseUp}
      style={{ width: "100%", height: "100%", overflow: "auto", position: "relative", background: "transparent" }}>
      {/* Wrapper flex-centers the fixed-size canvas when the pane is larger than
          the graph, and lets the canvas overflow (scroll) when the pane is
          smaller. min-width/min-height 100% + flexShrink 0 on the canvas gives
          us centering without losing scroll access in either direction. */}
      <div style={{
        minWidth: "100%",
        minHeight: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 48,
        boxSizing: "border-box",
      }}>
      <div style={{ position: "relative", width: canvasW, height: canvasH, flexShrink: 0 }}>
        {/* Edges */}
        <svg style={{ position: "absolute", inset: 0, pointerEvents: "none" }} width={canvasW} height={canvasH}>
          {edgeLines.map((e, i) => {
            const srcOff = dragOffsets.get(e.srcId);
            const tgtOff = dragOffsets.get(e.tgtId);
            const x1 = e.x1 + (srcOff?.dx || 0);
            const y1 = e.y1 + (srcOff?.dy || 0);
            const x2 = e.x2 + (tgtOff?.dx || 0);
            const y2 = e.y2 + (tgtOff?.dy || 0);
            const mx = (x1 + x2) / 2;
            const isFocusedEdge = focusedNeighbors ? (focusedNeighbors.has(e.srcId) && focusedNeighbors.has(e.tgtId)) : false;
            const dimmed = focusedNeighbors && !isFocusedEdge;
            const edgeColor = isFocusedEdge
              ? (e.isAlert ? ALERT_RED : ACCENT)
              : dimmed
                ? "#262626"
                : (e.isAlert ? "rgba(224,87,87,0.3)" : BORDER);
            return (
              <g key={i}>
                <path d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
                  fill="none" stroke={edgeColor}
                  strokeWidth={isFocusedEdge ? 2 : 1}
                  strokeDasharray={e.isAlert ? "4 3" : undefined}
                  style={{ transition: "stroke 0.2s, stroke-width 0.2s" }} />
                {isFocusedEdge && (
                  <text x={mx} y={Math.min(y1, y2) + Math.abs(y2 - y1) / 2 - 5}
                    fill={TEXT_MUTED} fontSize={9} fontFamily="var(--font-mono)" textAnchor="middle">{e.label}</text>
                )}
              </g>
            );
          })}
        </svg>

        {/* Nodes */}
        {layoutItems.map(({ node, x: baseX, y: baseY, alertCount }) => {
          const cfg = TYPE_CONFIG[node.type] || TYPE_CONFIG.host;
          const isAlertLinked = alertLinkedIds?.has(node.id) || node.type === "alert";
          const count = Number((node.metadata as Record<string, unknown> | undefined)?.count || 0);
          const isFocused = focusedId === node.id;
          const isNeighbor = focusedNeighbors?.has(node.id) || false;
          const dimmed = focusedNeighbors && !isNeighbor;
          const { x, y } = getPos(node.id, baseX, baseY);

          return (
            <div key={node.id}
              onMouseDown={(e) => startDrag(e, node.id)}
              onClick={() => { if (!draggingRef.current) onSelect?.(node); }}
              onMouseEnter={() => setFocusedId(node.id)}
              onMouseLeave={() => setFocusedId(null)}
              style={{
                position: "absolute", left: x - NODE_R, top: y - NODE_R,
                width: NODE_R * 2 + 40, textAlign: "center",
                cursor: draggingRef.current?.id === node.id ? "grabbing" : "grab",
                opacity: dimmed ? 0.2 : 1,
                transition: "opacity 0.2s",
                zIndex: isFocused ? 10 : isNeighbor ? 5 : 1,
              }}>
              {/* Circle */}
              <div style={{
                width: NODE_R * 2, height: NODE_R * 2, borderRadius: "50%",
                margin: "0 auto",
                background: node.expanded ? cfg.color : NODE_FILL,
                border: `2px solid ${isAlertLinked ? ALERT_RED : cfg.color}`,
                boxShadow: isAlertLinked ? "0 0 10px rgba(224,87,87,0.25)" : "0 1px 3px rgba(0,0,0,0.5)",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 22, position: "relative",
                transition: "all 0.2s",
              }}>
                <span style={{ filter: node.expanded ? "brightness(10)" : "none" }}>{cfg.icon}</span>

                {/* Alert count badge */}
                {alertCount > 0 && (
                  <span style={{
                    position: "absolute", top: -BADGE_R + 2, right: -BADGE_R + 2,
                    width: BADGE_R * 2, height: BADGE_R * 2, borderRadius: "50%",
                    background: ALERT_RED, color: "#fff",
                    fontSize: 11, fontWeight: 800,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    border: `2px solid ${GRAPH_BG}`,
                  }}>{alertCount}</span>
                )}

                {/* Expand indicator — the "+" is drawn as an SVG cross rather
                    than a text glyph. Text "+" inside a 24×24 flex box gets
                    clipped at the bottom by line-box rounding no matter how we
                    fiddle with line-height / padding, because the plus
                    character's em-box extends below its visible strokes and
                    the browser crops the descender. With SVG we control the
                    exact stroke geometry — perfectly centred, no clipping. */}
                {!node.expanded && !node.loading && (
                  <span onClick={(e) => { e.stopPropagation(); onExpand(node); }} style={{
                    position: "absolute", bottom: -4, right: -4,
                    width: EXPAND_R * 2, height: EXPAND_R * 2, borderRadius: "50%",
                    background: cfg.color,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    cursor: "pointer",
                    border: `2px solid ${GRAPH_BG}`,
                    boxSizing: "border-box",
                    zIndex: 5,
                  }}>
                    <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"
                      style={{ display: "block", pointerEvents: "none" }}>
                      {/* Two 2px-thick strokes centred on (5,5) — perfectly
                          symmetric both axes. shapeRendering:crispEdges so
                          the 2px strokes stay axis-aligned without AA fuzz. */}
                      <rect x="0" y="4" width="10" height="2" fill="#fff" shapeRendering="crispEdges" />
                      <rect x="4" y="0" width="2" height="10" fill="#fff" shapeRendering="crispEdges" />
                    </svg>
                  </span>
                )}

                {node.loading && (
                  <div className="loading-spinner" style={{
                    position: "absolute", inset: -4, width: NODE_R * 2 + 8, height: NODE_R * 2 + 8,
                    borderWidth: 2, borderRadius: "50%",
                  }} />
                )}
              </div>

              {/* Label */}
              <div style={{
                marginTop: 6, fontSize: 12, fontWeight: 600,
                fontFamily: "var(--font-mono)",
                color: isAlertLinked ? ALERT_RED : TEXT_SECONDARY,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                maxWidth: NODE_R * 2 + 40,
              }} title={node.value}>
                {node.value.length > 18 ? node.value.substring(0, 16) + "\u2026" : node.value}
              </div>

              {count > 0 && (
                <div style={{ fontSize: 10, color: TEXT_MUTED, fontFamily: "var(--font-mono)" }}>
                  {count.toLocaleString()}
                </div>
              )}
            </div>
          );
        })}

        {/* Overflow groups */}
        {groups.map((g, i) => {
          const cfg = TYPE_CONFIG[g.type] || TYPE_CONFIG.host;
          return (
            <div key={`group-${i}`} style={{
              position: "absolute", left: g.x - NODE_R, top: g.y - NODE_R,
              width: NODE_R * 2 + 40, textAlign: "center",
            }}>
              <div style={{
                width: NODE_R * 2, height: NODE_R * 2, borderRadius: "50%",
                margin: "0 auto",
                background: NODE_FILL_ALT,
                border: `2px dashed ${cfg.color}66`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 16, fontWeight: 700, color: cfg.color,
                fontFamily: "var(--font-mono)",
              }}>
                +{g.count}
              </div>
              <div style={{ marginTop: 6, fontSize: 11, color: TEXT_MUTED, fontFamily: "var(--font-mono)" }}>
                {g.count} more {g.type}s
              </div>
            </div>
          );
        })}
      </div>

      </div>
      {/* Legend is rendered by the parent .graph-pane — see App.tsx. */}
    </div>
  );
}
