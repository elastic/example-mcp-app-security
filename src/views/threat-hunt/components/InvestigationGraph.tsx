/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useRef, useCallback, useState } from "react";
import * as d3Force from "d3-force";
import * as d3Selection from "d3-selection";
import * as d3Zoom from "d3-zoom";
import * as d3Drag from "d3-drag";

export interface GNode {
  id: string;
  type: "user" | "host" | "ip" | "process" | "alert";
  value: string;
  metadata?: Record<string, unknown>;
  expanded?: boolean;
  loading?: boolean;
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface GEdge {
  source: string | GNode;
  target: string | GNode;
  label: string;
}

interface Props {
  nodes: GNode[];
  edges: GEdge[];
  onExpand: (node: GNode) => void;
  onCollapse: (node: GNode) => void;
  alertLinkedIds?: Set<string>;
}

const TYPE_CONFIG: Record<string, { color: string; shape: string; radius: number }> = {
  user: { color: "#5c7cfa", shape: "circle", radius: 22 },
  host: { color: "#40c790", shape: "rect", radius: 20 },
  ip: { color: "#f0b840", shape: "diamond", radius: 18 },
  process: { color: "#b07cfa", shape: "hexagon", radius: 18 },
  alert: { color: "#f04040", shape: "triangle", radius: 20 },
};

export function InvestigationGraph({ nodes, edges, onExpand, onCollapse, alertLinkedIds }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const simRef = useRef<d3Force.Simulation<GNode, GEdge> | null>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 400 });

  useEffect(() => {
    const el = svgRef.current?.parentElement;
    if (!el) return;
    const obs = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      setDimensions({ width: Math.max(400, width), height: Math.max(250, height) });
    });
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3Selection.select(svgRef.current);
    const { width, height } = dimensions;

    svg.selectAll("*").remove();

    const g = svg.append("g");

    const zoom = d3Zoom.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoom);

    // Center the view
    const initialTransform = d3Zoom.zoomIdentity.translate(width / 2, height / 2).scale(0.9);
    svg.call(zoom.transform, initialTransform);

    const simulation = d3Force.forceSimulation<GNode>(nodes)
      .force("link", d3Force.forceLink<GNode, GEdge>(edges).id((d) => d.id).distance(120).strength(0.4))
      .force("charge", d3Force.forceManyBody().strength(-400))
      .force("center", d3Force.forceCenter(0, 0))
      .force("collision", d3Force.forceCollide().radius(40));

    simRef.current = simulation;

    // Edges
    const edgeG = g.append("g").attr("class", "edges");
    const link = edgeG.selectAll("line")
      .data(edges)
      .join("line")
      .attr("stroke", "rgba(255,255,255,0.12)")
      .attr("stroke-width", 1.5);

    const edgeLabels = edgeG.selectAll("text")
      .data(edges)
      .join("text")
      .text((d) => d.label)
      .attr("font-size", 9)
      .attr("fill", "rgba(255,255,255,0.3)")
      .attr("text-anchor", "middle")
      .attr("dy", -4);

    // Nodes
    const nodeG = g.append("g").attr("class", "nodes");
    const node = nodeG.selectAll<SVGGElement, GNode>("g")
      .data(nodes, (d) => d.id)
      .join("g")
      .attr("cursor", "pointer")
      .on("click", (_event, d) => {
        if (d.expanded) onCollapse(d);
        else onExpand(d);
      });

    // Drag behavior
    const drag = d3Drag.drag<SVGGElement, GNode>()
      .on("start", (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    node.call(drag);

    // Alert-linked glow ring
    node.filter((d) => alertLinkedIds?.has(d.id) || d.type === "alert")
      .append("circle")
      .attr("r", (d) => (TYPE_CONFIG[d.type]?.radius || 20) + 6)
      .attr("fill", "none")
      .attr("stroke", "#f04040")
      .attr("stroke-width", 2)
      .attr("stroke-dasharray", "4 3")
      .attr("opacity", 0.7);

    // Draw shapes
    node.each(function (d) {
      const el = d3Selection.select(this);
      const cfg = TYPE_CONFIG[d.type] || TYPE_CONFIG.host;
      const r = cfg.radius;

      if (d.loading) {
        el.append("circle").attr("r", r)
          .attr("fill", "none").attr("stroke", cfg.color).attr("stroke-width", 2)
          .attr("stroke-dasharray", "4 4")
          .attr("opacity", 0.6);
      } else if (cfg.shape === "circle") {
        el.append("circle").attr("r", r)
          .attr("fill", d.expanded ? cfg.color : "rgba(0,0,0,0.4)")
          .attr("stroke", cfg.color).attr("stroke-width", 2);
      } else if (cfg.shape === "rect") {
        el.append("rect").attr("x", -r).attr("y", -r * 0.7).attr("width", r * 2).attr("height", r * 1.4).attr("rx", 4)
          .attr("fill", d.expanded ? cfg.color : "rgba(0,0,0,0.4)")
          .attr("stroke", cfg.color).attr("stroke-width", 2);
      } else if (cfg.shape === "diamond") {
        el.append("polygon")
          .attr("points", `0,${-r} ${r},0 0,${r} ${-r},0`)
          .attr("fill", d.expanded ? cfg.color : "rgba(0,0,0,0.4)")
          .attr("stroke", cfg.color).attr("stroke-width", 2);
      } else if (cfg.shape === "hexagon") {
        const pts = Array.from({ length: 6 }, (_, i) => {
          const angle = (Math.PI / 3) * i - Math.PI / 6;
          return `${Math.cos(angle) * r},${Math.sin(angle) * r}`;
        }).join(" ");
        el.append("polygon").attr("points", pts)
          .attr("fill", d.expanded ? cfg.color : "rgba(0,0,0,0.4)")
          .attr("stroke", cfg.color).attr("stroke-width", 2);
      } else if (cfg.shape === "triangle") {
        el.append("polygon")
          .attr("points", `0,${-r} ${r},${r * 0.7} ${-r},${r * 0.7}`)
          .attr("fill", d.expanded ? cfg.color : "rgba(0,0,0,0.4)")
          .attr("stroke", cfg.color).attr("stroke-width", 2);
      }

      // Type icon letter
      el.append("text")
        .text(d.type[0].toUpperCase())
        .attr("text-anchor", "middle").attr("dy", "0.35em")
        .attr("font-size", 11).attr("font-weight", 700)
        .attr("fill", d.expanded ? "white" : cfg.color)
        .attr("pointer-events", "none");
    });

    // Value labels
    node.append("text")
      .text((d) => truncate(d.value, 20))
      .attr("text-anchor", "middle")
      .attr("dy", (d) => (TYPE_CONFIG[d.type]?.radius || 20) + 14)
      .attr("font-size", 10)
      .attr("fill", "rgba(255,255,255,0.7)")
      .attr("pointer-events", "none");

    // Count badges
    node.filter((d) => !!(d.metadata as Record<string, unknown> | undefined)?.count)
      .append("text")
      .text((d) => String((d.metadata as Record<string, unknown>)?.count || ""))
      .attr("text-anchor", "middle")
      .attr("dy", (d) => -((TYPE_CONFIG[d.type]?.radius || 20) + 6))
      .attr("font-size", 9)
      .attr("font-weight", 700)
      .attr("fill", (d) => TYPE_CONFIG[d.type]?.color || "#fff")
      .attr("pointer-events", "none");

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => (d.source as GNode).x || 0)
        .attr("y1", (d) => (d.source as GNode).y || 0)
        .attr("x2", (d) => (d.target as GNode).x || 0)
        .attr("y2", (d) => (d.target as GNode).y || 0);

      edgeLabels
        .attr("x", (d) => (((d.source as GNode).x || 0) + ((d.target as GNode).x || 0)) / 2)
        .attr("y", (d) => (((d.source as GNode).y || 0) + ((d.target as GNode).y || 0)) / 2);

      node.attr("transform", (d) => `translate(${d.x || 0},${d.y || 0})`);
    });

    return () => { simulation.stop(); };
  }, [nodes, edges, dimensions, onExpand, onCollapse]);

  if (nodes.length === 0) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-dim)", fontSize: 13 }}>
        Click an entity in query results to start investigating, or ask Claude to investigate a user/host/IP.
      </div>
    );
  }

  return (
    <div style={{ width: "100%", height: "100%", position: "relative" }}>
      <svg ref={svgRef} width={dimensions.width} height={dimensions.height}
        style={{ background: "var(--bg-primary)", borderRadius: "var(--radius-md)" }} />
      <div style={{ position: "absolute", bottom: 8, left: 12, display: "flex", gap: 10, fontSize: 9, color: "var(--text-dim)" }}>
        {Object.entries(TYPE_CONFIG).map(([type, cfg]) => (
          <span key={type} style={{ display: "flex", alignItems: "center", gap: 3 }}>
            <span style={{ width: 8, height: 8, borderRadius: type === "user" ? "50%" : 2, background: cfg.color }} />
            {type}
          </span>
        ))}
      </div>
    </div>
  );
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.substring(0, max - 1) + "\u2026" : s;
}
