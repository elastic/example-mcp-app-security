import React, { useState, useMemo } from "react";
import type { AttackDiscoveryFinding, DiscoveryDetail } from "../../shared/types";

const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact",
];

const TACTIC_COLOR: Record<string, string> = {
  "Reconnaissance": "#6dccb1", "Resource Development": "#6dccb1",
  "Initial Access": "#79aad9", "Execution": "#e7664c",
  "Persistence": "#da8b45", "Privilege Escalation": "#d6bf57",
  "Defense Evasion": "#b9a888", "Credential Access": "#e7664c",
  "Discovery": "#54b399", "Lateral Movement": "#da8b45",
  "Collection": "#d6bf57", "Command and Control": "#e7664c",
  "Exfiltration": "#e7664c", "Impact": "#bd271e",
};

const NODE_ICON: Record<string, string> = {
  campaign: "\u2620",
  host: "\uD83D\uDDA5\uFE0F",
  alert: "\u26A0\uFE0F",
  user: "\uD83D\uDC64",
  ip: "\uD83C\uDF10",
};

interface GNode {
  id: string;
  type: "campaign" | "host" | "alert" | "user" | "ip";
  label: string;
  sublabel?: string;
  detail?: string;
  color: string;
  tactic?: string;
  severity?: string;
}

interface GEdge {
  source: string;
  target: string;
  label?: string;
  dashed?: boolean;
}

interface TreeNode {
  gnode: GNode;
  children: TreeNode[];
  subtreeW: number;
  x: number;
  y: number;
}

interface Positioned {
  id: string;
  node: GNode;
  x: number;
  y: number;
}

interface Props {
  discovery: AttackDiscoveryFinding;
  detail: DiscoveryDetail | null;
}

function matchTactic(ruleName: string, tactics: string[]): string | undefined {
  const lower = ruleName.toLowerCase();
  for (const t of tactics) {
    if (lower.includes(t.toLowerCase())) return t;
    for (const word of t.toLowerCase().split(/\s+/)) {
      if (word.length > 4 && lower.includes(word)) return t;
    }
  }
  return undefined;
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + "\u2026" : s;
}

function buildGraph(
  disc: AttackDiscoveryFinding,
  det: DiscoveryDetail | null,
): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = [];
  const edges: GEdge[] = [];
  const ids = new Set<string>();
  const tactics = disc.mitreTactics || [];

  const add = (n: GNode) => { if (!ids.has(n.id)) { nodes.push(n); ids.add(n.id); } };

  add({
    id: "campaign",
    type: "campaign",
    label: truncate(disc.title, 36),
    sublabel: `ATK-${disc.id.slice(0, 12).toUpperCase()}`,
    color: "#e7664c",
  });

  const hosts = disc.hosts || [];
  for (const h of hosts) {
    add({ id: `host:${h}`, type: "host", label: truncate(h, 22), sublabel: "HOST", color: "#40c790" });
    edges.push({ source: "campaign", target: `host:${h}`, label: "Targets" });
  }

  if (det?.alerts) {
    const userAdded = new Set<string>();

    for (const a of det.alerts) {
      const tactic = matchTactic(a.ruleName, tactics);
      const color = tactic ? (TACTIC_COLOR[tactic] || "#5c7cfa") : "#5c7cfa";
      add({
        id: `alert:${a.id}`,
        type: "alert",
        label: truncate(a.ruleName, 24),
        sublabel: tactic,
        detail: a.severity,
        color,
        tactic,
        severity: a.severity,
      });

      const parent = hosts.includes(a.host)
        ? `host:${a.host}`
        : hosts.length > 0 ? `host:${hosts[0]}` : "campaign";

      const edgeLabel = tactic
        ? tactic.split(" ").slice(0, 2).join(" ")
        : "Triggers";
      edges.push({ source: parent, target: `alert:${a.id}`, label: edgeLabel });

      if (a.user && !userAdded.has(a.user)) {
        userAdded.add(a.user);
        add({
          id: `user:${a.user}`,
          type: "user",
          label: a.user,
          sublabel: "USER",
          color: "#5c7cfa",
        });
        edges.push({
          source: `alert:${a.id}`,
          target: `user:${a.user}`,
          label: "Actor",
          dashed: true,
        });
      }
    }

    if (det.entityRisk) {
      for (const er of det.entityRisk) {
        if (ids.has(`host:${er.name}`) || ids.has(`user:${er.name}`)) continue;
        const type = er.type === "host" ? "host" as const
          : er.type === "user" ? "user" as const
          : "ip" as const;
        const color = er.level === "critical" ? "#e7664c"
          : er.level === "high" ? "#da8b45" : "#54b399";
        add({
          id: `entity:${er.name}`,
          type,
          label: truncate(er.name, 22),
          sublabel: `${er.level.toUpperCase()} \u00B7 ${er.score.toFixed(0)}`,
          color,
        });
        const related = det.alerts.find(
          (a) => a.host === er.name || a.user === er.name,
        );
        edges.push({
          source: related ? `alert:${related.id}` : "campaign",
          target: `entity:${er.name}`,
          label: "Risk",
          dashed: true,
        });
      }
    }
  } else {
    for (const u of disc.users || []) {
      add({ id: `user:${u}`, type: "user", label: u, sublabel: "USER", color: "#5c7cfa" });
      edges.push({ source: "campaign", target: `user:${u}`, label: "Involves", dashed: true });
    }
  }

  return { nodes, edges };
}

function toTree(nodes: GNode[], edges: GEdge[]): TreeNode {
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const childMap = new Map<string, string[]>();
  for (const e of edges) {
    if (!childMap.has(e.source)) childMap.set(e.source, []);
    childMap.get(e.source)!.push(e.target);
  }

  const visited = new Set<string>();
  function walk(id: string): TreeNode | null {
    if (visited.has(id)) return null;
    visited.add(id);
    const gnode = nodeMap.get(id);
    if (!gnode) return null;
    const children: TreeNode[] = [];
    for (const cid of childMap.get(id) || []) {
      const child = walk(cid);
      if (child) children.push(child);
    }
    return { gnode, children, subtreeW: 0, x: 0, y: 0 };
  }

  const root = walk("campaign") || { gnode: nodes[0], children: [], subtreeW: 0, x: 0, y: 0 };
  for (const n of nodes) {
    if (!visited.has(n.id)) {
      const orphan = walk(n.id);
      if (orphan) root.children.push(orphan);
    }
  }
  return root;
}

function computeWidths(tree: TreeNode, cardW: number, gap: number): number {
  if (tree.children.length === 0) {
    tree.subtreeW = cardW;
    return cardW;
  }
  let w = 0;
  for (const c of tree.children) w += computeWidths(c, cardW, gap) + gap;
  w -= gap;
  tree.subtreeW = Math.max(w, cardW);
  return tree.subtreeW;
}

function positionTree(
  tree: TreeNode, sx: number, sy: number,
  cardW: number, cardH: number, layerGap: number, gap: number,
  out: Positioned[],
) {
  tree.x = sx + tree.subtreeW / 2 - cardW / 2;
  tree.y = sy;
  out.push({ id: tree.gnode.id, node: tree.gnode, x: tree.x, y: tree.y });
  let cx = sx;
  for (const c of tree.children) {
    positionTree(c, cx, sy + cardH + layerGap, cardW, cardH, layerGap, gap, out);
    cx += c.subtreeW + gap;
  }
}

export function AttackFlowDiagram({ discovery, detail }: Props) {
  const [scale, setScale] = useState<"compact" | "default" | "expand">("default");

  const dims = {
    compact:  { cardW: 130, cardH: 50, layerGap: 48, nodeGap: 12 },
    default:  { cardW: 170, cardH: 70, layerGap: 72, nodeGap: 24 },
    expand:   { cardW: 200, cardH: 80, layerGap: 96, nodeGap: 36 },
  }[scale];

  const { cardW, cardH, layerGap, nodeGap } = dims;
  const PAD = 30;

  const { nodes, edges } = useMemo(() => buildGraph(discovery, detail), [discovery, detail]);

  const { positioned, totalW, totalH } = useMemo(() => {
    const tree = toTree(nodes, edges);
    computeWidths(tree, cardW, nodeGap);
    const out: Positioned[] = [];
    positionTree(tree, PAD, PAD, cardW, cardH, layerGap, nodeGap, out);
    const maxX = Math.max(...out.map((p) => p.x + cardW), 0);
    const maxY = Math.max(...out.map((p) => p.y + cardH), 0);
    return { positioned: out, totalW: maxX + PAD, totalH: maxY + PAD };
  }, [nodes, edges, cardW, cardH, layerGap, nodeGap]);

  const posMap = useMemo(() => {
    const m = new Map<string, Positioned>();
    for (const p of positioned) m.set(p.id, p);
    return m;
  }, [positioned]);

  const tacticsInView = useMemo(() => {
    const seen = new Set<string>();
    for (const n of nodes) if (n.tactic) seen.add(n.tactic);
    return TACTIC_ORDER.filter((t) => seen.has(t));
  }, [nodes]);

  if (nodes.length <= 1 && !detail) {
    return (
      <div className="empty-state" style={{ padding: 30 }}>
        <div className="loading-spinner" />
        <span>Building attack graph\u2026</span>
      </div>
    );
  }

  return (
    <div className="attack-graph">
      <div className="ag-controls">
        <button
          className={`ag-ctrl ${scale === "compact" ? "active" : ""}`}
          onClick={() => setScale("compact")}
        >
          {"\u25FC"} Compact
        </button>
        <button className="ag-ctrl" onClick={() => setScale("default")}>
          {"\u21BA"} Reset
        </button>
        <button
          className={`ag-ctrl ${scale === "expand" ? "active" : ""}`}
          onClick={() => setScale("expand")}
        >
          {"\u2922"} Expand
        </button>

        {tacticsInView.length > 0 && (
          <div className="ag-legend">
            {tacticsInView.map((t) => (
              <span key={t} className="ag-legend-item">
                <span className="ag-legend-dot" style={{ background: TACTIC_COLOR[t] }} />
                {t}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="ag-scroll">
        <div className="ag-canvas" style={{ width: totalW, height: totalH }}>
          <svg
            className="ag-edges"
            width={totalW}
            height={totalH}
          >
            <defs>
              <marker
                id="ag-arrow"
                viewBox="0 0 10 6"
                refX="10"
                refY="3"
                markerWidth="7"
                markerHeight="4"
                orient="auto"
              >
                <path d="M0,0 L10,3 L0,6 Z" fill="rgba(255,255,255,0.25)" />
              </marker>
              <filter id="ag-glow">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {edges.map((e, i) => {
              const sp = posMap.get(e.source);
              const tp = posMap.get(e.target);
              if (!sp || !tp) return null;
              const x1 = sp.x + cardW / 2;
              const y1 = sp.y + cardH;
              const x2 = tp.x + cardW / 2;
              const y2 = tp.y;
              const my = (y1 + y2) / 2;

              return (
                <g key={i}>
                  <path
                    d={`M ${x1} ${y1} C ${x1} ${my}, ${x2} ${my}, ${x2} ${y2}`}
                    fill="none"
                    stroke={e.dashed ? "rgba(255,255,255,0.08)" : "rgba(255,255,255,0.16)"}
                    strokeWidth={1.5}
                    strokeDasharray={e.dashed ? "6 4" : undefined}
                    markerEnd="url(#ag-arrow)"
                  />
                  {e.label && (
                    <text
                      x={(x1 + x2) / 2}
                      y={my - 5}
                      textAnchor="middle"
                      fill="rgba(255,255,255,0.22)"
                      fontSize={8}
                      fontFamily="var(--font-mono)"
                    >
                      {e.label}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>

          {positioned.map((pn) => {
            const { node } = pn;
            const sevColor = node.severity === "critical" || node.severity === "high"
              ? "var(--severity-critical)"
              : node.severity === "medium" ? "var(--severity-medium)" : "var(--severity-low)";

            return (
              <div
                key={pn.id}
                className={`ag-card ag-${node.type}`}
                style={{
                  left: pn.x,
                  top: pn.y,
                  width: cardW,
                  minHeight: cardH,
                  borderColor: node.color,
                  "--nc": node.color,
                } as React.CSSProperties}
              >
                <div className="ag-card-head">
                  <span className="ag-card-icon">{NODE_ICON[node.type] || "\u25CF"}</span>
                  {node.sublabel && (
                    <span
                      className="ag-card-badge"
                      style={{
                        color: node.color,
                        background: `color-mix(in srgb, ${node.color} 12%, transparent)`,
                      }}
                    >
                      {node.sublabel}
                    </span>
                  )}
                </div>
                <div className="ag-card-title" title={node.label}>
                  {node.label}
                </div>
                {node.severity && (
                  <div className="ag-card-foot">
                    <span className="ag-sev-dot" style={{ background: sevColor }} />
                    <span className="ag-sev-label">{node.severity}</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
