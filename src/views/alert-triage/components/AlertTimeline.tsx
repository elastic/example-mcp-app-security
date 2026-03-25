import React from "react";
import type { ProcessEvent } from "../../../shared/types";

interface AlertTimelineProps {
  events: ProcessEvent[];
}

export function AlertTimeline({ events }: AlertTimelineProps) {
  if (!events.length) {
    return <div className="empty-state">No process events in the investigation window.</div>;
  }

  const tree = buildProcessTree(events);

  return (
    <div className="process-tree">
      {tree.map((node, i) => (
        <ProcessNode key={i} node={node} depth={0} />
      ))}
    </div>
  );
}

interface TreeNode {
  event: ProcessEvent;
  children: TreeNode[];
}

function buildProcessTree(events: ProcessEvent[]): TreeNode[] {
  const byPid = new Map<number, TreeNode>();
  const roots: TreeNode[] = [];

  for (const event of events) {
    const pid = event.process?.pid;
    if (!pid) continue;

    const node: TreeNode = { event, children: [] };

    if (!byPid.has(pid)) {
      byPid.set(pid, node);
    }

    const parentPid = event.process?.parent?.pid;
    const parentNode = parentPid ? byPid.get(parentPid) : undefined;

    if (parentNode) {
      const alreadyChild = parentNode.children.some(
        (c) => c.event.process?.pid === pid
      );
      if (!alreadyChild) parentNode.children.push(node);
    } else {
      const alreadyRoot = roots.some((r) => r.event.process?.pid === pid);
      if (!alreadyRoot) roots.push(node);
    }
  }

  return roots.slice(0, 30);
}

function ProcessNode({ node, depth }: { node: TreeNode; depth: number }) {
  const ev = node.event;
  const ts = new Date(ev["@timestamp"]);

  return (
    <>
      <div className="process-node">
        <div className="process-indent">
          {Array.from({ length: depth }).map((_, i) => (
            <span key={i} className="branch">{i === depth - 1 ? "├─" : "│ "}</span>
          ))}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
            <span className="process-name">{ev.process?.name || "unknown"}</span>
            <span className="process-pid">PID {ev.process?.pid || "?"}</span>
            {ev.event?.action && (
              <span style={{ fontSize: 10, color: "var(--text-dim)", fontStyle: "italic" }}>{ev.event.action}</span>
            )}
          </div>
          {ev.process?.args && (
            <div className="process-args">{ev.process.args.join(" ")}</div>
          )}
        </div>
        <span className="process-time">
          {ts.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
        </span>
      </div>
      {node.children.map((child, i) => (
        <ProcessNode key={i} node={child} depth={depth + 1} />
      ))}
    </>
  );
}
