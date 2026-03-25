import React from "react";
import { SeverityBadge } from "../../../shared/severity";
import { GeneratedAvatar } from "../../../shared/avatar";
import type { KibanaCase } from "../../../shared/types";

interface CaseListProps {
  cases: KibanaCase[];
  selectedId?: string;
  onSelect: (c: KibanaCase) => void;
  timeAgo: (date: string | Date) => string;
}

function displayName(c: KibanaCase): string {
  const u = c.created_by;
  if (!u) return "";
  return (u.full_name || u.username || "").trim();
}

export function CaseList({ cases, selectedId, onSelect, timeAgo }: CaseListProps) {
  return (
    <div>
      {cases.map((c, i) => {
        const sev = (c.severity || "low").toLowerCase();
        const creator = displayName(c);
        return (
          <div key={c.id} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
            <div role="button" tabIndex={0}
              className={`card sev-${sev} ${selectedId === c.id ? "selected" : ""}`}
              onClick={() => onSelect(c)}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(c); } }}>
              <div className="case-list-title-row">
                <SeverityBadge severity={c.severity} />
                {c.incremental_id && (
                  <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-dim)", flexShrink: 0 }}>#{c.incremental_id}</span>
                )}
                <span className="case-list-title" title={c.title}>{c.title}</span>
                <span className={`case-status ${c.status}`}>{c.status.replace("-", " ")}</span>
              </div>
              <div className="case-list-meta-row">
                {creator && (
                  <span className="meta-item" style={{ gap: 5 }}>
                    <GeneratedAvatar name={creator} size={18} />
                    <span className="meta-value" style={{ fontSize: 11 }}>{creator}</span>
                  </span>
                )}
                <span className="meta-item">
                  <span className="meta-label">Created</span>
                  <span className="meta-value">{timeAgo(c.created_at)}</span>
                </span>
                {c.totalAlerts > 0 && (
                  <span className="meta-item">
                    <span className="meta-label">Alerts</span>
                    <span className="meta-value">{c.totalAlerts}</span>
                  </span>
                )}
                {c.totalComment > 0 && (
                  <span className="meta-item">
                    <span className="meta-label">Comments</span>
                    <span className="meta-value">{c.totalComment}</span>
                  </span>
                )}
              </div>
              {c.tags.length > 0 && (
                <div className="case-tags">
                  {c.tags.slice(0, 6).map((tag) => (
                    <span key={tag} className="case-tag">{tag}</span>
                  ))}
                  {c.tags.length > 6 && <span className="case-tag">+{c.tags.length - 6}</span>}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
