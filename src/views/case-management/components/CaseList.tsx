import React from "react";
import { SeverityBadge } from "../../../shared/severity";
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
          <div
            key={c.id}
            className="animate-in"
            style={{ "--i": i } as React.CSSProperties}
          >
            <div
              role="button"
              tabIndex={0}
              className={`card sev-${sev} ${selectedId === c.id ? "selected" : ""}`}
              onClick={() => onSelect(c)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelect(c);
                }
              }}
            >
              <div className="case-list-title-row">
                <SeverityBadge severity={c.severity} />
                <span className="case-list-title" title={c.title}>
                  {c.title}
                </span>
                <span className={`case-status ${c.status}`}>{c.status.replace("-", " ")}</span>
              </div>
              <div className="case-list-meta-row">
                <span className="meta-item">
                  <span className="meta-label">Created</span>
                  <span className="meta-value">{timeAgo(c.created_at)}</span>
                </span>
                <span className="meta-item">
                  <span className="meta-label">Alerts</span>
                  <span className="meta-value">{c.totalAlerts}</span>
                </span>
                <span className="meta-item">
                  <span className="meta-label">Comments</span>
                  <span className="meta-value">{c.totalComment}</span>
                </span>
                {creator ? (
                  <span className="meta-item">
                    <span className="meta-label">Owner</span>
                    <span className="meta-value">{creator}</span>
                  </span>
                ) : null}
              </div>
              {c.tags.length > 0 ? (
                <div className="case-tags">
                  {c.tags.slice(0, 8).map((tag) => (
                    <span key={tag} className="case-tag">
                      {tag}
                    </span>
                  ))}
                  {c.tags.length > 8 ? (
                    <span className="case-tag">+{c.tags.length - 8}</span>
                  ) : null}
                </div>
              ) : null}
            </div>
          </div>
        );
      })}
    </div>
  );
}
