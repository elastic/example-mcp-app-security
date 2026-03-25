import React, { useState } from "react";
import { SeverityBadge } from "../../../shared/severity";
import type { KibanaCase } from "../../../shared/types";

interface CaseDetailProps {
  caseData: KibanaCase;
  onUpdateStatus: (status: string) => void;
  onAddComment: (comment: string) => void;
  timeAgo: (date: string | Date) => string;
}

function MetaCell({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="detail-meta-item">
      <span className="label">{label}</span>
      <span className="value">{children}</span>
    </div>
  );
}

function formatWhen(iso: string, relative: (d: string | Date) => string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toLocaleString()} · ${relative(iso)}`;
}

export function CaseDetail({ caseData, onUpdateStatus, onAddComment, timeAgo }: CaseDetailProps) {
  const [comment, setComment] = useState("");
  const sev = (caseData.severity || "low").toLowerCase();

  const handleAddComment = () => {
    const t = comment.trim();
    if (!t) return;
    onAddComment(t);
    setComment("");
  };

  const owner =
    caseData.created_by?.full_name?.trim() ||
    caseData.created_by?.username?.trim() ||
    "—";

  return (
    <div>
      <div className={`detail-header-card sev-${sev}`}>
        <h2 className="detail-title">{caseData.title}</h2>

        <div className="detail-meta-grid">
          <MetaCell label="Status">
            <span className={`case-status ${caseData.status}`}>
              {caseData.status.replace("-", " ")}
            </span>
          </MetaCell>
          <MetaCell label="Severity">
            <SeverityBadge severity={caseData.severity} />
          </MetaCell>
          <MetaCell label="Created">{formatWhen(caseData.created_at, timeAgo)}</MetaCell>
          <MetaCell label="Updated">{formatWhen(caseData.updated_at, timeAgo)}</MetaCell>
          <MetaCell label="Alerts">{caseData.totalAlerts}</MetaCell>
          <MetaCell label="Comments">{caseData.totalComment}</MetaCell>
          <MetaCell label="Created by">{owner}</MetaCell>
        </div>

        {caseData.tags.length > 0 ? (
          <div className="case-tags" style={{ marginTop: 14 }}>
            {caseData.tags.map((tag) => (
              <span key={tag} className="case-tag">
                {tag}
              </span>
            ))}
          </div>
        ) : null}

        <div className="case-description">{caseData.description || "No description."}</div>

        <div className="case-status-actions">
          {caseData.status === "open" ? (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => onUpdateStatus("in-progress")}
            >
              Start investigation
            </button>
          ) : null}
          {caseData.status === "in-progress" ? (
            <>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => onUpdateStatus("closed")}
              >
                Close case
              </button>
              <button type="button" className="btn" onClick={() => onUpdateStatus("open")}>
                Mark open
              </button>
            </>
          ) : null}
          {caseData.status === "closed" ? (
            <button type="button" className="btn btn-primary" onClick={() => onUpdateStatus("open")}>
              Reopen case
            </button>
          ) : null}
        </div>
      </div>

      <div className="comment-thread">
        <div className="comment-thread-label">Add comment</div>
        <textarea
          placeholder="Investigation notes, handoff context, or timeline updates…"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />
        <button
          type="button"
          className="btn btn-primary"
          onClick={handleAddComment}
          disabled={!comment.trim()}
        >
          Add comment
        </button>
      </div>
    </div>
  );
}
