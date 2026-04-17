/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useMemo, useEffect, useCallback } from "react";
import { marked } from "marked";
import { SeverityBadge } from "../../../shared/severity";
import { GeneratedAvatar } from "../../../shared/avatar";
import { extractCallResult } from "../../../shared/extract-tool-text";
import { timeAgo } from "../../../shared/theme";
import type { KibanaCase } from "../../../shared/types";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";

interface CaseComment {
  id: string; type: string; comment?: string; created_at: string;
  created_by: { username?: string; full_name?: string; email?: string | null };
}

interface CaseAlert {
  id: string; index: string; attached_at: string;
  rule?: string; severity?: string; host?: string; user?: string; reason?: string;
}

interface Observable {
  id: string; typeKey: string; value: string; description?: string;
}

interface CaseDetailProps {
  caseData: KibanaCase;
  onUpdateStatus: (status: string) => void;
  onAddComment: (comment: string) => void;
  timeAgo: (date: string | Date) => string;
  app: McpApp;
}

function MetaCell({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="detail-meta-item">
      <span className="label">{label}</span>
      <span className="value">{children}</span>
    </div>
  );
}

function renderMarkdown(text: string): string {
  try { return marked.parse(text, { async: false, gfm: true, breaks: true }) as string; }
  catch { return text.replace(/\n/g, "<br>"); }
}

function displayName(user: { username?: string; full_name?: string; email?: string | null }): string {
  return user.full_name?.trim() || user.username?.trim() || user.email?.trim() || "Unknown";
}

function formatWhen(iso: string): string {
  if (!iso) return "\u2014";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toLocaleString()} \u00B7 ${timeAgo(iso)}`;
}

const OBSERVABLE_ICONS: Record<string, string> = {
  "observable-type-file-hash": "\u{1F510}",
  "observable-type-ipv4": "\u{1F310}",
  "observable-type-domain": "\u{1F517}",
  "observable-type-url": "\u{1F517}",
  "observable-type-file-name": "\u{1F4C4}",
};

export function CaseDetail({ caseData, onUpdateStatus, onAddComment, timeAgo: timeAgoFn, app }: CaseDetailProps) {
  const [tab, setTab] = useState<"overview" | "alerts" | "observables" | "comments">("overview");
  const [comment, setComment] = useState("");
  const [comments, setComments] = useState<CaseComment[]>([]);
  const [alerts, setAlerts] = useState<CaseAlert[]>([]);
  const [loadingAlerts, setLoadingAlerts] = useState(false);
  const [loadingComments, setLoadingComments] = useState(false);
  const sev = (caseData.severity || "low").toLowerCase();
  const descHtml = useMemo(() => renderMarkdown(caseData.description || ""), [caseData.description]);
  const observables = ((caseData as unknown as Record<string, unknown>).observables || []) as Observable[];

  const loadComments = useCallback(async () => {
    setLoadingComments(true);
    try {
      const result = await app.callServerTool({ name: "get-case-comments", arguments: { caseId: caseData.id } });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text) as { comments?: CaseComment[] };
        setComments((data.comments || []).filter(c => c.type === "user" && c.comment));
      }
    } catch { /* ignore */ }
    finally { setLoadingComments(false); }
  }, [app, caseData.id]);

  const loadAlerts = useCallback(async () => {
    setLoadingAlerts(true);
    try {
      const result = await app.callServerTool({ name: "get-case-alerts", arguments: { caseId: caseData.id } });
      const text = extractCallResult(result);
      if (text) setAlerts(JSON.parse(text));
    } catch { /* ignore */ }
    finally { setLoadingAlerts(false); }
  }, [app, caseData.id]);

  useEffect(() => { loadComments(); loadAlerts(); }, [loadComments, loadAlerts]);

  const handleAddComment = () => {
    const t = comment.trim();
    if (!t) return;
    onAddComment(t);
    setComment("");
    setTimeout(loadComments, 1000);
  };

  const owner = displayName(caseData.created_by || { username: "" });

  return (
    <div>
      {/* Header */}
      <div className={`detail-header-card sev-${sev}`}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 12, marginBottom: 14 }}>
          <GeneratedAvatar name={owner} size={38} />
          <div style={{ flex: 1 }}>
            <h2 className="detail-title" style={{ marginBottom: 3 }}>
              {caseData.incremental_id && <span style={{ color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontWeight: 400, marginRight: 8 }}>#{caseData.incremental_id}</span>}
              {caseData.title}
            </h2>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
              Created by <strong style={{ color: "var(--text-secondary)" }}>{owner}</strong> &middot; {timeAgoFn(caseData.created_at)}
            </div>
          </div>
        </div>

        <div className="detail-meta-grid">
          <MetaCell label="Status"><span className={`case-status ${caseData.status}`}>{caseData.status.replace("-", " ")}</span></MetaCell>
          <MetaCell label="Severity"><SeverityBadge severity={caseData.severity} /></MetaCell>
          <MetaCell label="Alerts">{caseData.totalAlerts}</MetaCell>
          <MetaCell label="Observables">{observables.length}</MetaCell>
          <MetaCell label="Created">{formatWhen(caseData.created_at)}</MetaCell>
          <MetaCell label="Updated">{formatWhen(caseData.updated_at)}</MetaCell>
        </div>

        {caseData.tags.length > 0 && (
          <div className="case-tags" style={{ marginTop: 12 }}>
            {caseData.tags.map((tag) => <span key={tag} className="case-tag">{tag}</span>)}
          </div>
        )}

        <div className="case-status-actions">
          {caseData.status === "open" && <button type="button" className="btn btn-primary" onClick={() => onUpdateStatus("in-progress")}>Start investigation</button>}
          {caseData.status === "in-progress" && (
            <>
              <button type="button" className="btn btn-primary" onClick={() => onUpdateStatus("closed")}>Close case</button>
              <button type="button" className="btn" onClick={() => onUpdateStatus("open")}>Mark open</button>
            </>
          )}
          {caseData.status === "closed" && <button type="button" className="btn btn-primary" onClick={() => onUpdateStatus("open")}>Reopen case</button>}
        </div>
      </div>

      {/* AI Actions */}
      <div style={{ display: "flex", gap: 6, marginBottom: 12, flexWrap: "wrap" }}>
        {[
          { label: "Summarize case", prompt: `Summarize security case #${caseData.incremental_id || ""} "${caseData.title}" — give me a concise executive summary of the current state, key findings, and what remains to be done.` },
          { label: "Suggest next steps", prompt: `For security case #${caseData.incremental_id || ""} "${caseData.title}" (status: ${caseData.status}, severity: ${caseData.severity}, ${caseData.totalAlerts} alerts) — what are the recommended next investigation steps? Be specific and actionable.` },
          { label: "Extract IOCs", prompt: `Extract all indicators of compromise (IOCs) from case #${caseData.incremental_id || ""} "${caseData.title}". Look at the description, tags, and observables. List each IOC with its type (hash, IP, domain, URL, filename) and context.` },
          { label: "Generate timeline", prompt: `Create a chronological investigation timeline for case #${caseData.incremental_id || ""} "${caseData.title}" based on the available data — alert timestamps, case creation, status changes, and any events mentioned.` },
        ].map((action) => (
          <button key={action.label} className="btn btn-sm" style={{ fontSize: 10, gap: 4 }}
            onClick={async () => {
              try {
                await app.sendMessage({ role: "user", content: [{ type: "text", text: action.prompt }] });
              } catch (e) { console.error("sendMessage failed:", e); }
            }}>
            <span style={{ fontSize: 12 }}>{action.label === "Summarize case" ? "\u2728" : action.label === "Suggest next steps" ? "\u27A1" : action.label === "Extract IOCs" ? "\u{1F50D}" : "\u{1F4C5}"}</span>
            {action.label}
          </button>
        ))}
      </div>

      {/* Tabs */}
      <div className="detail-tabs">
        <button className={`detail-tab ${tab === "overview" ? "active" : ""}`} onClick={() => setTab("overview")}>Overview</button>
        <button className={`detail-tab ${tab === "alerts" ? "active" : ""}`} onClick={() => setTab("alerts")}>
          Alerts<span className="tab-count">{caseData.totalAlerts}</span>
        </button>
        <button className={`detail-tab ${tab === "observables" ? "active" : ""}`} onClick={() => setTab("observables")}>
          Observables<span className="tab-count">{observables.length}</span>
        </button>
        <button className={`detail-tab ${tab === "comments" ? "active" : ""}`} onClick={() => setTab("comments")}>
          Comments<span className="tab-count">{comments.length}</span>
        </button>
      </div>

      {/* Tab content */}
      {tab === "overview" && (
        <div className="case-description markdown-body" dangerouslySetInnerHTML={{ __html: descHtml }} />
      )}

      {tab === "alerts" && (
        <div>
          {loadingAlerts ? (
            <div className="loading-state"><div className="loading-spinner" style={{ width: 16, height: 16 }} /> Loading alerts...</div>
          ) : alerts.length === 0 ? (
            <div className="empty-state" style={{ padding: 30 }}>No alerts attached to this case.</div>
          ) : (
            alerts.map((a) => (
              <div key={a.id} className={`card sev-${(a.severity || "low").toLowerCase()}`} style={{ cursor: "default" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  {a.severity && <SeverityBadge severity={a.severity} />}
                  <span style={{ fontWeight: 700, fontSize: 13, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {a.rule || "Unknown Rule"}
                  </span>
                  <span style={{ fontSize: 10, color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>{timeAgoFn(a.attached_at)}</span>
                </div>
                {a.reason && (
                  <div style={{ fontSize: 11, color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: 4 }}>
                    {a.reason}
                  </div>
                )}
                <div style={{ display: "flex", gap: 14, fontSize: 11 }}>
                  {a.host && <span className="meta-item"><span className="meta-label">Host</span><span className="meta-value">{a.host}</span></span>}
                  {a.user && <span className="meta-item"><span className="meta-label">User</span><span className="meta-value">{a.user}</span></span>}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {tab === "observables" && (
        <div>
          {observables.length === 0 ? (
            <div className="empty-state" style={{ padding: 30 }}>No observables in this case.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {observables.map((o) => {
                const icon = OBSERVABLE_ICONS[o.typeKey] || "\u{1F50D}";
                const typeLabel = o.typeKey.replace("observable-type-", "").replace(/-/g, " ");
                return (
                  <div key={o.id} style={{
                    display: "flex", alignItems: "center", gap: 10,
                    padding: "10px 14px", background: "var(--bg-secondary)",
                    border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-md)",
                  }}>
                    <span style={{ fontSize: 16 }}>{icon}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                        <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--accent)" }}>{typeLabel}</span>
                        {o.description && <span style={{ fontSize: 9, color: "var(--text-dim)" }}>{o.description}</span>}
                      </div>
                      <div style={{ fontSize: 12, fontFamily: "var(--font-mono)", color: "var(--text-primary)", wordBreak: "break-all" }}>{o.value}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {tab === "comments" && (
        <div>
          {loadingComments && comments.length === 0 && (
            <div className="loading-state" style={{ padding: 20 }}><div className="loading-spinner" style={{ width: 14, height: 14 }} /> Loading...</div>
          )}
          {comments.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
              {comments.map((c) => {
                const authorName = displayName(c.created_by || { username: "" });
                const commentHtml = renderMarkdown(c.comment || "");
                return (
                  <div key={c.id} style={{
                    display: "flex", gap: 10, padding: "12px 14px",
                    background: "var(--bg-primary)", borderRadius: "var(--radius-md)",
                    border: "1px solid var(--border-subtle)",
                  }}>
                    <GeneratedAvatar name={authorName} size={28} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 4 }}>
                        <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text-primary)" }}>{authorName}</span>
                        <span style={{ fontSize: 10, color: "var(--text-dim)" }}>{timeAgoFn(c.created_at)}</span>
                      </div>
                      <div className="markdown-body" style={{ fontSize: 12 }} dangerouslySetInnerHTML={{ __html: commentHtml }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start", padding: "12px 0" }}>
            <GeneratedAvatar name="You" size={28} />
            <div style={{ flex: 1 }}>
              <textarea className="comment-textarea"
                placeholder="Add investigation notes..."
                value={comment} onChange={(e) => setComment(e.target.value)} />
              <button type="button" className="btn btn-primary" onClick={handleAddComment} disabled={!comment.trim()}>Add comment</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
