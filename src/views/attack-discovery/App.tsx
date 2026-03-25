import React, { useState, useEffect, useCallback, useRef } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme, timeAgo } from "../../shared/theme";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import { RiskScore, SeverityBadge } from "../../shared/severity";
import type { AttackDiscoveryFinding, DiscoveryDetail } from "../../shared/types";
import { AttackFlowDiagram } from "./AttackFlowDiagram";
import "./styles.css";

interface Verdict {
  title: string;
  classification: string;
  confidence: string;
  summary: string;
  action: string;
}

const CONFIDENCE_LABELS: Record<string, string> = { high: "HIGH", moderate: "MOD", low: "LOW" };
const CONFIDENCE_CLASSES: Record<string, string> = { high: "confidence-high", moderate: "confidence-moderate", low: "confidence-low" };
const CARD_BORDER_CLASSES: Record<string, string> = { high: "conf-high", moderate: "conf-moderate", low: "conf-low" };

function ConfidenceBadge({ level }: { level: string }) {
  return (
    <span className={`confidence-badge ${CONFIDENCE_CLASSES[level] || "confidence-low"}`}>
      {CONFIDENCE_LABELS[level] || level.toUpperCase()}
    </span>
  );
}

function SearchIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
      <circle cx="11" cy="11" r="7" /><path d="m21 21-4.35-4.35" />
    </svg>
  );
}

const ENTITY_STYLES: Record<string, { icon: string; color: string; label: string }> = {
  host: { icon: "\uD83D\uDDA5\uFE0F", color: "#40c790", label: "HOST" },
  user: { icon: "\uD83D\uDC64", color: "#5c7cfa", label: "USER" },
  process: { icon: "\u2699\uFE0F", color: "#b07cfa", label: "PROCESS" },
  file: { icon: "\uD83D\uDCC4", color: "#da8b45", label: "FILE" },
};

interface EntityRef { field: string; type: string; value: string }
interface FlyoutState { type: string; value: string; x: number; y: number }

function parseSummary(text: string): (string | EntityRef)[] {
  const re = /\{\{\s*([\w.]+)\s+(.+?)\s*\}\}/g;
  const parts: (string | EntityRef)[] = [];
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    parts.push({ field: m[1], type: m[1].split(".")[0], value: m[2] });
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

function SummaryContent({ text, onEntity }: {
  text: string;
  onEntity: (type: string, value: string, x: number, y: number) => void;
}) {
  const parts = parseSummary(text.replace(/[#*_`]/g, ""));
  return (
    <span>
      {parts.map((p, i) => {
        if (typeof p === "string") return <span key={i}>{p}</span>;
        const cfg = ENTITY_STYLES[p.type] || ENTITY_STYLES.host;
        return (
          <span
            key={i}
            className="entity-badge"
            style={{ "--ec": cfg.color } as React.CSSProperties}
            onClick={(e) => {
              e.stopPropagation();
              const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
              onEntity(p.type, p.value, r.left, r.bottom + 6);
            }}
          >
            <span className="eb-icon">{cfg.icon}</span>
            <span className="eb-label">{cfg.label}</span>
            <span className="eb-value">{p.value}</span>
          </span>
        );
      })}
    </span>
  );
}

function EntityFlyout({ state, detail, onClose }: {
  state: FlyoutState;
  detail: DiscoveryDetail | null;
  onClose: () => void;
}) {
  const cfg = ENTITY_STYLES[state.type] || ENTITY_STYLES.host;
  const risk = detail?.entityRisk?.find((er) => er.name === state.value);
  const alerts = detail?.alerts?.filter((a) =>
    (state.type === "host" && a.host === state.value) ||
    (state.type === "user" && a.user === state.value)
  ) || [];

  return (
    <div
      className="entity-flyout"
      style={{ top: Math.min(state.y, window.innerHeight - 320), left: Math.min(state.x, window.innerWidth - 290) }}
      onClick={(e) => e.stopPropagation()}
    >
      <div className="ef-header">
        <span className="ef-icon" style={{ background: `color-mix(in srgb, ${cfg.color} 12%, transparent)`, color: cfg.color }}>
          {cfg.icon}
        </span>
        <div className="ef-identity">
          <span className="ef-type" style={{ color: cfg.color }}>{cfg.label}</span>
          <span className="ef-name">{state.value}</span>
        </div>
        <button className="ef-close" onClick={onClose}>{"\u2715"}</button>
      </div>

      {risk && risk.level.toLowerCase() !== "unknown" ? (
        <div className="ef-risk">
          <div className="ef-risk-bar">
            <div
              className="ef-risk-fill"
              style={{
                width: `${Math.min(risk.score, 100)}%`,
                background: risk.level === "critical" ? "var(--severity-critical)"
                  : risk.level === "high" ? "var(--severity-high)"
                  : "var(--severity-medium)",
              }}
            />
          </div>
          <span className="ef-risk-label">{risk.score.toFixed(0)}</span>
          <span className="ef-risk-level">{risk.level}</span>
        </div>
      ) : (
        <div className="ef-unscored">Risk engine not enabled for this entity</div>
      )}

      {alerts.length > 0 && (
        <div className="ef-alerts">
          <div className="ef-section-title">{alerts.length} Related Alert{alerts.length !== 1 ? "s" : ""}</div>
          {alerts.slice(0, 5).map((a, i) => (
            <div key={i} className="ef-alert-row">
              <SeverityBadge severity={a.severity} compact />
              <span className="ef-alert-name">{a.ruleName}</span>
            </div>
          ))}
          {alerts.length > 5 && (
            <div className="ef-more">+{alerts.length - 5} more</div>
          )}
        </div>
      )}

      {alerts.length === 0 && (
        <div className="ef-empty">No related alerts found</div>
      )}
    </div>
  );
}

export function App() {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  const [discoveries, setDiscoveries] = useState<AttackDiscoveryFinding[]>([]);
  const [selected, setSelected] = useState<AttackDiscoveryFinding | null>(null);
  const [detail, setDetail] = useState<DiscoveryDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [verdicts, setVerdicts] = useState<Verdict[]>([]);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [actionResult, setActionResult] = useState<string | null>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [tab, setTab] = useState<"summary" | "flow" | "alerts" | "entities" | "signals">("summary");
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [flyout, setFlyout] = useState<FlyoutState | null>(null);
  const [expandedAlerts, setExpandedAlerts] = useState<Set<string>>(new Set());
  const paramsRef = useRef<{ days: number; limit: number }>({ days: 1, limit: 50 });

  const loadDiscoveries = useCallback(async (app?: McpApp) => {
    const mcpApp = app || appRef.current;
    if (!mcpApp) return;
    setLoading(true);
    try {
      const result = await mcpApp.callServerTool({ name: "poll-discoveries", arguments: paramsRef.current });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text);
        if (data.discoveries) {
          setDiscoveries(data.discoveries.map((d: Record<string, unknown>) => ({
            ...d,
            alertCount: (d.alertIds as string[])?.length || d.alertCount || 0,
          })));
          assessConfidence(mcpApp, data.discoveries);
        }
      }
    } catch (e) {
      console.error("Load discoveries failed:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  const assessConfidence = useCallback(async (app: McpApp, discs: AttackDiscoveryFinding[]) => {
    try {
      const result = await app.callServerTool({
        name: "assess-discovery-confidence",
        arguments: { discoveries: JSON.stringify(discs) },
      });
      const text = extractCallResult(result);
      if (text) {
        const triaged: AttackDiscoveryFinding[] = JSON.parse(text);
        setDiscoveries(triaged.map((d) => ({
          ...d,
          alertCount: d.alertIds?.length || d.alertCount || 0,
        })));
      }
    } catch (e) {
      console.error("Confidence assessment failed:", e);
    }
  }, []);

  const loadDetail = useCallback(async (discovery: AttackDiscoveryFinding) => {
    const mcpApp = appRef.current;
    if (!mcpApp) return;
    setDetailLoading(true);
    setDetail(null);
    try {
      const result = await mcpApp.callServerTool({
        name: "enrich-discovery",
        arguments: { discovery: JSON.stringify(discovery) },
      });
      const text = extractCallResult(result);
      if (text) {
        setDetail(JSON.parse(text));
      }
    } catch (e) {
      console.error("Enrich failed:", e);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const handleApprove = useCallback(async () => {
    const mcpApp = appRef.current;
    if (!mcpApp || checked.size === 0) return;
    const findings = discoveries.filter((d) => checked.has(d.id));
    try {
      const result = await mcpApp.callServerTool({
        name: "approve-discoveries",
        arguments: { findings },
      });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text);
        setActionResult(`Created ${data.created} case(s)`);
        setTimeout(() => setActionResult(null), 5000);
      }
    } catch (e) {
      console.error("Approve failed:", e);
    }
  }, [checked, discoveries]);

  const handleAcknowledge = useCallback(async () => {
    const mcpApp = appRef.current;
    if (!mcpApp || checked.size === 0) return;
    const ids = [...checked];
    try {
      const result = await mcpApp.callServerTool({
        name: "acknowledge-discoveries",
        arguments: { discoveryIds: ids },
      });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text);
        setActionResult(`Acknowledged ${data.updated} discovery(ies)`);
        setDiscoveries((prev) => prev.filter((d) => !checked.has(d.id)));
        setChecked(new Set());
        setTimeout(() => setActionResult(null), 5000);
      }
    } catch (e) {
      console.error("Acknowledge failed:", e);
    }
  }, [checked]);

  useEffect(() => {
    const app = new McpApp({ name: "attack-discovery-triage", version: "0.1.0" });
    appRef.current = app;
    applyTheme(app);

    let gotResult = false;

    app.ontoolresult = (result) => {
      gotResult = true;
      try {
        const text = extractToolText(result);
        if (text) {
          const data = JSON.parse(text);
          if (data.params) {
            paramsRef.current = { days: data.params.days || 1, limit: data.params.limit || 50 };
          }
          if (Array.isArray(data.verdicts)) setVerdicts(data.verdicts);
          if (Array.isArray(data.discoveries)) {
            setDiscoveries(data.discoveries.map((d: Record<string, unknown>) => ({
              ...d,
              alertCount: (d.alertIds as string[])?.length || d.alertCount || 0,
            })));
            setLoading(false);
          }
        }
      } catch { /* ignore */ }
    };

    app.connect().then(() => {
      setConnected(true);
      setTimeout(() => { if (!gotResult) loadDiscoveries(app); }, 1500);
    });

    return () => { appRef.current = null; };
  }, [loadDiscoveries]);

  useEffect(() => {
    if (!flyout) return;
    const close = () => setFlyout(null);
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, [flyout]);

  const openFlyout = useCallback((type: string, value: string, x: number, y: number) => {
    setFlyout({ type, value, x, y });
  }, []);

  const filtered = searchFilter
    ? discoveries.filter((d) =>
        d.title.toLowerCase().includes(searchFilter.toLowerCase()) ||
        d.mitreTactics?.some((t) => t.toLowerCase().includes(searchFilter.toLowerCase())) ||
        d.hosts?.some((h) => h.toLowerCase().includes(searchFilter.toLowerCase())) ||
        d.users?.some((u) => u.toLowerCase().includes(searchFilter.toLowerCase()))
      )
    : discoveries;

  const byConfidence = {
    high: filtered.filter((d) => d.confidence === "high").length,
    moderate: filtered.filter((d) => d.confidence === "moderate").length,
    low: filtered.filter((d) => d.confidence === "low").length,
  };

  const toggleCheck = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (checked.size === filtered.length) setChecked(new Set());
    else setChecked(new Set(filtered.map((d) => d.id)));
  };

  const riskSeverity = (score: number): string =>
    score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : "low";

  const entityRiskColor = (level: string): string => {
    const l = level.toLowerCase();
    if (l === "critical") return "var(--severity-critical)";
    if (l === "high") return "var(--severity-high)";
    if (l === "moderate") return "var(--severity-medium)";
    if (l === "unknown") return "var(--text-dim)";
    return "var(--severity-low)";
  };

  return (
    <div className="app-layout">
      {/* Filter bar */}
      <div className="filter-bar">
        <span className="filter-bar-title">Attack Discovery</span>
        <span className="filter-bar-count">{filtered.length} finding{filtered.length !== 1 ? "s" : ""}</span>

        {byConfidence.high > 0 && (
          <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <ConfidenceBadge level="high" />
            <span style={{ fontSize: 11, fontWeight: 700, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>{byConfidence.high}</span>
          </span>
        )}
        {byConfidence.moderate > 0 && (
          <span style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <ConfidenceBadge level="moderate" />
            <span style={{ fontSize: 11, fontWeight: 700, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>{byConfidence.moderate}</span>
          </span>
        )}

        <div className="filter-bar-search" style={{ marginLeft: "auto" }}>
          <SearchIcon />
          <input
            placeholder="Filter findings..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
          />
        </div>
        <button className="btn btn-sm btn-ghost" style={{ flexShrink: 0 }} onClick={() => {
          const next = !isFullscreen;
          try { appRef.current?.requestDisplayMode({ mode: next ? "fullscreen" : "inline" }); } catch {}
          setIsFullscreen(next);
        }} title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}>
          {isFullscreen ? "\u2715" : "\u26F6"}
        </button>
      </div>

      {/* Verdicts */}
      {verdicts.length > 0 && !selected && (
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border-subtle)", background: "var(--bg-secondary)" }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.6px", color: "var(--text-dim)", marginBottom: 8 }}>
            AI Verdicts
          </div>
          {verdicts.map((v, i) => (
            <div key={i} className={`verdict-card ${v.classification}`}>
              <div className="verdict-card-header">
                <span className="verdict-card-title">{v.title}</span>
                <span className={`confidence-badge ${v.classification === "malicious" ? "confidence-high" : v.classification === "suspicious" ? "confidence-moderate" : "confidence-low"}`}>
                  {v.classification.toUpperCase()}
                </span>
              </div>
              <div className="verdict-card-body">{v.summary}</div>
              <div className="verdict-card-action">{v.action}</div>
            </div>
          ))}
        </div>
      )}

      {/* Main body */}
      <div className="app-body">
        {/* Discovery list */}
        <div className={`list-pane ${selected ? "narrow" : ""}`}>
          {loading ? (
            <div className="loading-state">
              <div className="loading-spinner" />
              <span>Loading attack discoveries...</span>
            </div>
          ) : filtered.length === 0 ? (
            <div className="empty-state">
              <div style={{ fontSize: 28, marginBottom: 8 }}>&#128737;</div>
              <div>No open attack discoveries found</div>
              <div style={{ fontSize: 12, marginTop: 4 }}>Try adjusting the time range</div>
            </div>
          ) : (
            filtered.map((d, i) => (
              <div
                key={d.id}
                className={`discovery-card ${selected?.id === d.id ? "selected" : ""} ${CARD_BORDER_CLASSES[d.confidence || ""] || ""} ${selected ? "compact" : ""} animate-in`}
                style={{ "--i": i } as React.CSSProperties}
                onClick={() => {
                  setSelected(d);
                  setTab("summary");
                  setDetail(null);
                  setExpandedAlerts(new Set());
                  loadDetail(d);
                }}
              >
                <div className="discovery-card-row1">
                  <div
                    className={`discovery-card-check ${checked.has(d.id) ? "checked" : ""}`}
                    onClick={(e) => toggleCheck(d.id, e)}
                  >
                    {checked.has(d.id) && <span style={{ fontSize: 10 }}>&#10003;</span>}
                  </div>
                  <span className="discovery-card-title">{d.title}</span>
                  {d.confidence && <ConfidenceBadge level={d.confidence} />}
                  <RiskScore score={d.riskScore} />
                  <span className="discovery-card-time">{timeAgo(d.timestamp)}</span>
                </div>

                {!selected && (
                  <div className="discovery-card-summary">{d.summaryMarkdown?.replace(/[#*_`]/g, "")}</div>
                )}

                <div className="discovery-card-meta">
                  <span className="meta-item">
                    <span className="meta-label">Alerts</span>
                    <span className="meta-value">{d.alertCount || d.alertIds?.length || 0}</span>
                  </span>
                  {d.hosts && d.hosts.length > 0 && (
                    <span className="meta-item">
                      <span className="meta-label">Hosts</span>
                      <span className="meta-value">{d.hosts.join(", ")}</span>
                    </span>
                  )}
                  {d.users && d.users.length > 0 && (
                    <span className="meta-item">
                      <span className="meta-label">Users</span>
                      <span className="meta-value">{d.users.join(", ")}</span>
                    </span>
                  )}
                </div>

                {!selected && d.mitreTactics && d.mitreTactics.length > 0 && (
                  <div className="discovery-card-tactics">
                    {d.mitreTactics.map((t) => (
                      <span key={t} className="mitre-tag mitre-tactic">{t}</span>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Detail pane */}
        {selected && (
          <div className="detail-pane">
            <button className="back-btn" onClick={() => { setSelected(null); setDetail(null); }}>
              &#8592; Back to list
            </button>

            <div className={`detail-header-card sev-${riskSeverity(selected.riskScore)}`}>
              <div className="detail-title">
                <SummaryContent
                  text={detail?.titleWithReplacements || selected.title}
                  onEntity={openFlyout}
                />
              </div>
              <div className="detail-desc">
                <SummaryContent
                  text={detail?.summaryWithReplacements || selected.summaryMarkdown || ""}
                  onEntity={openFlyout}
                />
              </div>
              <div className="detail-meta-grid">
                <div className="detail-meta-item">
                  <span className="label">Risk Score</span>
                  <span className="value"><RiskScore score={selected.riskScore} /></span>
                </div>
                <div className="detail-meta-item">
                  <span className="label">Confidence</span>
                  <span className="value">{selected.confidence ? <ConfidenceBadge level={selected.confidence} /> : "—"}</span>
                </div>
                <div className="detail-meta-item">
                  <span className="label">Alerts</span>
                  <span className="value">{selected.alertCount || selected.alertIds?.length || 0}</span>
                </div>
                <div className="detail-meta-item">
                  <span className="label">Timestamp</span>
                  <span className="value">{timeAgo(selected.timestamp)}</span>
                </div>
                {selected.hosts && selected.hosts.length > 0 && (
                  <div className="detail-meta-item">
                    <span className="label">Hosts</span>
                    <span className="value">{selected.hosts.join(", ")}</span>
                  </div>
                )}
                {selected.users && selected.users.length > 0 && (
                  <div className="detail-meta-item">
                    <span className="label">Users</span>
                    <span className="value">{selected.users.join(", ")}</span>
                  </div>
                )}
              </div>
            </div>

            {selected.mitreTactics && selected.mitreTactics.length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 16 }}>
                {selected.mitreTactics.map((t) => (
                  <span key={t} className="mitre-tag mitre-tactic">{t}</span>
                ))}
              </div>
            )}

            {/* Tabs */}
            <div className="detail-tabs">
              <button className={`detail-tab ${tab === "summary" ? "active" : ""}`} onClick={() => setTab("summary")}>
                Summary
              </button>
              {selected.mitreTactics && selected.mitreTactics.length > 0 && (
                <button className={`detail-tab ${tab === "flow" ? "active" : ""}`} onClick={() => setTab("flow")}>
                  Attack Flow
                  <span className="tab-count">{selected.mitreTactics.length}</span>
                </button>
              )}
              <button className={`detail-tab ${tab === "alerts" ? "active" : ""}`} onClick={() => setTab("alerts")}>
                Alerts
                <span className="tab-count">{detail?.alerts?.length || "..."}</span>
              </button>
              <button className={`detail-tab ${tab === "entities" ? "active" : ""}`} onClick={() => setTab("entities")}>
                Entity Risk
                <span className="tab-count">{detail?.entityRisk?.length || "..."}</span>
              </button>
              {selected.signals && (
                <button className={`detail-tab ${tab === "signals" ? "active" : ""}`} onClick={() => setTab("signals")}>
                  Confidence Signals
                </button>
              )}
            </div>

            {detailLoading && (
              <div className="loading-state" style={{ padding: "30px 20px" }}>
                <div className="loading-spinner" />
                <span>Enriching finding...</span>
              </div>
            )}

            {/* Summary tab */}
            {tab === "summary" && !detailLoading && (
              <div>
                {!(detail?.detailsWithReplacements || selected.detailsMarkdown) && (
                  <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.85 }}>
                    <SummaryContent
                      text={detail?.summaryWithReplacements || selected.summaryMarkdown || ""}
                      onEntity={openFlyout}
                    />
                  </div>
                )}
                {(detail?.detailsWithReplacements || selected.detailsMarkdown) && (
                  <div className="details-timeline">
                    <div className="details-timeline-title">Attack Chain</div>
                    {(detail?.detailsWithReplacements || selected.detailsMarkdown || "")
                      .split(/\n/)
                      .filter((line) => line.trim())
                      .map((line, i) => {
                        const cleaned = line.replace(/^[-*•]\s*/, "").trim();
                        if (!cleaned) return null;
                        return (
                          <div key={i} className="details-timeline-item">
                            <div className="details-timeline-dot" />
                            <div className="details-timeline-text">
                              <SummaryContent text={cleaned} onEntity={openFlyout} />
                            </div>
                          </div>
                        );
                      })}
                  </div>
                )}
              </div>
            )}

            {/* Attack Flow tab */}
            {tab === "flow" && selected.mitreTactics && selected.mitreTactics.length > 0 && (
              <AttackFlowDiagram discovery={selected} detail={detail} />
            )}

            {/* Alerts tab */}
            {tab === "alerts" && !detailLoading && detail?.alerts && (
              <div>
                {detail.alerts.map((a) => {
                  const isExpanded = expandedAlerts.has(a.id);
                  const toggle = () => setExpandedAlerts((prev) => {
                    const next = new Set(prev);
                    next.has(a.id) ? next.delete(a.id) : next.add(a.id);
                    return next;
                  });
                  const details = a.details || {};
                  const FIELD_LABELS: Record<string, string> = {
                    "host.name": "host.name", "user.name": "user.name",
                    "process.name": "process.name", "process.executable": "process.executable",
                    "file.name": "file.name", "file.path": "file.path",
                    "source.ip": "source.ip", "destination.ip": "destination.ip",
                    "rule.description": "rule.description", "risk_score": "risk_score",
                    "reason": "reason",
                  };
                  const FIELD_ORDER = ["host.name", "user.name", "rule.description", "process.name", "process.executable", "file.name", "file.path", "source.ip", "destination.ip", "risk_score", "reason"];
                  return (
                    <div key={a.id} className={`alert-expandable ${isExpanded ? "expanded" : ""}`}>
                      <div className="alert-row" onClick={toggle} style={{ cursor: "pointer" }}>
                        <span className={`alert-chevron ${isExpanded ? "open" : ""}`}>&#9656;</span>
                        <SeverityBadge severity={a.severity} compact />
                        <span className="alert-row-rule">{a.ruleName}</span>
                        <span className="alert-row-host">{a.host}</span>
                        <span className="alert-row-time">{timeAgo(a.timestamp)}</span>
                      </div>
                      {isExpanded && (
                        <div className="alert-detail-table">
                          <div className="alert-detail-field">
                            <span className="adf-label">Source event</span>
                            <span className="adf-value adf-mono">{a.id}</span>
                          </div>
                          {FIELD_ORDER.filter((f) => details[f]).map((f) => (
                            <div key={f} className="alert-detail-field">
                              <span className="adf-label">{FIELD_LABELS[f] || f}</span>
                              <span className={`adf-value ${["process.executable", "file.path", "file.name", "source.ip", "destination.ip"].includes(f) ? "adf-mono" : ""}`}>
                                {(f === "host.name" || f === "user.name") ? (
                                  <span
                                    className={`entity-badge ${f === "host.name" ? "host" : "user"}`}
                                    onClick={(e) => { e.stopPropagation(); openFlyout(f === "host.name" ? "host" : "user", details[f], e.clientX, e.clientY); }}
                                  >
                                    {f === "host.name" ? "\uD83D\uDDA5\uFE0F" : "\uD83D\uDC64"} {details[f]}
                                  </span>
                                ) : details[f]}
                              </span>
                            </div>
                          ))}
                          <div className="alert-detail-field">
                            <span className="adf-label">@timestamp</span>
                            <span className="adf-value">{a.timestamp}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
                {detail.alerts.length === 0 && (
                  <div className="empty-state" style={{ padding: "30px" }}>No alerts loaded</div>
                )}
              </div>
            )}

            {/* Entities tab */}
            {tab === "entities" && !detailLoading && detail?.entityRisk && (
              <div>
                {detail.entityRisk.map((er) => {
                  const scored = er.level.toLowerCase() !== "unknown";
                  const color = entityRiskColor(er.level);
                  return (
                    <div
                      key={`${er.type}:${er.name}`}
                      className="entity-risk-row"
                      style={{ cursor: "pointer" }}
                      onClick={(e) => openFlyout(er.type, er.name, e.clientX, e.clientY)}
                    >
                      <div className={`entity-risk-icon ${er.type}`}>
                        {er.type === "host" ? "\uD83D\uDDA5\uFE0F" : "\uD83D\uDC64"}
                      </div>
                      <span className="entity-risk-name">{er.name}</span>
                      {scored ? (
                        <>
                          <span
                            className="entity-risk-level"
                            style={{
                              color,
                              background: `color-mix(in srgb, ${color} 10%, transparent)`,
                              border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
                            }}
                          >
                            {er.level}
                          </span>
                          <span className="entity-risk-score" style={{ color }}>
                            {er.score.toFixed(0)}
                          </span>
                        </>
                      ) : (
                        <span className="entity-risk-unscored">Risk engine not enabled</span>
                      )}
                    </div>
                  );
                })}
                {detail.entityRisk.length === 0 && (
                  <div className="empty-state" style={{ padding: "30px" }}>No entity risk data available</div>
                )}
              </div>
            )}

            {/* Signals tab */}
            {tab === "signals" && selected.signals && (
              <div>
                <div className="signals-grid">
                  <div className="signal-card">
                    <div className="signal-card-header">
                      <span className="signal-card-title">Alert Diversity</span>
                    </div>
                    <div className="signal-card-value">{selected.signals.alertDiversity.alertCount}</div>
                    <div className="signal-card-detail">
                      {selected.signals.alertDiversity.ruleCount} rule{selected.signals.alertDiversity.ruleCount !== 1 ? "s" : ""}
                      {" "}&#183;{" "}
                      {selected.signals.alertDiversity.severities.join(", ") || "—"}
                    </div>
                  </div>
                  <div className="signal-card">
                    <div className="signal-card-header">
                      <span className="signal-card-title">Rule Noise</span>
                    </div>
                    <div className="signal-card-value">
                      {selected.signals.ruleFrequency.length} rule{selected.signals.ruleFrequency.length !== 1 ? "s" : ""}
                    </div>
                    <div className="signal-card-detail">
                      {selected.signals.ruleFrequency.map((rf) => (
                        <div key={rf.ruleName} style={{ marginBottom: 2 }}>
                          <span style={{ color: "var(--text-primary)" }}>{rf.ruleName}</span>
                          {" "}&#8212;{" "}
                          {rf.totalAlerts7d} alerts / {rf.hostCount} hosts
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="signal-card">
                    <div className="signal-card-header">
                      <span className="signal-card-title">Entity Risk</span>
                    </div>
                    <div className="signal-card-value">
                      {selected.signals.entityRisk.length} entit{selected.signals.entityRisk.length !== 1 ? "ies" : "y"}
                    </div>
                    <div className="signal-card-detail">
                      {selected.signals.entityRisk.map((er) => (
                        <div key={`${er.type}:${er.name}`} style={{ marginBottom: 2 }}>
                          <span style={{ color: entityRiskColor(er.riskLevel) }}>{er.riskLevel}</span>
                          {" "}&#8212;{" "}
                          {er.name} ({er.type})
                        </div>
                      ))}
                      {selected.signals.entityRisk.length === 0 && "No risk data"}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Action bar */}
      {flyout && <EntityFlyout state={flyout} detail={detail} onClose={() => setFlyout(null)} />}

      {checked.size > 0 && (
        <div className="action-bar">
          <button className="btn btn-sm btn-ghost" onClick={selectAll}>
            {checked.size === filtered.length ? "Deselect All" : "Select All"}
          </button>
          <span className="action-bar-count">{checked.size} selected</span>
          {actionResult && (
            <span style={{ fontSize: 12, color: "var(--success)", fontWeight: 600 }}>
              &#10003; {actionResult}
            </span>
          )}
          <button className="btn btn-sm" onClick={handleAcknowledge}>
            Acknowledge
          </button>
          <button className="btn btn-sm btn-success" onClick={handleApprove}>
            Create Cases
          </button>
        </div>
      )}
    </div>
  );
}
