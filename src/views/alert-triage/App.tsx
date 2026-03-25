import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme, timeAgo } from "../../shared/theme";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import { SeverityBadge, SeverityDot, severityColor } from "../../shared/severity";
import type { SecurityAlert, AlertSummary, AlertContext } from "../../shared/types";
import { AlertCard } from "./components/AlertCard";
import { AlertTimeline } from "./components/AlertTimeline";
import { ThreatClassifier } from "./components/ThreatClassifier";
import { InvestigationPanel } from "./components/InvestigationPanel";
import "./styles.css";

interface FilterParams {
  days: number;
  severity?: string;
  limit: number;
  query?: string;
}

const SearchIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <circle cx="11" cy="11" r="7" /><path d="m21 21-4.35-4.35" />
  </svg>
);

export function App() {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [alertContext, setAlertContext] = useState<AlertContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [contextLoading, setContextLoading] = useState(false);
  const [searchInput, setSearchInput] = useState("");
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [verdicts, setVerdicts] = useState<Array<{rule: string; classification: string; confidence: string; summary: string; action: string; hosts?: string[]}>>([]);
  const paramsRef = useRef<FilterParams>({ days: 7, limit: 50 });

  const loadAlerts = useCallback(async (app?: McpApp, overrideParams?: Partial<FilterParams>) => {
    const mcpApp = app || appRef.current;
    if (!mcpApp) return;
    setLoading(true);
    try {
      const args = { ...paramsRef.current, ...overrideParams };
      if (overrideParams) paramsRef.current = { ...paramsRef.current, ...overrideParams };
      const result = await mcpApp.callServerTool({ name: "poll-alerts", arguments: args });
      const text = extractCallResult(result);
      if (text) setSummary(JSON.parse(text));
    } catch (e) {
      console.error("Load alerts failed:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const app = new McpApp({ name: "alert-triage", version: "0.1.0" });
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
            paramsRef.current = {
              days: data.params.days || 7,
              severity: data.params.severity,
              limit: data.params.limit || 50,
              query: data.params.query,
            };
            if (data.params.query) setSearchInput(data.params.query);
          }
          if (Array.isArray(data.verdicts)) setVerdicts(data.verdicts);
        }
      } catch { /* ignore */ }
      loadAlerts(app);
    };

    app.connect().then(() => {
      setConnected(true);
      setTimeout(() => { if (!gotResult) loadAlerts(app); }, 1500);
    });

    return () => { app.close(); };
  }, [loadAlerts]);

  useEffect(() => {
    if (!connected) return;
    const interval = setInterval(() => loadAlerts(), 60000);
    return () => clearInterval(interval);
  }, [connected, loadAlerts]);

  const selectAlert = useCallback(async (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setAlertContext(null);
    setContextLoading(true);
    if (!appRef.current) return;
    try {
      const result = await appRef.current.callServerTool({
        name: "get-alert-context",
        arguments: { alertId: alert._id, alert: JSON.stringify(alert) },
      });
      const text = extractCallResult(result);
      if (text) setAlertContext(JSON.parse(text));
    } catch { /* optional */ }
    finally { setContextLoading(false); }
  }, []);

  const acknowledgeAlert = useCallback(async (alertId: string) => {
    if (!appRef.current) return;
    try {
      await appRef.current.callServerTool({ name: "acknowledge-alert", arguments: { alertId } });
      setSummary((prev) => prev ? { ...prev, total: prev.total - 1, alerts: prev.alerts.filter((a) => a._id !== alertId) } : prev);
      if (selectedAlert?._id === alertId) setSelectedAlert(null);
    } catch { /* ignore */ }
  }, [selectedAlert]);

  const handleSearch = useCallback((q: string) => {
    loadAlerts(undefined, { query: q.trim() || undefined });
  }, [loadAlerts]);

  const clearQuery = useCallback(() => {
    setSearchInput("");
    loadAlerts(undefined, { query: undefined });
  }, [loadAlerts]);

  const groupedAlerts = useMemo(() => {
    if (!summary) return [];
    const groups = new Map<string, SecurityAlert[]>();
    for (const alert of summary.alerts) {
      const host = alert._source.host?.name || "Unknown";
      if (!groups.has(host)) groups.set(host, []);
      groups.get(host)!.push(alert);
    }
    return Array.from(groups.entries()).sort(([, a], [, b]) => b.length - a.length);
  }, [summary]);

  if (!connected) {
    return <div className="loading-state"><div className="loading-spinner" />Connecting...</div>;
  }

  const activeQuery = paramsRef.current.query;
  const hasDetail = !!selectedAlert;

  // verdict lookup removed for stability

  return (
    <div className="triage-app">
      <div className="filter-bar" style={{ flexWrap: "wrap" }}>
        <span className="filter-bar-title">Alert Triage</span>
        {summary && <span className="filter-bar-count">{summary.total} open</span>}
        {activeQuery && (
          <span className="query-pill">
            {activeQuery}
            <button onClick={clearQuery}>&times;</button>
          </span>
        )}
        <div className="filter-bar-severity" style={{ marginLeft: "auto" }}>
          {summary && Object.entries(summary.bySeverity)
            .sort(([, a], [, b]) => b - a)
            .map(([sev, count]) => <SeverityDot key={sev} severity={sev} count={count} />)}
        </div>
        <div className="filter-bar-search" style={{ flex: "0 0 160px" }}>
          <SearchIcon />
          <input type="text" placeholder="Filter..." value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleSearch(searchInput);
              if (e.key === "Escape") { setSearchInput(""); clearQuery(); }
            }} />
        </div>
        <button className="btn btn-sm btn-ghost" style={{ flexShrink: 0 }} onClick={() => {
          const next = !isFullscreen;
          try { appRef.current?.requestDisplayMode({ mode: next ? "fullscreen" : "inline" }); } catch {}
          setIsFullscreen(next);
        }} title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}>
          {isFullscreen ? "\u2715" : "\u26F6"}
        </button>
      </div>

      {summary && !hasDetail && summary.alerts.length > 0 && (
        <div className="summary-panel">
          <div className="summary-grid">
            <div className="summary-section">
              <div className="summary-section-title">Affected Hosts</div>
              {summary.byHost.slice(0, 5).map((h) => (
                <div key={h.name} className="summary-bar-row">
                  <span className="summary-bar-label">{h.name}</span>
                  <div className="summary-bar-track">
                    <div className="summary-bar-fill summary-bar-host"
                      style={{ width: `${(h.count / (summary.byHost[0]?.count || 1)) * 100}%` }} />
                  </div>
                  <span className="summary-bar-value">{h.count}</span>
                </div>
              ))}
            </div>
            <div className="summary-section">
              <div className="summary-section-title">Detection Rules</div>
              {summary.byRule.slice(0, 5).map((r) => (
                <div key={r.name} className="summary-bar-row">
                  <span className="summary-bar-label">{r.name}</span>
                  <div className="summary-bar-track">
                    <div className="summary-bar-fill summary-bar-rule"
                      style={{ width: `${(r.count / (summary.byRule[0]?.count || 1)) * 100}%` }} />
                  </div>
                  <span className="summary-bar-value">{r.count}</span>
                </div>
              ))}
            </div>
            <div className="summary-section">
              <div className="summary-section-title">Severity</div>
              {Object.entries(summary.bySeverity).sort(([, a], [, b]) => b - a).map(([sev, count]) => (
                <div key={sev} className="summary-bar-row">
                  <span className="summary-bar-label" style={{ flex: "0 0 60px", textTransform: "uppercase", fontSize: 10 }}>{sev}</span>
                  <div className="summary-bar-track">
                    <div className="summary-bar-fill" style={{ width: `${(count / summary.total) * 100}%`, backgroundColor: severityColor(sev) }} />
                  </div>
                  <span className="summary-bar-value">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {verdicts.length > 0 && !hasDetail && (
        <div style={{ padding: "10px 16px", borderBottom: "1px solid var(--border-subtle)", flexShrink: 0, maxHeight: 280, overflowY: "auto" }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.6px", color: "var(--text-dim)", marginBottom: 6 }}>Triage Verdicts</div>
          {verdicts.map((v, i) => {
            const colors: Record<string, string> = { benign: "var(--severity-low)", suspicious: "var(--severity-medium)", malicious: "var(--severity-critical)" };
            const bgs: Record<string, string> = { benign: "var(--severity-low-bg)", suspicious: "var(--severity-medium-bg)", malicious: "var(--severity-critical-bg)" };
            const borders: Record<string, string> = { benign: "var(--severity-low-border)", suspicious: "var(--severity-medium-border)", malicious: "var(--severity-critical-border)" };
            const c = colors[v.classification] || colors.suspicious;
            const bg = bgs[v.classification] || bgs.suspicious;
            const bd = borders[v.classification] || borders.suspicious;
            const matchingAlert = summary?.alerts.find(a => a._source["kibana.alert.rule.name"] === v.rule);
            return (
              <div key={i} onClick={() => matchingAlert && selectAlert(matchingAlert)} style={{ display: "flex", alignItems: "flex-start", gap: 10, background: bg, border: `1px solid ${bd}`, borderLeft: `4px solid ${c}`, borderRadius: "var(--radius-md)", padding: "8px 12px", marginBottom: 6, cursor: matchingAlert ? "pointer" : "default", transition: "all 0.15s" }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginBottom: 2 }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: c }}>{(v.classification || "").toUpperCase()}</span>
                    <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{v.confidence} confidence</span>
                    {v.hosts && <span style={{ fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--text-dim)" }}>{v.hosts.join(", ")}</span>}
                  </div>
                  <div style={{ fontSize: 11.5, fontWeight: 600, color: "var(--text-primary)", marginBottom: 2 }}>{v.rule}</div>
                  <div style={{ fontSize: 11, color: "var(--text-secondary)", lineHeight: 1.4 }}>{v.summary}</div>
                  <div style={{ fontSize: 10, color: c, fontWeight: 600, marginTop: 4 }}>{v.action}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="triage-body">
        <div className={`alert-list-pane ${hasDetail ? "narrow" : ""}`}>
          {loading && !summary ? (
            <div className="loading-state"><div className="loading-spinner" />Loading alerts...</div>
          ) : !summary || summary.alerts.length === 0 ? (
            <div className="empty-state">{activeQuery ? `No alerts matching "${activeQuery}"` : "No open alerts"}</div>
          ) : (
            groupedAlerts.map(([hostName, alerts]) => (
              <HostGroup key={hostName} hostName={hostName} alerts={alerts} compact={hasDetail}
                selectedId={selectedAlert?._id} onSelect={selectAlert}
                defaultOpen={groupedAlerts.length <= 5} />
            ))
          )}
        </div>

        {hasDetail && (
          <div className="detail-pane">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
              <button className="back-btn" onClick={() => setSelectedAlert(null)}>&larr; Back to list</button>
              <button className="btn btn-sm btn-ghost" onClick={() => setSelectedAlert(null)}>&times;</button>
            </div>
            <DetailView key={selectedAlert._id} alert={selectedAlert} context={alertContext} contextLoading={contextLoading}
              onAcknowledge={() => acknowledgeAlert(selectedAlert._id)} app={appRef.current!} />
          </div>
        )}
      </div>
    </div>
  );
}

function HostGroup({ hostName, alerts, compact, selectedId, onSelect, defaultOpen }: {
  hostName: string; alerts: SecurityAlert[]; compact: boolean;
  selectedId?: string; onSelect: (a: SecurityAlert) => void; defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="host-group">
      <div className="host-group-header" onClick={() => setOpen(!open)}>
        <span className={`chevron ${open ? "open" : ""}`}>&#9654;</span>
        <span className="host-name">{hostName}</span>
        <span className="host-count">{alerts.length} alert{alerts.length !== 1 ? "s" : ""}</span>
      </div>
      {open && (
        <div className="host-group-alerts">
          {alerts.map((alert, i) => (
            <div key={alert._id} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
              <AlertCard alert={alert} compact={compact} selected={selectedId === alert._id}
                onClick={() => onSelect(alert)} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function DetailView({ alert, context, contextLoading, onAcknowledge, app }: {
  alert: SecurityAlert; context: AlertContext | null; contextLoading: boolean;
  onAcknowledge: () => void; app: McpApp;
}) {
  const src = alert._source;
  const sev = src["kibana.alert.severity"]?.toLowerCase() || "low";
  const [tab, setTab] = useState<"overview" | "process" | "network" | "related">("overview");

  return (
    <>
      <div className={`detail-header-card sev-${sev}`}>
        <div className="detail-rule-name">{src["kibana.alert.rule.name"]}</div>
        <div className="detail-reason">{src["kibana.alert.reason"]}</div>

        {src["kibana.alert.rule.threat"]?.length ? (
          <div className="alert-card-mitre" style={{ margin: "8px 0" }}>
            {src["kibana.alert.rule.threat"]!.map((t, i) => (
              <React.Fragment key={i}>
                <span className="mitre-tag mitre-tactic">{t.tactic.name}</span>
                {t.technique?.map((tech) => (
                  <span key={tech.id} className="mitre-tag mitre-technique">{tech.id}</span>
                ))}
              </React.Fragment>
            ))}
          </div>
        ) : null}

        <div className="detail-meta-grid">
          {src.host?.name && <MetaItem label="Host" value={src.host.name} />}
          {src.user?.name && <MetaItem label="User" value={`${src.user.domain ? src.user.domain + "\\" : ""}${src.user.name}`} />}
          {src.process?.name && <MetaItem label="Process" value={`${src.process.name}${src.process.pid ? ` (${src.process.pid})` : ""}`} />}
          {src.process?.executable && <MetaItem label="Executable" value={src.process.executable} />}
          {src.source?.ip && <MetaItem label="Source" value={`${src.source.ip}${src.source.port ? `:${src.source.port}` : ""}`} />}
          {src.destination?.ip && <MetaItem label="Destination" value={`${src.destination.ip}${src.destination.port ? `:${src.destination.port}` : ""}`} />}
          {src.file?.path && <MetaItem label="File" value={src.file.path} />}
        </div>
      </div>

      <ThreatClassifier alert={alert} onAcknowledge={onAcknowledge} app={app} />

      <div className="detail-tabs">
        {(["overview", "process", "network", "related"] as const).map((t) => (
          <button key={t} className={`detail-tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {t === "overview" ? "Overview" : t === "process" ? "Process Tree" : t === "network" ? "Network" : "Related"}
            {t !== "overview" && context && (
              <span className="tab-count">
                {t === "process" ? context.processEvents.length : t === "network" ? context.networkEvents.length : context.relatedAlerts.length}
              </span>
            )}
          </button>
        ))}
      </div>

      {contextLoading ? (
        <div className="loading-state"><div className="loading-spinner" />Loading context...</div>
      ) : tab === "overview" ? (
        <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.7, padding: "4px 0" }}>
          {src["kibana.alert.rule.description"] && <DetailField label="Rule Description" value={src["kibana.alert.rule.description"]} />}
          {src.process?.args && <DetailField label="Command Line" value={src.process.args.join(" ")} mono />}
          {src.process?.parent && <DetailField label="Parent Process" value={`${src.process.parent.name || "?"}${src.process.parent.pid ? ` (${src.process.parent.pid})` : ""}`} mono />}
        </div>
      ) : tab === "process" && context ? (
        <AlertTimeline events={context.processEvents} />
      ) : tab === "network" && context ? (
        <InvestigationPanel context={context} alert={alert} tab="network" />
      ) : tab === "related" && context ? (
        <InvestigationPanel context={context} alert={alert} tab="related" />
      ) : null}
    </>
  );
}

function MetaItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="detail-meta-item">
      <span className="label">{label}</span>
      <span className="value">{value}</span>
    </div>
  );
}

function DetailField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-dim)", marginBottom: 3 }}>{label}</div>
      <div style={mono ? { fontFamily: "var(--font-mono)", fontSize: 11, wordBreak: "break-all" as const } : undefined}>{value}</div>
    </div>
  );
}
