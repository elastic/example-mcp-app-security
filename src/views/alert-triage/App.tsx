/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme } from "../../shared/theme";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import type { SecurityAlert, AlertSummary, AlertContext } from "../../shared/types";

type SeverityKey = "critical" | "high" | "medium" | "low";
import { AlertCard, AlertScoreRing, EntityIcon } from "./components/AlertCard";
import type { ProcessEvent, NetworkEvent } from "../../shared/types";
import "./styles.css";

interface FilterParams {
  days: number;
  severity?: string;
  limit: number;
  query?: string;
}

const SearchIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
    <circle cx="11" cy="11" r="7" /><path d="m21 21-4.35-4.35" />
  </svg>
);

const AppGlyph = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <path d="M23.9506 12.4984C23.9527 11.5265 23.6542 10.5777 23.0961 9.78204C22.538 8.98635 21.7475 8.38267 20.8329 8.05369C20.9165 7.62975 20.9586 7.19872 20.9588 6.76664C20.9593 5.33599 20.5061 3.94206 19.6645 2.78515C18.8228 1.62826 17.6361 0.767973 16.2748 0.327936C14.9135 -0.112099 13.4478 -0.109226 12.0882 0.336144C10.7287 0.781513 9.54534 1.64645 8.70826 2.80664C8.09097 2.32848 7.33466 2.06452 6.55389 2.05472C5.77314 2.04491 5.01045 2.2898 4.38134 2.75229C3.75222 3.21479 3.29095 3.86969 3.0674 4.61782C2.84384 5.36595 2.87015 6.16656 3.14238 6.8984C2.22542 7.23206 1.43269 7.83861 0.870884 8.63641C0.309073 9.43422 0.00515049 10.385 2.34805e-05 11.3608C-0.00305405 12.3366 0.296461 13.2893 0.857326 14.0879C1.41819 14.8864 2.21282 15.4914 3.13179 15.8195C3.05214 16.2435 3.01275 16.6741 3.01414 17.1054C3.01158 18.5358 3.46368 19.9298 4.30518 21.0864C5.14666 22.2429 6.33397 23.1021 7.69564 23.5398C9.05729 23.9775 10.5228 23.9711 11.8806 23.5214C13.2384 23.0718 14.4181 22.2022 15.2494 21.0384C15.8649 21.5186 16.6204 21.7849 17.4009 21.7969C18.1815 21.8089 18.9447 21.566 19.5747 21.1049C20.2047 20.6438 20.6669 19.9898 20.8915 19.242C21.1161 18.4944 21.0906 17.6938 20.8188 16.9619C21.734 16.6265 22.5246 16.0189 23.0845 15.2211C23.6442 14.4232 23.9465 13.4731 23.9506 12.4984ZM9.27296 3.52899C10.0442 2.40726 11.1788 1.586 12.4853 1.20381C13.7919 0.821635 15.1902 0.901957 16.4444 1.43121C17.6986 1.96048 18.7316 2.90626 19.3694 4.10891C20.0071 5.31156 20.2104 6.69741 19.9447 8.03252L14.6576 12.6631L9.41649 10.2749L8.39297 8.09017L9.27296 3.52899ZM6.62238 2.94075C7.24393 2.94062 7.84828 3.14484 8.34238 3.52193L7.54943 7.60311L3.95885 6.75487C3.80314 6.32609 3.75287 5.86614 3.81229 5.41386C3.87172 4.96158 4.03908 4.53022 4.30026 4.15621C4.56145 3.78221 4.90878 3.47653 5.31293 3.26499C5.71708 3.05344 6.1662 2.94224 6.62238 2.94075ZM0.925906 11.3713C0.931192 10.5387 1.19621 9.72838 1.68401 9.05351C2.17182 8.37865 2.85807 7.87284 3.64708 7.60664L7.58826 8.53722L8.51296 10.5149L3.47414 15.0725C2.72441 14.7865 2.07928 14.2793 1.62421 13.6184C1.16915 12.9574 0.925627 12.1738 0.925906 11.3713ZM14.7012 20.3348C13.9892 21.3831 12.9599 22.1753 11.7643 22.5953C10.5688 23.0152 9.27013 23.0407 8.05905 22.668C6.84795 22.2953 5.78828 21.5441 5.03568 20.5247C4.28307 19.5053 3.8772 18.2714 3.87767 17.0042C3.87822 16.6092 3.91764 16.2152 3.99532 15.8278L9.14826 11.1643L14.4094 13.5619L15.5741 15.7878L14.7012 20.3348ZM17.3341 20.9231C16.7144 20.9209 16.1126 20.7142 15.6224 20.3348L16.4035 16.2666L19.9918 17.1054C20.1479 17.5339 20.1986 17.9934 20.1396 18.4455C20.0808 18.8976 19.914 19.3289 19.6534 19.7031C19.3928 20.0772 19.0461 20.3831 18.6425 20.5951C18.2388 20.8069 17.79 20.9187 17.3341 20.9207V20.9231ZM20.3035 16.2513L16.3529 15.3278L15.3035 13.3278L20.4706 8.80075C21.2209 9.08447 21.8672 9.58986 22.3234 10.2497C22.7796 10.9096 23.0242 11.6926 23.0247 12.4948C23.0173 13.3258 22.7512 14.1336 22.2635 14.8065C21.7759 15.4792 21.0908 15.9834 20.3035 16.2489V16.2513Z" fill="currentColor"/>
  </svg>
);

const FullscreenIcon = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M2 6V2h4" /><path d="M14 6V2h-4" /><path d="M2 10v4h4" /><path d="M14 10v4h-4" />
  </svg>
);

const ExitFullscreenIcon = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M6 2v4H2" /><path d="M10 2v4h4" /><path d="M6 14v-4H2" /><path d="M10 14v-4h4" />
  </svg>
);

type SortKey = "severity" | "risk" | "newest" | "oldest" | "rule" | "host";
const SORT_LABEL: Record<SortKey, string> = {
  severity: "Severity",
  risk: "Risk score",
  newest: "Newest first",
  oldest: "Oldest first",
  rule: "Rule name",
  host: "Host name",
};
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

type GroupKey = "none" | "host" | "user" | "process";
const GROUP_LABEL: Record<GroupKey, string> = {
  none: "None",
  host: "Host",
  user: "User",
  process: "Process",
};

const SEVERITY_ORDER: SeverityKey[] = ["critical", "high", "medium", "low"];
const SEVERITY_LABEL: Record<SeverityKey, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low",
};
const SEVERITY_STROKE: Record<SeverityKey, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
};

function SeverityDonut({ bySeverity }: { bySeverity: Record<string, number> }) {
  // Normalize — bySeverity keys may be capitalized or include extras.
  const counts: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const [k, v] of Object.entries(bySeverity)) {
    const key = k.toLowerCase() as SeverityKey;
    if (key in counts) counts[key] += v;
  }
  const total = SEVERITY_ORDER.reduce((s, k) => s + counts[k], 0);

  // viewBox chosen so circumference = 100 → segment lengths are percentages.
  const r = 15.91549430918954;
  const cx = 21, cy = 21, sw = 6;

  let cumulative = 0;
  const arcs = SEVERITY_ORDER.map((key) => {
    const pct = total ? (counts[key] / total) * 100 : 0;
    const arc = { key, count: counts[key], pct, offset: -cumulative };
    cumulative += pct;
    return arc;
  });

  return (
    <div className="severity-donut">
      <svg
        width="105" height="105" viewBox="0 0 42 42"
        className="severity-donut-svg"
        role="img"
        aria-label={`Severity breakdown: ${total} alerts total`}
      >
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#171716" strokeWidth={sw} />
        {arcs.filter((a) => a.pct > 0).map((a) => (
          <circle
            key={a.key}
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={SEVERITY_STROKE[a.key]}
            strokeWidth={sw}
            strokeDasharray={`${a.pct} ${100 - a.pct}`}
            strokeDashoffset={a.offset}
            transform={`rotate(-90 ${cx} ${cy})`}
          />
        ))}
      </svg>
      <div className="severity-legend">
        {arcs.map((a) => (
          <div key={a.key} className="severity-legend-row">
            <span className={`severity-legend-dot sev-${a.key}`} />
            <span className="severity-legend-label">{SEVERITY_LABEL[a.key]}</span>
            <span className="severity-legend-value">{a.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

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
  const [showDetails, setShowDetails] = useState(false);
  const [sortBy, setSortBy] = useState<SortKey>("severity");
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const sortRef = useRef<HTMLDivElement | null>(null);
  const [groupBy, setGroupBy] = useState<GroupKey>("none");
  const [groupMenuOpen, setGroupMenuOpen] = useState(false);
  const groupRef = useRef<HTMLDivElement | null>(null);
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
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
    const app = new McpApp({ name: "alert-triage", version: "1.0.0" });
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

  useEffect(() => {
    if (!sortMenuOpen) return;
    const onClick = (e: MouseEvent) => {
      if (sortRef.current && !sortRef.current.contains(e.target as Node)) {
        setSortMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [sortMenuOpen]);

  useEffect(() => {
    if (!groupMenuOpen) return;
    const onClick = (e: MouseEvent) => {
      if (groupRef.current && !groupRef.current.contains(e.target as Node)) {
        setGroupMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [groupMenuOpen]);

  const sortedAlerts = useMemo(() => {
    if (!summary) return [];
    const arr = [...summary.alerts];
    switch (sortBy) {
      case "severity":
        arr.sort((a, b) =>
          (SEV_RANK[b._source["kibana.alert.severity"]?.toLowerCase() || ""] || 0) -
          (SEV_RANK[a._source["kibana.alert.severity"]?.toLowerCase() || ""] || 0));
        break;
      case "risk":
        arr.sort((a, b) => (b._source["kibana.alert.risk_score"] || 0) - (a._source["kibana.alert.risk_score"] || 0));
        break;
      case "newest":
        arr.sort((a, b) => new Date(b._source["@timestamp"]).getTime() - new Date(a._source["@timestamp"]).getTime());
        break;
      case "oldest":
        arr.sort((a, b) => new Date(a._source["@timestamp"]).getTime() - new Date(b._source["@timestamp"]).getTime());
        break;
      case "rule":
        arr.sort((a, b) => (a._source["kibana.alert.rule.name"] || "").localeCompare(b._source["kibana.alert.rule.name"] || ""));
        break;
      case "host":
        arr.sort((a, b) => (a._source.host?.name || "").localeCompare(b._source.host?.name || ""));
        break;
    }
    return arr;
  }, [summary, sortBy]);

  // Group the sorted alert list by a chosen entity. Each group entry carries a display name,
  // a subtitle (OS / domain / executable), the highest-severity alert in the group, and the
  // alerts themselves — all derived so the group header can show reasonable summary data.
  const groupedAlerts = useMemo(() => {
    if (groupBy === "none") return null;
    const buckets = new Map<string, {
      key: string;
      name: string;
      subtitle?: string;
      topSeverity: SeverityKey;
      alerts: SecurityAlert[];
    }>();
    for (const a of sortedAlerts) {
      const src = a._source;
      let key: string | undefined;
      let name: string | undefined;
      let subtitle: string | undefined;
      if (groupBy === "host") {
        name = src.host?.name;
        key = name;
        const os = src.host?.os?.name || src.host?.os?.platform;
        subtitle = os ? `${os} host` : (src.host?.ip?.[0] ? `IP ${src.host.ip[0]}` : undefined);
      } else if (groupBy === "user") {
        name = src.user?.name;
        key = src.user?.domain ? `${src.user.domain}\\${name}` : name;
        subtitle = src.user?.domain ? `Domain ${src.user.domain}` : (src.host?.name ? `Seen on ${src.host.name}` : undefined);
      } else if (groupBy === "process") {
        name = src.process?.name;
        key = name;
        subtitle = src.process?.executable || (src.process?.parent?.name ? `Parent ${src.process.parent.name}` : undefined);
      }
      if (!key || !name) continue;
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { key, name, subtitle, topSeverity: "low", alerts: [] };
        buckets.set(key, bucket);
      }
      bucket.alerts.push(a);
      const sev = (src["kibana.alert.severity"]?.toLowerCase() || "low") as SeverityKey;
      if ((SEV_RANK[sev] || 0) > (SEV_RANK[bucket.topSeverity] || 0)) bucket.topSeverity = sev;
    }
    // Sort groups: highest severity first, then by alert count desc, then alphabetically.
    return [...buckets.values()].sort((a, b) => {
      const d = (SEV_RANK[b.topSeverity] || 0) - (SEV_RANK[a.topSeverity] || 0);
      if (d !== 0) return d;
      const c = b.alerts.length - a.alerts.length;
      if (c !== 0) return c;
      return a.name.localeCompare(b.name);
    });
  }, [sortedAlerts, groupBy]);

  const toggleGroup = useCallback((key: string) => {
    setOpenGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const setGroupByAndReset = useCallback((g: GroupKey) => {
    setGroupBy(g);
    setGroupMenuOpen(false);
    setOpenGroups(new Set());
  }, []);

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

  /**
   * Filter the alert list by a specific ECS field/value pair.
   * Called when the user clicks a dotted-underline fact value on a card or in the detail pane.
   *
   * NOTE: the `poll-alerts` server-side handler treats `query` as a plain full-text search —
   * it splits on whitespace and runs each term as a wildcard across a fixed set of fields
   * (rule name, reason, host.name, user.name, process.name, process.executable, file.*).
   * So we send the bare value (quoted if it contains whitespace), not KQL like `host.name: "x"`.
   */
  const entityFilter = useCallback((field: string, value: string) => {
    if (!value) return;
    const q = /\s/.test(value) ? `"${value}"` : value;
    setSearchInput(q);
    loadAlerts(undefined, { query: q });
  }, [loadAlerts]);

  if (!connected) {
    return <div className="loading-state"><div className="loading-spinner" />Connecting...</div>;
  }

  const activeQuery = paramsRef.current.query;
  const hasDetail = !!selectedAlert;

  // verdict lookup removed for stability

  return (
    <div className="triage-app">
      <header className="triage-header">
        <div className="triage-header-left">
          <div className="triage-header-brand">
            <span className="triage-header-glyph" aria-hidden="true"><AppGlyph /></span>
            <h1 className="triage-header-title">Alert Triage</h1>
          </div>
          {activeQuery && (
            <span className="query-pill">
              {activeQuery}
              <button onClick={clearQuery} aria-label="Clear filter">
                <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                  <path d="m7.293 8-3.147 3.146a.5.5 0 0 0 .708.708L8 8.707l3.146 3.147a.5.5 0 0 0 .708-.708L8.707 8l3.147-3.146a.5.5 0 1 0-.708-.708L8 7.293 4.854 4.146a.5.5 0 1 0-.708.708L7.293 8Z" />
                </svg>
              </button>
            </span>
          )}
        </div>
        <div className="triage-header-actions">
          <div className="triage-header-search">
            <SearchIcon />
            <input
              type="text"
              placeholder="Filter"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSearch(searchInput);
                if (e.key === "Escape") { setSearchInput(""); clearQuery(); }
              }}
            />
          </div>
          <button
            type="button"
            className="triage-header-icon-btn"
            onClick={() => {
              const next = !isFullscreen;
              try { appRef.current?.requestDisplayMode({ mode: next ? "fullscreen" : "inline" }); } catch {}
              setIsFullscreen(next);
            }}
            title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
            aria-label={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
          >
            {isFullscreen ? <ExitFullscreenIcon /> : <FullscreenIcon />}
          </button>
        </div>
      </header>

      <div className="triage-body">
        <div className={`alert-list-pane ${hasDetail ? "narrow" : ""}`}>
          {hasDetail && (
            <button
              type="button"
              className="alert-list-back"
              onClick={() => setSelectedAlert(null)}
            >
              <span aria-hidden="true">&larr;</span> Back to list
            </button>
          )}
          {summary && !hasDetail && summary.alerts.length > 0 && (
            <div className="summary-panel">
              <div className="summary-grid">
                <div className="summary-section">
                  <div className="summary-section-title">Severity</div>
                  <SeverityDonut bySeverity={summary.bySeverity} />
                </div>
                <div className="summary-section">
                  <div className="summary-section-title">Affected Hosts</div>
                  <div className="summary-section-body">
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
                </div>
                <div className="summary-section">
                  <div className="summary-section-title">Detection Rules</div>
                  <div className="summary-section-body">
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
                </div>
              </div>
            </div>
          )}

          {verdicts.length > 0 && !hasDetail && (
            <div className="verdicts-panel">
              <div className="verdicts-panel-title">Triage Verdicts</div>
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

          {summary && !hasDetail && summary.alerts.length > 0 && (
            <div className="alert-list-subheader">
              <div className="alert-list-subheader-left">
                <span className="alert-list-subheader-count">
                  Showing <strong>{summary.alerts.length}</strong> alerts
                </span>
                <div className="alert-list-subheader-sort" ref={sortRef}>
                  <button
                    type="button"
                    className="alert-list-subheader-sort-trigger"
                    onClick={() => setSortMenuOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={sortMenuOpen}
                  >
                    <span>Sort by: <span className="alert-list-subheader-sort-value">{SORT_LABEL[sortBy]}</span></span>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: sortMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                      <path d="M2.5 3.75L5 6.25L7.5 3.75" />
                    </svg>
                  </button>
                  {sortMenuOpen && (
                    <div className="alert-list-subheader-sort-menu" role="listbox">
                      {(Object.keys(SORT_LABEL) as SortKey[]).map((k) => (
                        <button
                          key={k}
                          type="button"
                          role="option"
                          aria-selected={k === sortBy}
                          className={`alert-list-subheader-sort-option${k === sortBy ? " active" : ""}`}
                          onClick={() => { setSortBy(k); setSortMenuOpen(false); }}
                        >
                          {SORT_LABEL[k]}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              <div className="alert-list-subheader-controls">
                <label className="alert-list-subheader-toggle">
                  <span className="alert-list-subheader-toggle-label">Details</span>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={showDetails}
                    aria-label="Toggle alert details"
                    className={`toggle-switch${showDetails ? " on" : ""}`}
                    onClick={() => setShowDetails((v) => !v)}
                  >
                    <span className="toggle-switch-thumb" />
                  </button>
                </label>
                <div className="alert-list-subheader-sort alert-list-subheader-group" ref={groupRef}>
                  <button
                    type="button"
                    className="alert-list-subheader-sort-trigger"
                    onClick={() => setGroupMenuOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={groupMenuOpen}
                  >
                    <span>Group by: <span className="alert-list-subheader-sort-value">{GROUP_LABEL[groupBy]}</span></span>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: groupMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                      <path d="M2.5 3.75L5 6.25L7.5 3.75" />
                    </svg>
                  </button>
                  {groupMenuOpen && (
                    <div className="alert-list-subheader-sort-menu alert-list-subheader-sort-menu-right" role="listbox">
                      {(Object.keys(GROUP_LABEL) as GroupKey[]).map((k) => (
                        <button
                          key={k}
                          type="button"
                          role="option"
                          aria-selected={k === groupBy}
                          className={`alert-list-subheader-sort-option${k === groupBy ? " active" : ""}`}
                          onClick={() => setGroupByAndReset(k)}
                        >
                          {GROUP_LABEL[k]}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          <div className="alert-list-content">
            {loading && !summary ? (
              <div className="loading-state"><div className="loading-spinner" />Loading alerts...</div>
            ) : !summary || summary.alerts.length === 0 ? (
              <div className="empty-state">{activeQuery ? `No alerts matching "${activeQuery}"` : "No open alerts"}</div>
            ) : groupedAlerts ? (
              groupedAlerts.length === 0 ? (
                <div className="empty-state">No alerts have a {GROUP_LABEL[groupBy].toLowerCase()} to group by.</div>
              ) : (
                groupedAlerts.map((group, i) => {
                  const expanded = openGroups.has(group.key);
                  return (
                    <div key={group.key} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
                      <GroupCard
                        group={group}
                        groupBy={groupBy}
                        expanded={expanded}
                        onToggle={() => toggleGroup(group.key)}
                      />
                      {expanded && (
                        <div className={`group-children sev-${group.topSeverity}`}>
                          {group.alerts.map((alert) => (
                            <AlertCard
                              key={alert._id}
                              alert={alert}
                              compact={hasDetail}
                              selected={selectedAlert?._id === alert._id}
                              showDetails={showDetails}
                              onClick={() => selectAlert(alert)}
                              onEntityFilter={entityFilter}
                            />
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })
              )
            ) : (
              sortedAlerts.map((alert, i) => (
                <div key={alert._id} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
                  <AlertCard alert={alert} compact={hasDetail} selected={selectedAlert?._id === alert._id}
                    showDetails={showDetails}
                    onClick={() => selectAlert(alert)}
                    onEntityFilter={entityFilter} />
                </div>
              ))
            )}
          </div>
        </div>

        {hasDetail && (
          <div className="detail-pane">
            <DetailView key={selectedAlert._id} alert={selectedAlert} context={alertContext} contextLoading={contextLoading}
              onAcknowledge={() => acknowledgeAlert(selectedAlert._id)} onSelectAlert={selectAlert}
              onEntityFilter={entityFilter} />
          </div>
        )}
      </div>
    </div>
  );
}

const PROCESS_PREVIEW = 3;
const NETWORK_PREVIEW = 4;
const RELATED_PREVIEW = 3;

interface GroupBucket {
  key: string;
  name: string;
  subtitle?: string;
  topSeverity: SeverityKey;
  alerts: SecurityAlert[];
}

function GroupCard({ group, groupBy, expanded, onToggle }: {
  group: GroupBucket;
  groupBy: GroupKey;
  expanded: boolean;
  onToggle: () => void;
}) {
  const sev = group.topSeverity;
  const label = SEVERITY_LABEL[sev];
  return (
    <button
      type="button"
      className={`group-card sev-${sev}${expanded ? " expanded" : ""}`}
      onClick={onToggle}
      aria-expanded={expanded}
    >
      <div className="group-card-body">
        <span className={`group-card-sev sev-chip sev-chip-${sev}`}>
          <span className="sev-chip-dot" />
          <span className="sev-chip-label">{label}</span>
        </span>
        <div className="group-card-identity">
          <div className="group-card-name">{group.name}</div>
          {group.subtitle && <div className="group-card-subtitle">{group.subtitle}</div>}
        </div>
      </div>
      <div className="group-card-meta">
        <span className="group-card-count">
          alerts: <span className="group-card-count-value">{group.alerts.length}</span>
        </span>
        <span className={`group-card-chevron${expanded ? " open" : ""}`} aria-hidden="true">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
            <path d="M3.5 5.25 L7 8.75 L10.5 5.25" />
          </svg>
        </span>
      </div>
      <span className="sr-only">Grouped by {GROUP_LABEL[groupBy]}</span>
    </button>
  );
}

function DetailView({ alert, context, contextLoading, onAcknowledge, onSelectAlert, onEntityFilter }: {
  alert: SecurityAlert; context: AlertContext | null; contextLoading: boolean;
  onAcknowledge: () => void; onSelectAlert: (a: SecurityAlert) => void;
  onEntityFilter?: (field: string, value: string) => void;
}) {
  const src = alert._source;
  const sev = ((src["kibana.alert.severity"]?.toLowerCase() || "low") as "low" | "medium" | "high" | "critical");
  const score = src["kibana.alert.risk_score"] ?? 0;

  const threat = src["kibana.alert.rule.threat"]?.[0];
  const tacticName = threat?.tactic?.name;
  const techniqueId = threat?.technique?.[0]?.id;

  const userDisplay = src.user?.name
    ? (src.user.domain ? `${src.user.domain}\\${src.user.name}` : src.user.name)
    : undefined;

  const [processOpen, setProcessOpen] = useState(false);
  const [networkOpen, setNetworkOpen] = useState(false);
  const [relatedOpen, setRelatedOpen] = useState(false);

  return (
    <div className="alert-detail">
      <div className="alert-detail-top">
        <AlertScoreRing score={score} severity={sev} />
        <button type="button" className="alert-detail-action" onClick={onAcknowledge}>
          Take Action
        </button>
      </div>

      <div className="alert-detail-head">
        {(tacticName || techniqueId) && (
          <div className="alert-card-mitre">
            {tacticName && <span className="mitre-tag mitre-tag-tactic">{tacticName}</span>}
            {techniqueId && <span className="mitre-tag mitre-tag-technique">{techniqueId}</span>}
          </div>
        )}
        <h2 className="alert-detail-title">{src["kibana.alert.rule.name"]}</h2>
        {src["kibana.alert.reason"] && (
          <div className="alert-detail-reason">{src["kibana.alert.reason"]}</div>
        )}
      </div>

      <div className="alert-detail-facts">
        <FactCol label="HOST" icon={EntityIcon.host} value={src.host?.name} field="host.name" onFilter={onEntityFilter} />
        <FactCol label="USER" icon={EntityIcon.user} value={userDisplay} filterValue={src.user?.name} field="user.name" onFilter={onEntityFilter} />
        <FactCol label="PROCESS" icon={EntityIcon.process} value={src.process?.name} field="process.name" onFilter={onEntityFilter} />
        <FactCol label="EXECUTABLE" icon={EntityIcon.executable} value={src.process?.executable} field="process.executable" onFilter={onEntityFilter} truncate />
      </div>

      {src["kibana.alert.rule.description"] && (
        <div className="alert-detail-description">
          <div className="alert-detail-description-label">Rule description</div>
          <div className="alert-detail-description-body">{src["kibana.alert.rule.description"]}</div>
        </div>
      )}

      {contextLoading ? (
        <div className="alert-detail-section"><div className="loading-state"><div className="loading-spinner" />Loading context...</div></div>
      ) : context ? (
        <>
          {context.processEvents.length > 0 && (
            <ExpandSection
              title="Process tree"
              count={context.processEvents.length}
              expanded={processOpen}
              onToggle={() => setProcessOpen((v) => !v)}
              previewCount={PROCESS_PREVIEW}
            >
              <div className="process-tree-box">
                {(processOpen ? context.processEvents : context.processEvents.slice(0, PROCESS_PREVIEW)).map((e, i) => (
                  <ProcessTreeRow key={i} event={e} />
                ))}
              </div>
            </ExpandSection>
          )}

          {context.networkEvents.length > 0 && (
            <ExpandSection
              title="Network"
              count={context.networkEvents.length}
              expanded={networkOpen}
              onToggle={() => setNetworkOpen((v) => !v)}
              previewCount={NETWORK_PREVIEW}
            >
              <NetworkTable events={networkOpen ? context.networkEvents : context.networkEvents.slice(0, NETWORK_PREVIEW)} />
            </ExpandSection>
          )}

          {context.relatedAlerts.length > 0 && (
            <ExpandSection
              title="Related"
              count={context.relatedAlerts.length}
              expanded={relatedOpen}
              onToggle={() => setRelatedOpen((v) => !v)}
              previewCount={RELATED_PREVIEW}
            >
              <div className="related-alerts-list">
                {(relatedOpen ? context.relatedAlerts : context.relatedAlerts.slice(0, RELATED_PREVIEW)).map((a) => (
                  <RelatedAlertCard key={a._id} alert={a} onClick={() => onSelectAlert(a)} />
                ))}
              </div>
            </ExpandSection>
          )}
        </>
      ) : null}
    </div>
  );
}

function FactCol({ label, value, filterValue, field, onFilter, truncate, icon }: {
  label: string;
  value?: string;
  /** Overrides `value` when building the filter query (e.g. bare user.name without the `DOMAIN\` prefix). */
  filterValue?: string;
  field?: string;
  onFilter?: (field: string, value: string) => void;
  truncate?: boolean;
  icon?: React.ReactNode;
}) {
  const displayed = value || "—";
  const canFilter = !!(onFilter && field && (filterValue ?? value));
  const classes = `alert-detail-fact-value${truncate ? " truncate" : ""}${canFilter ? " clickable" : ""}`;

  return (
    <div className="alert-detail-fact">
      <div className="alert-detail-fact-label">
        {icon && <span className="alert-detail-fact-icon" aria-hidden="true">{icon}</span>}
        <span>{label}</span>
      </div>
      {canFilter ? (
        <button
          type="button"
          className={classes}
          title={`Filter by ${field}: ${filterValue ?? value}`}
          onClick={() => onFilter!(field!, filterValue ?? value!)}
        >
          {displayed}
        </button>
      ) : (
        <div className={classes} title={value || undefined}>{displayed}</div>
      )}
    </div>
  );
}

function ExpandSection({ title, count, expanded, onToggle, previewCount, children }: {
  title: string; count: number; expanded: boolean; onToggle: () => void; previewCount: number; children: React.ReactNode;
}) {
  const canExpand = count > previewCount;
  return (
    <section className="alert-detail-section">
      <div className="alert-detail-section-head">
        <span className="alert-detail-section-title">{title}</span>
        <span className="alert-detail-section-count">{count}</span>
      </div>
      {children}
      {canExpand && (
        <button type="button" className="alert-detail-expand" onClick={onToggle}>
          <span>{expanded ? "Collapse" : "Expand"}</span>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: expanded ? "rotate(90deg)" : "none", transition: "transform 0.15s" }}>
            <path d="M4.5 3l3 3-3 3" />
          </svg>
        </button>
      )}
    </section>
  );
}

function ProcessTreeRow({ event }: { event: ProcessEvent }) {
  const name = event.process?.name || "unknown";
  const pid = event.process?.pid;
  const action = event.event?.action || "";
  const exe = event.process?.executable || "";
  const args = event.process?.args?.join(" ") || "";
  const cmd = exe || args;
  const ts = event["@timestamp"] ? new Date(event["@timestamp"]).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true }) : "";
  return (
    <div className="process-tree-row">
      <div className="process-tree-row-main">
        <div className="process-tree-row-title">
          <span className="process-tree-row-name">{name}</span>
          {pid !== undefined && <span> PID {pid}</span>}
          {action && <span> {action}</span>}
        </div>
        {cmd && <div className="process-tree-row-cmd">{cmd}</div>}
      </div>
      {ts && <div className="process-tree-row-time">{ts}</div>}
    </div>
  );
}

function NetworkTable({ events }: { events: NetworkEvent[] }) {
  if (events.length === 0) {
    return <div className="network-table-box"><div className="alert-detail-empty">No network events.</div></div>;
  }
  return (
    <div className="network-table-box">
      <table className="network-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Process</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => {
            const ts = e["@timestamp"] ? new Date(e["@timestamp"]).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true }) : "—";
            const src = e.source?.ip ? `${e.source.ip}${e.source.port ? `:${e.source.port}` : ""}` : "—";
            const dst = e.destination?.ip ? `${e.destination.ip}${e.destination.port ? `:${e.destination.port}` : ""}` : (e.destination?.port ? `—:${e.destination.port}` : "—");
            const proto = e.network?.protocol || "—";
            const proc = e.process?.name || "—";
            const action = e.event?.action || "—";
            return (
              <tr key={i}>
                <td>{ts}</td>
                <td>{src}</td>
                <td>{dst}</td>
                <td>{proto}</td>
                <td>{proc}</td>
                <td>{action}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function RelatedAlertCard({ alert, onClick }: { alert: SecurityAlert; onClick: () => void }) {
  const src = alert._source;
  const sev = ((src["kibana.alert.severity"]?.toLowerCase() || "low") as "low" | "medium" | "high" | "critical");
  const score = src["kibana.alert.risk_score"] ?? 0;
  return (
    <div className={`related-alert-card sev-${sev}`} onClick={onClick}>
      <div className="related-alert-card-score">
        <AlertScoreRing score={score} severity={sev} />
      </div>
      <div className="related-alert-card-body">
        <div className="related-alert-card-title">{src["kibana.alert.rule.name"]}</div>
        {src["kibana.alert.reason"] && (
          <div className="related-alert-card-reason">{src["kibana.alert.reason"]}</div>
        )}
      </div>
    </div>
  );
}
