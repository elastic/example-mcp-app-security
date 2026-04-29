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
import type { DetectionRule } from "../../shared/types";
import { RuleTestPanel } from "./components/RuleTestPanel";
import "./styles.css";

type SeverityKey = "critical" | "high" | "medium" | "low";
type StatusFilter = "all" | "enabled" | "disabled";
type SortKey = "severity" | "name" | "risk" | "updated" | "enabled";
type GroupKey = "none" | "severity" | "type" | "language" | "tag";
type View = "list" | "detail" | "noisy";

type NoisyRuleRow = { ruleName: string; ruleId: string; alertCount: number };

const SEVERITY_ORDER: SeverityKey[] = ["critical", "high", "medium", "low"];
const SEVERITY_LABEL: Record<SeverityKey, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low",
};
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const SEVERITY_STROKE: Record<SeverityKey, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
};

const STATUS_FILTERS: { key: StatusFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "enabled", label: "Enabled" },
  { key: "disabled", label: "Disabled" },
];

const SORT_LABEL: Record<SortKey, string> = {
  severity: "Severity",
  name: "Name",
  risk: "Risk score",
  updated: "Recently updated",
  enabled: "Enabled first",
};

const GROUP_LABEL: Record<GroupKey, string> = {
  none: "None",
  severity: "Severity",
  type: "Rule type",
  language: "Query language",
  tag: "Tag",
};

const SearchIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
    <circle cx="11" cy="11" r="7" /><path d="m21 21-4.35-4.35" />
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

const AppGlyph = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <path d="M23.9506 12.4984C23.9527 11.5265 23.6542 10.5777 23.0961 9.78204C22.538 8.98635 21.7475 8.38267 20.8329 8.05369C20.9165 7.62975 20.9586 7.19872 20.9588 6.76664C20.9593 5.33599 20.5061 3.94206 19.6645 2.78515C18.8228 1.62826 17.6361 0.767973 16.2748 0.327936C14.9135 -0.112099 13.4478 -0.109226 12.0882 0.336144C10.7287 0.781513 9.54534 1.64645 8.70826 2.80664C8.09097 2.32848 7.33466 2.06452 6.55389 2.05472C5.77314 2.04491 5.01045 2.2898 4.38134 2.75229C3.75222 3.21479 3.29095 3.86969 3.0674 4.61782C2.84384 5.36595 2.87015 6.16656 3.14238 6.8984C2.22542 7.23206 1.43269 7.83861 0.870884 8.63641C0.309073 9.43422 0.00515049 10.385 2.34805e-05 11.3608C-0.00305405 12.3366 0.296461 13.2893 0.857326 14.0879C1.41819 14.8864 2.21282 15.4914 3.13179 15.8195C3.05214 16.2435 3.01275 16.6741 3.01414 17.1054C3.01158 18.5358 3.46368 19.9298 4.30518 21.0864C5.14666 22.2429 6.33397 23.1021 7.69564 23.5398C9.05729 23.9775 10.5228 23.9711 11.8806 23.5214C13.2384 23.0718 14.4181 22.2022 15.2494 21.0384C15.8649 21.5186 16.6204 21.7849 17.4009 21.7969C18.1815 21.8089 18.9447 21.566 19.5747 21.1049C20.2047 20.6438 20.6669 19.9898 20.8915 19.242C21.1161 18.4944 21.0906 17.6938 20.8188 16.9619C21.734 16.6265 22.5246 16.0189 23.0845 15.2211C23.6442 14.4232 23.9465 13.4731 23.9506 12.4984ZM9.27296 3.52899C10.0442 2.40726 11.1788 1.586 12.4853 1.20381C13.7919 0.821635 15.1902 0.901957 16.4444 1.43121C17.6986 1.96048 18.7316 2.90626 19.3694 4.10891C20.0071 5.31156 20.2104 6.69741 19.9447 8.03252L14.6576 12.6631L9.41649 10.2749L8.39297 8.09017L9.27296 3.52899ZM6.62238 2.94075C7.24393 2.94062 7.84828 3.14484 8.34238 3.52193L7.54943 7.60311L3.95885 6.75487C3.80314 6.32609 3.75287 5.86614 3.81229 5.41386C3.87172 4.96158 4.03908 4.53022 4.30026 4.15621C4.56145 3.78221 4.90878 3.47653 5.31293 3.26499C5.71708 3.05344 6.1662 2.94224 6.62238 2.94075ZM0.925906 11.3713C0.931192 10.5387 1.19621 9.72838 1.68401 9.05351C2.17182 8.37865 2.85807 7.87284 3.64708 7.60664L7.58826 8.53722L8.51296 10.5149L3.47414 15.0725C2.72441 14.7865 2.07928 14.2793 1.62421 13.6184C1.16915 12.9574 0.925627 12.1738 0.925906 11.3713ZM14.7012 20.3348C13.9892 21.3831 12.9599 22.1753 11.7643 22.5953C10.5688 23.0152 9.27013 23.0407 8.05905 22.668C6.84795 22.2953 5.78828 21.5441 5.03568 20.5247C4.28307 19.5053 3.8772 18.2714 3.87767 17.0042C3.87822 16.6092 3.91764 16.2152 3.99532 15.8278L9.14826 11.1643L14.4094 13.5619L15.5741 15.7878L14.7012 20.3348ZM17.3341 20.9231C16.7144 20.9209 16.1126 20.7142 15.6224 20.3348L16.4035 16.2666L19.9918 17.1054C20.1479 17.5339 20.1986 17.9934 20.1396 18.4455C20.0808 18.8976 19.914 19.3289 19.6534 19.7031C19.3928 20.0772 19.0461 20.3831 18.6425 20.5951C18.2388 20.8069 17.79 20.9187 17.3341 20.9207V20.9231ZM20.3035 16.2513L16.3529 15.3278L15.3035 13.3278L20.4706 8.80075C21.2209 9.08447 21.8672 9.58986 22.3234 10.2497C22.7796 10.9096 23.0242 11.6926 23.0247 12.4948C23.0173 13.3258 22.7512 14.1336 22.2635 14.8065C21.7759 15.4792 21.0908 15.9834 20.3035 16.2489V16.2513Z" fill="currentColor"/>
  </svg>
);

function SeverityChip({ severity }: { severity: SeverityKey }) {
  return (
    <span className={`sev-chip sev-chip-${severity}`}>
      <span className="sev-chip-dot" />
      <span className="sev-chip-label">{SEVERITY_LABEL[severity]}</span>
    </span>
  );
}

/**
 * Severity donut chart — matches the one in alert-triage for visual consistency.
 * Renders a ring of 4 colored arcs sized by count, with a legend on the right.
 */
function SeverityDonut({ bySeverity }: { bySeverity: Record<string, number> }) {
  const counts: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const [k, v] of Object.entries(bySeverity)) {
    const key = k.toLowerCase() as SeverityKey;
    if (key in counts) counts[key] += v;
  }
  const total = SEVERITY_ORDER.reduce((s, k) => s + counts[k], 0);

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
        aria-label={`Severity breakdown: ${total} rules total`}
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
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [total, setTotal] = useState(0);
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);
  const [view, setView] = useState<View>("list");
  const [searchInput, setSearchInput] = useState("");
  const [activeFilter, setActiveFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [noisyRules, setNoisyRules] = useState<NoisyRuleRow[]>([]);
  const [listLoading, setListLoading] = useState(true);
  const [noisyLoading, setNoisyLoading] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showDetails, setShowDetails] = useState(false);
  const [sortBy, setSortBy] = useState<SortKey>("severity");
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const sortRef = useRef<HTMLDivElement | null>(null);
  const [statusMenuOpen, setStatusMenuOpen] = useState(false);
  const statusRef = useRef<HTMLDivElement | null>(null);
  const [groupBy, setGroupBy] = useState<GroupKey>("none");
  const [groupMenuOpen, setGroupMenuOpen] = useState(false);
  const groupRef = useRef<HTMLDivElement | null>(null);
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());

  const loadRules = useCallback(async (filter?: string, app?: McpApp) => {
    const mcpApp = app || appRef.current;
    if (!mcpApp) return;
    setListLoading(true);
    try {
      const result = await mcpApp.callServerTool({
        name: "find-rules",
        arguments: { filter: filter || undefined, perPage: 50 },
      });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text);
        setRules(data.data || []);
        setTotal(data.total || 0);
      }
    } catch (e) {
      console.error("Failed to load rules:", e);
    } finally {
      setListLoading(false);
    }
  }, []);

  useEffect(() => {
    const app = new McpApp({ name: "detection-rules", version: "1.0.0" });
    appRef.current = app;
    applyTheme(app);

    let gotResult = false;
    app.ontoolresult = (params) => {
      gotResult = true;
      try {
        const text = extractToolText(params);
        if (text) {
          const data = JSON.parse(text);
          if (typeof data.params?.filter === "string") {
            setSearchInput(data.params.filter);
            setActiveFilter(data.params.filter);
          }
        }
      } catch { /* ignore */ }
      loadRules(undefined, app);
    };

    app.connect().then(() => {
      setConnected(true);
      setTimeout(() => { if (!gotResult) loadRules(undefined, app); }, 1500);
    });

    return () => { app.close(); };
  }, [loadRules]);

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
    if (!statusMenuOpen) return;
    const onClick = (e: MouseEvent) => {
      if (statusRef.current && !statusRef.current.contains(e.target as Node)) {
        setStatusMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [statusMenuOpen]);

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

  const openRule = useCallback(async (id: string) => {
    if (!appRef.current) return;
    try {
      const result = await appRef.current.callServerTool({ name: "get-rule", arguments: { id } });
      const text = extractCallResult(result);
      if (text) {
        setSelectedRule(JSON.parse(text));
        setView("detail");
      }
    } catch (e) { console.error("Failed to load rule:", e); }
  }, []);

  const toggleRule = useCallback(async (id: string, enabled: boolean) => {
    if (!appRef.current) return;
    try {
      await appRef.current.callServerTool({ name: "toggle-rule", arguments: { id, enabled } });
      await loadRules(activeFilter || undefined);
      if (selectedRule?.id === id) {
        const result = await appRef.current.callServerTool({ name: "get-rule", arguments: { id } });
        const text = extractCallResult(result);
        if (text) setSelectedRule(JSON.parse(text));
      }
    } catch (e) { console.error("Failed to toggle rule:", e); }
  }, [loadRules, activeFilter, selectedRule?.id]);

  const validateQuery = useCallback(async (query: string, language: string) => {
    if (!appRef.current) return { valid: false, error: "Not connected" };
    try {
      const result = await appRef.current.callServerTool({ name: "validate-query", arguments: { query, language } });
      const text = extractCallResult(result);
      if (text) return JSON.parse(text);
      return { valid: false, error: "No response" };
    } catch (e) {
      return { valid: false, error: e instanceof Error ? e.message : String(e) };
    }
  }, []);

  const loadNoisyRules = useCallback(async () => {
    if (!appRef.current) return;
    setView("noisy");
    setSelectedRule(null);
    setNoisyLoading(true);
    setNoisyRules([]);
    try {
      const result = await appRef.current.callServerTool({ name: "noisy-rules", arguments: { days: 7, limit: 20 } });
      const text = extractCallResult(result);
      if (text) setNoisyRules(JSON.parse(text));
    } catch (e) { console.error("Failed to load noisy rules:", e); }
    finally { setNoisyLoading(false); }
  }, []);

  const goBackToList = useCallback(() => {
    setView("list");
    setSelectedRule(null);
  }, []);

  const runSearch = useCallback((q: string) => {
    setActiveFilter(q.trim());
    loadRules(q.trim() || undefined);
  }, [loadRules]);

  const clearSearch = useCallback(() => {
    setSearchInput("");
    setActiveFilter("");
    loadRules(undefined);
  }, [loadRules]);

  const filteredRules = useMemo(() => {
    let arr = rules;
    if (statusFilter === "enabled") arr = arr.filter((r) => r.enabled);
    if (statusFilter === "disabled") arr = arr.filter((r) => !r.enabled);
    const sorted = [...arr];
    switch (sortBy) {
      case "severity":
        sorted.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
        break;
      case "name":
        sorted.sort((a, b) => a.name.localeCompare(b.name));
        break;
      case "risk":
        sorted.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
        break;
      case "updated":
        sorted.sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());
        break;
      case "enabled":
        sorted.sort((a, b) => Number(b.enabled) - Number(a.enabled));
        break;
    }
    return sorted;
  }, [rules, statusFilter, sortBy]);

  // Group filtered rules by the selected key. A rule can land in multiple buckets
  // when grouping by tag (since a rule may carry several tags).
  const groupedRules = useMemo(() => {
    if (groupBy === "none") return null;
    const buckets = new Map<string, {
      key: string;
      name: string;
      subtitle?: string;
      topSeverity: SeverityKey;
      rules: DetectionRule[];
    }>();
    const add = (key: string, name: string, subtitle: string | undefined, r: DetectionRule) => {
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { key, name, subtitle, topSeverity: "low", rules: [] };
        buckets.set(key, bucket);
      }
      bucket.rules.push(r);
      const rs = (r.severity?.toLowerCase() || "low") as SeverityKey;
      if ((SEV_RANK[rs] || 0) > (SEV_RANK[bucket.topSeverity] || 0)) bucket.topSeverity = rs;
    };
    for (const r of filteredRules) {
      if (groupBy === "severity") {
        const s = (r.severity?.toLowerCase() || "low") as SeverityKey;
        add(s, SEVERITY_LABEL[s], undefined, r);
      } else if (groupBy === "type") {
        const t = r.type || "unknown";
        add(t, t, undefined, r);
      } else if (groupBy === "language") {
        const l = r.language || "kuery";
        add(l, l, undefined, r);
      } else if (groupBy === "tag") {
        const tags = r.tags || [];
        if (tags.length === 0) {
          add("__none__", "No tag", undefined, r);
        } else {
          for (const t of tags) add(t, t, tags.length > 1 ? `${tags.length} tags on this rule` : undefined, r);
        }
      }
    }
    return [...buckets.values()].sort((a, b) => {
      const d = (SEV_RANK[b.topSeverity] || 0) - (SEV_RANK[a.topSeverity] || 0);
      if (d !== 0) return d;
      const c = b.rules.length - a.rules.length;
      if (c !== 0) return c;
      return a.name.localeCompare(b.name);
    });
  }, [filteredRules, groupBy]);

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
    setOpenGroups(new Set());
    setGroupMenuOpen(false);
  }, []);

  const summary = useMemo(() => {
    const bySeverity: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    let enabled = 0;
    let disabled = 0;
    rules.forEach((r) => {
      const s = (r.severity?.toLowerCase() || "low") as SeverityKey;
      if (s in bySeverity) bySeverity[s]++;
      if (r.enabled) enabled++; else disabled++;
    });
    return { bySeverity, enabled, disabled };
  }, [rules]);

  if (!connected) {
    return <div className="loading-state"><div className="loading-spinner" />Connecting…</div>;
  }

  const hasDetail = view === "detail" && !!selectedRule;
  const showingNoisy = view === "noisy";

  return (
    <div className="rules-app">
      <header className="rules-header">
        <div className="rules-header-left">
          <div className="rules-header-brand">
            <span className="rules-header-glyph" aria-hidden="true"><AppGlyph /></span>
            <h1 className="rules-header-title">Detection Rules</h1>
          </div>
          {activeFilter && (
            <span className="query-pill">
              {activeFilter}
              <button onClick={clearSearch} aria-label="Clear filter">
                <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                  <path d="m7.293 8-3.147 3.146a.5.5 0 0 0 .708.708L8 8.707l3.146 3.147a.5.5 0 0 0 .708-.708L8.707 8l3.147-3.146a.5.5 0 1 0-.708-.708L8 7.293 4.854 4.146a.5.5 0 1 0-.708.708L7.293 8Z" />
                </svg>
              </button>
            </span>
          )}
        </div>
        <div className="rules-header-actions">
          <div className="rules-status-tabs">
            {STATUS_FILTERS.map((s) => (
              <button
                key={s.key}
                type="button"
                className={`rules-status-tab${statusFilter === s.key ? " active" : ""}`}
                onClick={() => setStatusFilter(s.key)}
              >
                {s.label}
              </button>
            ))}
          </div>
          <div className="rules-status-dropdown" ref={statusRef}>
            <button
              type="button"
              className="rules-status-dropdown-trigger"
              onClick={() => setStatusMenuOpen((v) => !v)}
              aria-haspopup="listbox"
              aria-expanded={statusMenuOpen}
            >
              <span>Status: <span className="rules-status-dropdown-value">{STATUS_FILTERS.find((s) => s.key === statusFilter)?.label ?? "All"}</span></span>
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: statusMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                <path d="M2 3.5 5 6.5 8 3.5" />
              </svg>
            </button>
            {statusMenuOpen && (
              <div className="rules-status-dropdown-menu" role="listbox">
                {STATUS_FILTERS.map((s) => (
                  <button
                    key={s.key}
                    type="button"
                    role="option"
                    aria-selected={s.key === statusFilter}
                    className={`rules-status-dropdown-option${s.key === statusFilter ? " active" : ""}`}
                    onClick={() => { setStatusFilter(s.key); setStatusMenuOpen(false); }}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="rules-header-search">
            <SearchIcon />
            <input
              type="text"
              placeholder="KQL filter…"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") runSearch(searchInput);
                if (e.key === "Escape") { setSearchInput(""); clearSearch(); }
              }}
            />
          </div>
          <button type="button" className="rules-header-ghost-btn" onClick={loadNoisyRules} disabled={noisyLoading}>
            {noisyLoading ? "Loading…" : "Noisy Rules"}
          </button>
          <button
            type="button"
            className="rules-header-icon-btn"
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

      <div className="rules-body">
        <div className={`rules-list-pane ${hasDetail || showingNoisy ? "narrow" : ""}`}>
          {(hasDetail || showingNoisy) && (
            <button
              type="button"
              className="rules-list-back"
              onClick={goBackToList}
            >
              <span aria-hidden="true">&larr;</span> Back to list
            </button>
          )}

          {!hasDetail && !showingNoisy && rules.length > 0 && (
            <div className="rules-kpi-strip">
              <div className="summary-section">
                <div className="summary-section-title">By severity</div>
                <SeverityDonut bySeverity={summary.bySeverity} />
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">Total rules</div>
                <div className="kpi-tile-value">{total || rules.length}</div>
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">Enabled</div>
                <div className="kpi-tile-value">{summary.enabled}</div>
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">Disabled</div>
                <div className="kpi-tile-value">{summary.disabled}</div>
              </div>
            </div>
          )}

          {!hasDetail && !showingNoisy && rules.length > 0 && (
            <div className="rules-list-subheader">
              <div className="rules-list-subheader-left">
                <span className="rules-list-subheader-count">
                  Showing <strong>{filteredRules.length}</strong> rule{filteredRules.length !== 1 ? "s" : ""}
                  {total > filteredRules.length && <> of <strong>{total}</strong></>}
                </span>
                <div className="rules-list-subheader-sort" ref={sortRef}>
                  <button
                    type="button"
                    className="rules-list-subheader-sort-trigger"
                    onClick={() => setSortMenuOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={sortMenuOpen}
                  >
                    <span>Sort by: <span className="rules-list-subheader-sort-value">{SORT_LABEL[sortBy]}</span></span>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: sortMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                      <path d="M2.5 3.75L5 6.25L7.5 3.75" />
                    </svg>
                  </button>
                  {sortMenuOpen && (
                    <div className="rules-list-subheader-sort-menu" role="listbox">
                      {(Object.keys(SORT_LABEL) as SortKey[]).map((k) => (
                        <button
                          key={k}
                          type="button"
                          role="option"
                          aria-selected={k === sortBy}
                          className={`rules-list-subheader-sort-option${k === sortBy ? " active" : ""}`}
                          onClick={() => { setSortBy(k); setSortMenuOpen(false); }}
                        >
                          {SORT_LABEL[k]}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              <div className="rules-list-subheader-controls">
                <label className="rules-list-subheader-toggle">
                  <span className="rules-list-subheader-toggle-label">Details</span>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={showDetails}
                    aria-label="Toggle rule details"
                    className={`toggle-switch${showDetails ? " on" : ""}`}
                    onClick={() => setShowDetails((v) => !v)}
                  >
                    <span className="toggle-switch-thumb" />
                  </button>
                </label>
                <div className="rules-list-subheader-sort" ref={groupRef}>
                  <button
                    type="button"
                    className="rules-list-subheader-sort-trigger"
                    onClick={() => setGroupMenuOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={groupMenuOpen}
                  >
                    <span>Group by: <span className="rules-list-subheader-sort-value">{GROUP_LABEL[groupBy]}</span></span>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: groupMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                      <path d="M2.5 3.75L5 6.25L7.5 3.75" />
                    </svg>
                  </button>
                  {groupMenuOpen && (
                    <div className="rules-list-subheader-sort-menu rules-list-subheader-sort-menu-right" role="listbox">
                      {(Object.keys(GROUP_LABEL) as GroupKey[]).map((k) => (
                        <button
                          key={k}
                          type="button"
                          role="option"
                          aria-selected={k === groupBy}
                          className={`rules-list-subheader-sort-option${k === groupBy ? " active" : ""}`}
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

          <div className="rules-list-content">
            {listLoading && !rules.length ? (
              <div className="loading-state"><div className="loading-spinner" />Loading rules…</div>
            ) : !rules.length ? (
              <div className="empty-state">{activeFilter ? `No rules matching "${activeFilter}"` : "No rules available"}</div>
            ) : groupedRules ? (
              groupedRules.length === 0 ? (
                <div className="empty-state">No rules have a {GROUP_LABEL[groupBy].toLowerCase()} to group by.</div>
              ) : (
                groupedRules.map((group, gi) => {
                  const expanded = openGroups.has(group.key);
                  return (
                    <div key={group.key} className="animate-in" style={{ "--i": gi } as React.CSSProperties}>
                      <RuleGroupCard
                        group={group}
                        groupBy={groupBy}
                        expanded={expanded}
                        onToggle={() => toggleGroup(group.key)}
                      />
                      {expanded && (
                        <div className={`group-children sev-${group.topSeverity}`}>
                          {group.rules.map((r) => (
                            <RuleCard
                              key={`${group.key}-${r.id}`}
                              rule={r}
                              compact={hasDetail || showingNoisy}
                              selected={selectedRule?.id === r.id}
                              showDetails={showDetails}
                              onClick={() => openRule(r.id)}
                              onToggle={(enabled) => toggleRule(r.id, enabled)}
                            />
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })
              )
            ) : (
              filteredRules.map((r, i) => (
                <div key={r.id} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
                  <RuleCard
                    rule={r}
                    compact={hasDetail || showingNoisy}
                    selected={selectedRule?.id === r.id}
                    showDetails={showDetails}
                    onClick={() => openRule(r.id)}
                    onToggle={(enabled) => toggleRule(r.id, enabled)}
                  />
                </div>
              ))
            )}
          </div>
        </div>

        {hasDetail && selectedRule && (
          <div className="detail-pane">
            <button
              type="button"
              className="detail-pane-close"
              onClick={goBackToList}
              aria-label="Close rule details"
            >
              <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <path d="m7.293 8-3.147 3.146a.5.5 0 0 0 .708.708L8 8.707l3.146 3.147a.5.5 0 0 0 .708-.708L8.707 8l3.147-3.146a.5.5 0 1 0-.708-.708L8 7.293 4.854 4.146a.5.5 0 1 0-.708.708L7.293 8Z" />
              </svg>
            </button>
            <RuleDetailView
              key={selectedRule.id}
              rule={selectedRule}
              onToggle={(enabled) => toggleRule(selectedRule.id, enabled)}
              onValidate={validateQuery}
            />
          </div>
        )}

        {showingNoisy && (
          <div className="detail-pane">
            <button
              type="button"
              className="detail-pane-close"
              onClick={goBackToList}
              aria-label="Close noisy rules"
            >
              <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <path d="m7.293 8-3.147 3.146a.5.5 0 0 0 .708.708L8 8.707l3.146 3.147a.5.5 0 0 0 .708-.708L8.707 8l3.147-3.146a.5.5 0 1 0-.708-.708L8 7.293 4.854 4.146a.5.5 0 1 0-.708.708L7.293 8Z" />
              </svg>
            </button>
            <NoisyRulesView loading={noisyLoading} rows={noisyRules} />
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Group Card ──────────────────────────────────────────────────────────────

function RuleGroupCard({ group, groupBy, expanded, onToggle }: {
  group: {
    key: string;
    name: string;
    subtitle?: string;
    topSeverity: SeverityKey;
    rules: DetectionRule[];
  };
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
          rules: <span className="group-card-count-value">{group.rules.length}</span>
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

// ─── Rule Card ───────────────────────────────────────────────────────────────

function RuleCard({ rule, compact, selected, showDetails = true, onClick, onToggle }: {
  rule: DetectionRule; compact?: boolean; selected?: boolean; showDetails?: boolean;
  onClick?: () => void; onToggle?: (enabled: boolean) => void;
}) {
  const sev = (rule.severity?.toLowerCase() || "low") as SeverityKey;
  const tacticName = rule.threat?.[0]?.tactic?.name;
  const techniqueId = rule.threat?.[0]?.technique?.[0]?.id;
  const firstIndex = rule.index?.[0];

  return (
    <div
      className={`rule-card sev-${sev}${compact ? " compact" : ""}${selected ? " selected" : ""}${rule.enabled ? " enabled" : " disabled"}`}
      onClick={onClick}
    >
      <div className="rule-card-main">
        <div className="rule-card-head">
          <div className="rule-card-tags">
            <SeverityChip severity={sev} />
            <span className={`rule-status-tag rule-status-tag-${rule.enabled ? "on" : "off"}`}>
              {rule.enabled ? "Enabled" : "Disabled"}
            </span>
            <span className="rule-type-pill">{rule.type}</span>
            {tacticName && <span className="rule-mitre-pill">{tacticName}</span>}
            {techniqueId && <span className="rule-mitre-pill rule-mitre-pill-technique">{techniqueId}</span>}
          </div>
          <div className="rule-card-titles">
            <div className="rule-card-title">{rule.name}</div>
            {rule.description && (
              <div className="rule-card-reason">{rule.description}</div>
            )}
          </div>
        </div>

        <div className="rule-card-meta">
          <span className="rule-card-meta-item">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><circle cx="8" cy="8" r="5.5"/><path d="M8 4v4l2.5 2.5" strokeLinecap="round"/></svg>
            Risk {rule.risk_score}
          </span>
          {firstIndex && (
            <span className="rule-card-meta-item rule-card-meta-creator">
              <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="M2 4.5 a 1 1 0 0 1 1 -1 h10 a1 1 0 0 1 1 1 v7 a1 1 0 0 1 -1 1 h-10 a1 1 0 0 1 -1 -1 z" strokeLinejoin="round"/></svg>
              {firstIndex}{rule.index && rule.index.length > 1 ? ` +${rule.index.length - 1}` : ""}
            </span>
          )}
          <span className="rule-card-meta-item">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="M3 7h10M3 11h7" strokeLinecap="round"/></svg>
            Updated {formatDateShort(rule.updated_at)}
          </span>
        </div>

        {!compact && showDetails && (
          <div className="rule-card-facts">
            <div className="fact-row">
              <span className="fact-label">LANGUAGE</span>
              <span className="fact-value">{rule.language || "kuery"}</span>
            </div>
            <div className="fact-row">
              <span className="fact-label">CREATED BY</span>
              <span className="fact-value">{rule.created_by || "—"}</span>
            </div>
            {rule.tags && rule.tags.length > 0 && (
              <div className="fact-row">
                <span className="fact-label">TAGS</span>
                <span className="fact-value">{rule.tags.join(", ")}</span>
              </div>
            )}
          </div>
        )}
      </div>

      <button
        type="button"
        className={`rule-card-switch${rule.enabled ? " on" : ""}`}
        aria-checked={rule.enabled}
        role="switch"
        aria-label={rule.enabled ? "Disable rule" : "Enable rule"}
        onClick={(e) => { e.stopPropagation(); onToggle?.(!rule.enabled); }}
      >
        <span className="rule-card-switch-thumb" />
      </button>
    </div>
  );
}

// ─── Rule Detail View ───────────────────────────────────────────────────────

function RuleDetailView({ rule, onToggle, onValidate }: {
  rule: DetectionRule;
  onToggle: (enabled: boolean) => void;
  onValidate: (q: string, lang: string) => Promise<{ valid: boolean; error?: string }>;
}) {
  const [testOpen, setTestOpen] = useState(false);
  const [indicesOpen, setIndicesOpen] = useState(false);
  const sev = (rule.severity?.toLowerCase() || "low") as SeverityKey;
  const hasIndices = rule.index && rule.index.length > 0;

  return (
    <div className="rule-detail">
      <div className="rule-detail-top">
        <SeverityChip severity={sev} />
        <button
          type="button"
          className={`rule-detail-action${rule.enabled ? " rule-detail-action-danger" : ""}`}
          onClick={() => onToggle(!rule.enabled)}
        >
          {rule.enabled ? "Disable rule" : "Enable rule"}
        </button>
      </div>

      <div className="rule-detail-head">
        <div className="rule-card-tags">
          <span className={`rule-status-tag rule-status-tag-${rule.enabled ? "on" : "off"}`}>
            {rule.enabled ? "Enabled" : "Disabled"}
          </span>
          <span className="rule-type-pill">{rule.type}</span>
          {rule.tags?.map((t) => (
            <span key={t} className="rule-mitre-pill">{t}</span>
          ))}
        </div>
        <h2 className="rule-detail-title">{rule.name}</h2>
      </div>

      <div className="rule-detail-facts">
        <FactCol label="TYPE" value={rule.type} />
        <FactCol label="SEVERITY" value={SEVERITY_LABEL[sev]} />
        <FactCol label="RISK" value={String(rule.risk_score)} />
        <FactCol label="LANGUAGE" value={rule.language || "kuery"} />
        <FactCol label="UPDATED" value={formatDateShort(rule.updated_at)} />
      </div>

      {rule.description && (
        <div className="rule-detail-description">
          <div className="rule-detail-description-label">Description</div>
          <div className="rule-detail-description-body">{rule.description}</div>
        </div>
      )}

      {rule.threat && rule.threat.length > 0 && (
        <div className="rule-detail-description">
          <div className="rule-detail-description-label">MITRE ATT&amp;CK</div>
          <div className="rule-card-tags" style={{ marginTop: 4 }}>
            {rule.threat.flatMap((t, ti) => {
              const items: React.ReactNode[] = [];
              if (t.tactic?.name) items.push(
                <span key={`tac-${ti}`} className="rule-mitre-pill">{t.tactic.name}</span>
              );
              t.technique?.forEach((te, tei) => {
                if (te.id) items.push(
                  <span key={`tec-${ti}-${tei}`} className="rule-mitre-pill rule-mitre-pill-technique">{te.id}{te.name ? ` · ${te.name}` : ""}</span>
                );
              });
              return items;
            })}
          </div>
        </div>
      )}

      {rule.query && (
        <section className="rule-detail-section">
          <div className="rule-detail-section-head">
            <span className="rule-detail-section-title">Query</span>
            <span className="rule-detail-section-count">{rule.language || "kuery"}</span>
          </div>
          <pre className="rule-query-block">{rule.query}</pre>
          <button
            type="button"
            className="rule-detail-expand"
            onClick={() => setTestOpen((v) => !v)}
          >
            <span>{testOpen ? "Hide validator" : "Validate query"}</span>
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: testOpen ? "rotate(90deg)" : "none", transition: "transform 0.15s" }}>
              <path d="M4.5 3l3 3-3 3" />
            </svg>
          </button>
          {testOpen && (
            <RuleTestPanel
              query={rule.query}
              language={rule.language || "kuery"}
              onValidate={onValidate}
            />
          )}
        </section>
      )}

      {hasIndices && (
        <section className="rule-detail-section">
          <div className="rule-detail-section-head">
            <span className="rule-detail-section-title">Index patterns</span>
            <span className="rule-detail-section-count">{rule.index!.length}</span>
          </div>
          <div className="rule-index-grid">
            {(indicesOpen ? rule.index! : rule.index!.slice(0, 4)).map((i) => (
              <span key={i} className="rule-index-pill">{i}</span>
            ))}
          </div>
          {rule.index!.length > 4 && (
            <button
              type="button"
              className="rule-detail-expand"
              onClick={() => setIndicesOpen((v) => !v)}
            >
              <span>{indicesOpen ? "Collapse" : `Expand (${rule.index!.length - 4} more)`}</span>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: indicesOpen ? "rotate(90deg)" : "none", transition: "transform 0.15s" }}>
                <path d="M4.5 3l3 3-3 3" />
              </svg>
            </button>
          )}
        </section>
      )}
    </div>
  );
}

function FactCol({ label, value }: { label: string; value?: string }) {
  return (
    <div className="rule-detail-fact">
      <div className="rule-detail-fact-label">{label}</div>
      <div className="rule-detail-fact-value" title={value || undefined}>{value || "—"}</div>
    </div>
  );
}

// ─── Noisy Rules ────────────────────────────────────────────────────────────

function NoisyRulesView({ loading, rows }: { loading: boolean; rows: NoisyRuleRow[] }) {
  const max = rows[0]?.alertCount || 1;
  return (
    <div className="rule-detail">
      <div className="rule-detail-head">
        <h2 className="rule-detail-title">Noisy rules</h2>
        <div className="rule-detail-subtitle">Ranked by alert volume over the last 7 days. Use this to tune or disable high-chatter rules.</div>
      </div>
      {loading ? (
        <div className="loading-state"><div className="loading-spinner" />Loading volume data…</div>
      ) : rows.length === 0 ? (
        <div className="empty-state">No noisy-rule data available for this window.</div>
      ) : (
        <div className="noisy-list">
          {rows.map((r, i) => (
            <div key={r.ruleId} className="noisy-row animate-in" style={{ "--i": Math.min(i, 12) } as React.CSSProperties}>
              <div className="noisy-row-rank">{i + 1}</div>
              <div className="noisy-row-main">
                <div className="noisy-row-title" title={r.ruleName}>{r.ruleName}</div>
                <div className="summary-bar-track">
                  <div className="summary-bar-fill summary-bar-sev-medium" style={{ width: `${(r.alertCount / max) * 100}%` }} />
                </div>
              </div>
              <div className="noisy-row-count">{r.alertCount.toLocaleString()}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function formatDateShort(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "—";
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  } catch { return "—"; }
}
