/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme, timeAgo } from "../../shared/theme";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import type { KibanaCase } from "../../shared/types";
import { CaseForm } from "./components/CaseForm";
import "./styles.css";

type SeverityKey = "critical" | "high" | "medium" | "low";
type StatusKey = "open" | "in-progress" | "closed";
/** StatusKey plus the UI-only "all" sentinel used by the filter dropdown. */
type StatusFilterKey = StatusKey | "all";
type SortKey = "severity" | "newest" | "oldest" | "title" | "alerts" | "comments";
type GroupKey = "none" | "status" | "severity" | "creator" | "tag";
const GROUP_LABEL: Record<GroupKey, string> = {
  none: "None",
  status: "Status",
  severity: "Severity",
  creator: "Creator",
  tag: "Tag",
};

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

const STATUS_ORDER: StatusFilterKey[] = ["all", "open", "in-progress", "closed"];
const STATUS_LABEL: Record<StatusFilterKey, string> = {
  all: "All", open: "Open", "in-progress": "In progress", closed: "Closed",
};

const SORT_LABEL: Record<SortKey, string> = {
  severity: "Severity",
  newest: "Newest first",
  oldest: "Oldest first",
  title: "Title",
  alerts: "Alert count",
  comments: "Comment count",
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
    <span className={`sev-chip sev-chip-${severity}`} aria-label={`Severity: ${SEVERITY_LABEL[severity]}`}>
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
        aria-label={`Severity breakdown: ${total} cases total`}
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

type ViewMode = "browse" | "create";

interface CaseListParams {
  status?: string;
  search?: string;
}

function normalizeCase(raw: unknown): KibanaCase | null {
  if (!raw || typeof raw !== "object") return null;
  const c = raw as Record<string, unknown>;
  const created = c.created_by;
  let created_by: KibanaCase["created_by"] = { username: "" };
  if (typeof created === "string") created_by = { username: created };
  else if (created && typeof created === "object" && "username" in created) {
    const u = created as { username?: string; full_name?: string };
    created_by = { username: u.username || "", full_name: u.full_name };
  }
  const st = c.status;
  const status: KibanaCase["status"] =
    st === "open" || st === "in-progress" || st === "closed" ? st : "open";
  const sv = String(c.severity ?? "low").toLowerCase();
  const severity: KibanaCase["severity"] =
    sv === "medium" || sv === "high" || sv === "critical" || sv === "low" ? sv : "low";

  try {
    return {
      id: String(c.id),
      version: String(c.version ?? ""),
      incremental_id: typeof c.incremental_id === "number" ? c.incremental_id : undefined,
      title: String(c.title ?? ""),
      description: String(c.description ?? ""),
      status,
      severity,
      tags: Array.isArray(c.tags) ? (c.tags as string[]) : [],
      totalAlerts: Number(c.totalAlerts ?? 0),
      totalComment: Number(c.totalComment ?? 0),
      created_at: String(c.created_at ?? ""),
      created_by,
      updated_at: String(c.updated_at ?? ""),
      connector: c.connector,
      settings: c.settings,
    };
  } catch {
    return null;
  }
}

export function App() {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  const [cases, setCases] = useState<KibanaCase[]>([]);
  const [total, setTotal] = useState(0);
  const [selectedCase, setSelectedCase] = useState<KibanaCase | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>("browse");
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState("");
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [statusFilter, setStatusFilter] = useState<StatusFilterKey>("open");
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
  const [caseContext, setCaseContext] = useState<{ alerts: unknown[]; comments: unknown[] } | null>(null);
  const [contextLoading, setContextLoading] = useState(false);
  const paramsRef = useRef<CaseListParams>({ status: "open" });

  const loadCases = useCallback(async (app?: McpApp, override?: Partial<CaseListParams>) => {
    const mcpApp = app || appRef.current;
    if (!mcpApp) return;
    setLoading(true);
    try {
      if (override) {
        paramsRef.current = { ...paramsRef.current, ...override };
        if (override.status !== undefined) setStatusFilter(override.status as StatusFilterKey);
      }
      const { status, search } = paramsRef.current;
      const result = await mcpApp.callServerTool({
        name: "list-cases",
        arguments: {
          // "all" is a UI-only sentinel — the server treats a missing status
          // as "any status", which is the same thing.
          status: status === "all" ? undefined : status,
          search: search?.trim() || undefined,
          perPage: 50,
        },
      });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text) as { cases?: unknown[]; total?: number };
        const list = (data.cases || []).map(normalizeCase).filter(Boolean) as KibanaCase[];
        setCases(list);
        setTotal(data.total ?? list.length);
      }
    } catch (e) {
      console.error("Failed to load cases:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const app = new McpApp({ name: "case-management", version: "1.0.0" });
    appRef.current = app;
    applyTheme(app);

    let gotResult = false;
    app.ontoolresult = (result) => {
      gotResult = true;
      try {
        const text = extractToolText(result);
        if (text) {
          const data = JSON.parse(text) as { params?: { status?: string; search?: string } };
          if (data.params) {
            const next: Partial<CaseListParams> = {};
            if (data.params.status) next.status = data.params.status;
            if (data.params.search !== undefined) {
              next.search = data.params.search || undefined;
              if (data.params.search) setSearchInput(data.params.search);
            }
            paramsRef.current = { ...paramsRef.current, ...next };
            if (next.status) setStatusFilter(next.status as StatusKey);
          }
        }
      } catch { /* ignore */ }
      loadCases(app);
    };

    app.connect().then(() => {
      setConnected(true);
      setTimeout(() => { if (!gotResult) loadCases(app); }, 1500);
    });

    return () => { app.close(); };
  }, [loadCases]);

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

  const openCase = useCallback(async (caseId: string) => {
    if (!appRef.current) return;
    setContextLoading(true);
    setCaseContext(null);
    try {
      const result = await appRef.current.callServerTool({
        name: "get-case",
        arguments: { caseId },
      });
      const text = extractCallResult(result);
      if (text) {
        const parsed = normalizeCase(JSON.parse(text));
        if (parsed) {
          setSelectedCase(parsed);
          setViewMode("browse");
        }
      }
      // Load alerts + comments in parallel (best-effort)
      try {
        const [alertsR, commentsR] = await Promise.all([
          appRef.current.callServerTool({ name: "get-case-alerts", arguments: { caseId } }),
          appRef.current.callServerTool({ name: "get-case-comments", arguments: { caseId } }),
        ]);
        const alertsText = extractCallResult(alertsR);
        const commentsText = extractCallResult(commentsR);
        const alerts = alertsText ? JSON.parse(alertsText) : [];
        const comments = commentsText ? JSON.parse(commentsText) : [];
        setCaseContext({
          alerts: Array.isArray(alerts) ? alerts : (alerts?.alerts || []),
          comments: Array.isArray(comments) ? comments : (comments?.comments || []),
        });
      } catch { /* optional */ }
    } catch (e) {
      console.error("Failed to load case:", e);
    } finally {
      setContextLoading(false);
    }
  }, []);

  const createCase = useCallback(async (data: { title: string; description: string; tags: string; severity: string }) => {
    if (!appRef.current) return;
    try {
      await appRef.current.callServerTool({ name: "create-case", arguments: data });
      setViewMode("browse");
      setSelectedCase(null);
      await loadCases();
    } catch (e) {
      console.error("Failed to create case:", e);
    }
  }, [loadCases]);

  const updateCaseStatus = useCallback(async (caseId: string, version: string, status: string) => {
    if (!appRef.current) return;
    try {
      await appRef.current.callServerTool({
        name: "update-case",
        arguments: { caseId, version, status },
      });
      await loadCases();
      if (selectedCase?.id === caseId) await openCase(caseId);
    } catch (e) {
      console.error("Failed to update case:", e);
    }
  }, [loadCases, openCase, selectedCase?.id]);

  const handleSearch = useCallback((q: string) => {
    loadCases(undefined, { search: q.trim() || undefined });
  }, [loadCases]);

  const clearSearch = useCallback(() => {
    setSearchInput("");
    loadCases(undefined, { search: undefined });
  }, [loadCases]);

  const sortedCases = useMemo(() => {
    const arr = [...cases];
    switch (sortBy) {
      case "severity":
        arr.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
        break;
      case "newest":
        arr.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
        break;
      case "oldest":
        arr.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
        break;
      case "title":
        arr.sort((a, b) => a.title.localeCompare(b.title));
        break;
      case "alerts":
        arr.sort((a, b) => b.totalAlerts - a.totalAlerts);
        break;
      case "comments":
        arr.sort((a, b) => b.totalComment - a.totalComment);
        break;
    }
    return arr;
  }, [cases, sortBy]);

  // Group cases into buckets by the selected grouping key. Each bucket carries a display
  // name, optional subtitle, the highest-severity case in the group, and the cases themselves.
  const groupedCases = useMemo(() => {
    if (groupBy === "none") return null;
    const buckets = new Map<string, {
      key: string;
      name: string;
      subtitle?: string;
      topSeverity: SeverityKey;
      cases: KibanaCase[];
    }>();
    const add = (key: string, name: string, subtitle: string | undefined, c: KibanaCase) => {
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { key, name, subtitle, topSeverity: "low", cases: [] };
        buckets.set(key, bucket);
      }
      bucket.cases.push(c);
      if ((SEV_RANK[c.severity] || 0) > (SEV_RANK[bucket.topSeverity] || 0)) bucket.topSeverity = c.severity;
    };
    for (const c of sortedCases) {
      if (groupBy === "status") {
        add(c.status, STATUS_LABEL[c.status], `${sortedCases.filter((x) => x.status === c.status).length} cases`, c);
      } else if (groupBy === "severity") {
        add(c.severity, SEVERITY_LABEL[c.severity], undefined, c);
      } else if (groupBy === "creator") {
        const creator = c.created_by.full_name || c.created_by.username;
        if (!creator) continue;
        const username = c.created_by.username && c.created_by.username !== creator ? c.created_by.username : undefined;
        add(creator, creator, username, c);
      } else if (groupBy === "tag") {
        if (c.tags.length === 0) {
          add("__untagged__", "Untagged", undefined, c);
        } else {
          for (const tag of c.tags) add(tag, tag, `${c.tags.length === 1 ? "1 tag" : `${c.tags.length} tags`}`, c);
        }
      }
    }
    // Sort groups: highest severity first, then by case count desc, then alphabetically.
    return [...buckets.values()].sort((a, b) => {
      const d = (SEV_RANK[b.topSeverity] || 0) - (SEV_RANK[a.topSeverity] || 0);
      if (d !== 0) return d;
      const c = b.cases.length - a.cases.length;
      if (c !== 0) return c;
      return a.name.localeCompare(b.name);
    });
  }, [sortedCases, groupBy]);

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

  const summary = useMemo(() => {
    const bySeverity: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const byStatus: Record<StatusKey, number> = { open: 0, "in-progress": 0, closed: 0 };
    const tagCounts = new Map<string, number>();
    cases.forEach((c) => {
      bySeverity[c.severity]++;
      byStatus[c.status]++;
      c.tags.forEach((t) => tagCounts.set(t, (tagCounts.get(t) || 0) + 1));
    });
    const byTag = Array.from(tagCounts.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
    return { bySeverity, byStatus, byTag };
  }, [cases]);

  if (!connected) {
    return <div className="loading-state"><div className="loading-spinner" />Connecting…</div>;
  }

  const activeSearch = paramsRef.current.search;
  const hasDetail = !!selectedCase && viewMode === "browse";
  const isCreating = viewMode === "create";
  const updatedTodayCount = cases.filter((c) => {
    if (!c.updated_at) return false;
    const d = new Date(c.updated_at).getTime();
    return Date.now() - d < 24 * 60 * 60 * 1000;
  }).length;

  return (
    <div className="cases-app">
      <header className="cases-header">
        <div className="cases-header-left">
          <div className="cases-header-brand">
            <span className="cases-header-glyph" aria-hidden="true"><AppGlyph /></span>
            <h1 className="cases-header-title">Security Cases</h1>
          </div>
          {activeSearch && (
            <span className="query-pill">
              {activeSearch}
              <button onClick={clearSearch} aria-label="Clear filter">
                <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                  <path d="m7.293 8-3.147 3.146a.5.5 0 0 0 .708.708L8 8.707l3.146 3.147a.5.5 0 0 0 .708-.708L8.707 8l3.147-3.146a.5.5 0 1 0-.708-.708L8 7.293 4.854 4.146a.5.5 0 1 0-.708.708L7.293 8Z" />
                </svg>
              </button>
            </span>
          )}
        </div>
        <div className="cases-header-actions">
          <div className="cases-status-tabs">
            {STATUS_ORDER.map((s) => (
              <button
                key={s}
                type="button"
                className={`cases-status-tab${statusFilter === s ? " active" : ""}`}
                onClick={() => loadCases(undefined, { status: s })}
              >
                {STATUS_LABEL[s]}
              </button>
            ))}
          </div>
          <div className="cases-status-dropdown" ref={statusRef}>
            <button
              type="button"
              className="cases-status-dropdown-trigger"
              onClick={() => setStatusMenuOpen((v) => !v)}
              aria-haspopup="listbox"
              aria-expanded={statusMenuOpen}
            >
              <span>Status: <span className="cases-status-dropdown-value">{STATUS_LABEL[statusFilter]}</span></span>
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: statusMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                <path d="M2 3.5 5 6.5 8 3.5" />
              </svg>
            </button>
            {statusMenuOpen && (
              <div className="cases-status-dropdown-menu" role="listbox">
                {STATUS_ORDER.map((s) => (
                  <button
                    key={s}
                    type="button"
                    role="option"
                    aria-selected={s === statusFilter}
                    className={`cases-status-dropdown-option${s === statusFilter ? " active" : ""}`}
                    onClick={() => { loadCases(undefined, { status: s }); setStatusMenuOpen(false); }}
                  >
                    {STATUS_LABEL[s]}
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="cases-header-search">
            <SearchIcon />
            <input
              type="text"
              placeholder="Filter"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSearch(searchInput);
                if (e.key === "Escape") { setSearchInput(""); clearSearch(); }
              }}
            />
          </div>
          <button
            type="button"
            className="cases-header-new-btn"
            onClick={() => { setViewMode("create"); setSelectedCase(null); }}
          >
            + New case
          </button>
          <button
            type="button"
            className="cases-header-icon-btn"
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

      <div className="cases-body">
        <div className={`case-list-pane ${hasDetail || isCreating ? "narrow" : ""}`}>
          {(hasDetail || isCreating) && (
            <button
              type="button"
              className="case-list-back"
              onClick={() => {
                setSelectedCase(null);
                setViewMode("browse");
              }}
            >
              <span aria-hidden="true">&larr;</span> Back to list
            </button>
          )}

          {!hasDetail && !isCreating && cases.length > 0 && (
            <div className="cases-kpi-strip">
              <div className="summary-section">
                <div className="summary-section-title">By severity</div>
                <SeverityDonut bySeverity={summary.bySeverity} />
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">Open</div>
                <div className="kpi-tile-value-row">
                  <div className="kpi-tile-value">{summary.byStatus.open}</div>
                  <span className="kpi-tile-meta-inline">+{summary.byStatus["in-progress"]} in progress</span>
                </div>
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">Closed</div>
                <div className="kpi-tile-value">{summary.byStatus.closed}</div>
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">Updated today</div>
                <div className="kpi-tile-value">{updatedTodayCount}</div>
              </div>
            </div>
          )}

          {!hasDetail && !isCreating && cases.length > 0 && (
            <div className="case-list-subheader">
              <div className="case-list-subheader-left">
                <span className="case-list-subheader-count">
                  Showing <strong>{cases.length}</strong> case{cases.length !== 1 ? "s" : ""}
                </span>
                <div className="case-list-subheader-sort" ref={sortRef}>
                  <button
                    type="button"
                    className="case-list-subheader-sort-trigger"
                    onClick={() => setSortMenuOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={sortMenuOpen}
                  >
                    <span>Sort by: <span className="case-list-subheader-sort-value">{SORT_LABEL[sortBy]}</span></span>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: sortMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                      <path d="M2.5 3.75L5 6.25L7.5 3.75" />
                    </svg>
                  </button>
                  {sortMenuOpen && (
                    <div className="case-list-subheader-sort-menu" role="listbox">
                      {(Object.keys(SORT_LABEL) as SortKey[]).map((k) => (
                        <button
                          key={k}
                          type="button"
                          role="option"
                          aria-selected={k === sortBy}
                          className={`case-list-subheader-sort-option${k === sortBy ? " active" : ""}`}
                          onClick={() => { setSortBy(k); setSortMenuOpen(false); }}
                        >
                          {SORT_LABEL[k]}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              <div className="case-list-subheader-controls">
                <label className="case-list-subheader-toggle">
                  <span className="case-list-subheader-toggle-label">Details</span>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={showDetails}
                    aria-label="Toggle case details"
                    className={`toggle-switch${showDetails ? " on" : ""}`}
                    onClick={() => setShowDetails((v) => !v)}
                  >
                    <span className="toggle-switch-thumb" />
                  </button>
                </label>
                <div className="case-list-subheader-sort case-list-subheader-group" ref={groupRef}>
                  <button
                    type="button"
                    className="case-list-subheader-sort-trigger"
                    onClick={() => setGroupMenuOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={groupMenuOpen}
                  >
                    <span>Group by: <span className="case-list-subheader-sort-value">{GROUP_LABEL[groupBy]}</span></span>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: groupMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                      <path d="M2.5 3.75L5 6.25L7.5 3.75" />
                    </svg>
                  </button>
                  {groupMenuOpen && (
                    <div className="case-list-subheader-sort-menu case-list-subheader-sort-menu-right" role="listbox">
                      {(Object.keys(GROUP_LABEL) as GroupKey[]).map((k) => (
                        <button
                          key={k}
                          type="button"
                          role="option"
                          aria-selected={k === groupBy}
                          className={`case-list-subheader-sort-option${k === groupBy ? " active" : ""}`}
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

          <div className="case-list-content">
            {loading && !cases.length ? (
              <div className="loading-state"><div className="loading-spinner" />Loading cases…</div>
            ) : isCreating ? (
              <div className="empty-state">Fill in the form on the right to create a case.</div>
            ) : !cases.length ? (
              <div className="empty-state">{activeSearch ? `No cases matching "${activeSearch}"` : "No cases in this view"}</div>
            ) : groupedCases ? (
              groupedCases.length === 0 ? (
                <div className="empty-state">No cases have a {GROUP_LABEL[groupBy].toLowerCase()} to group by.</div>
              ) : (
                groupedCases.map((group, i) => {
                  const expanded = openGroups.has(group.key);
                  return (
                    <div key={group.key} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
                      <CaseGroupCard
                        group={group}
                        groupBy={groupBy}
                        expanded={expanded}
                        onToggle={() => toggleGroup(group.key)}
                      />
                      {expanded && (
                        <div className={`group-children sev-${group.topSeverity}`}>
                          {group.cases.map((c) => (
                            <CaseCard
                              key={`${group.key}-${c.id}`}
                              caseData={c}
                              compact={hasDetail || isCreating}
                              selected={selectedCase?.id === c.id}
                              showDetails={showDetails}
                              onClick={() => openCase(c.id)}
                              onFilter={(q) => {
                                const value = q.trim();
                                if (!value) return;
                                const quoted = /\s/.test(value) ? `"${value}"` : value;
                                setSearchInput(quoted);
                                handleSearch(quoted);
                              }}
                            />
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })
              )
            ) : (
              sortedCases.map((c, i) => (
                <div key={c.id} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
                  <CaseCard
                    caseData={c}
                    compact={hasDetail || isCreating}
                    selected={selectedCase?.id === c.id}
                    showDetails={showDetails}
                    onClick={() => openCase(c.id)}
                    onFilter={(q) => {
                      const value = q.trim();
                      if (!value) return;
                      const quoted = /\s/.test(value) ? `"${value}"` : value;
                      setSearchInput(quoted);
                      handleSearch(quoted);
                    }}
                  />
                </div>
              ))
            )}
          </div>
        </div>

        {hasDetail && selectedCase && (
          <div className="detail-pane">
            <button
              type="button"
              className="detail-pane-close"
              onClick={() => setSelectedCase(null)}
              aria-label="Close case details"
            >
              <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <path d="m7.293 8-3.147 3.146a.5.5 0 0 0 .708.708L8 8.707l3.146 3.147a.5.5 0 0 0 .708-.708L8.707 8l3.147-3.146a.5.5 0 1 0-.708-.708L8 7.293 4.854 4.146a.5.5 0 1 0-.708.708L7.293 8Z" />
              </svg>
            </button>
            <CaseDetailView
              key={selectedCase.id}
              caseData={selectedCase}
              context={caseContext}
              contextLoading={contextLoading}
              onUpdateStatus={(s) => updateCaseStatus(selectedCase.id, selectedCase.version, s)}
              onFilter={(q) => {
                const value = q.trim();
                if (!value) return;
                const quoted = /\s/.test(value) ? `"${value}"` : value;
                setSearchInput(quoted);
                setSelectedCase(null);
                handleSearch(quoted);
              }}
            />
          </div>
        )}

        {isCreating && (
          <div className="detail-pane">
            <button
              type="button"
              className="detail-pane-close"
              onClick={() => setViewMode("browse")}
              aria-label="Cancel new case"
            >
              <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <path d="m7.293 8-3.147 3.146a.5.5 0 0 0 .708.708L8 8.707l3.146 3.147a.5.5 0 0 0 .708-.708L8.707 8l3.147-3.146a.5.5 0 1 0-.708-.708L8 7.293 4.854 4.146a.5.5 0 1 0-.708.708L7.293 8Z" />
              </svg>
            </button>
            <div className="case-create-pane">
              <CaseForm onSubmit={createCase} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Group card ───────────────────────────────────────────────────────────────

interface CaseGroupBucket {
  key: string;
  name: string;
  subtitle?: string;
  topSeverity: SeverityKey;
  cases: KibanaCase[];
}

function CaseGroupCard({ group, groupBy, expanded, onToggle }: {
  group: CaseGroupBucket;
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
          cases: <span className="group-card-count-value">{group.cases.length}</span>
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

// ─── Card ─────────────────────────────────────────────────────────────────────

function CaseCard({ caseData, compact, selected, showDetails = true, onClick, onFilter }: {
  caseData: KibanaCase; compact?: boolean; selected?: boolean; showDetails?: boolean; onClick?: () => void; onFilter?: (q: string) => void;
}) {
  const sev = caseData.severity;
  const statusLabel = STATUS_LABEL[caseData.status];
  const tag = caseData.tags[0];
  const creator = caseData.created_by.full_name || caseData.created_by.username;
  const firstLine = caseData.description.split(/\r?\n/)[0];
  const caseId = caseData.incremental_id !== undefined ? `#${caseData.incremental_id}` : null;

  const filterClick = (value: string) => (e: React.MouseEvent) => {
    if (!onFilter) return;
    e.stopPropagation();
    onFilter(value);
  };

  return (
    <div
      className={`case-card sev-${sev}${compact ? " compact" : ""}${selected ? " selected" : ""}`}
      onClick={onClick}
    >
      <div className="case-card-main">
        <div className="case-card-head">
          <div className="case-card-tags">
            <SeverityChip severity={sev} />
            <span className={`case-status-tag case-status-tag-${caseData.status}`}>{statusLabel}</span>
            {tag && <span className="case-tag-pill">{tag}</span>}
            {caseData.tags.length > 1 && <span className="case-tag-pill case-tag-pill-muted">+{caseData.tags.length - 1}</span>}
          </div>
          <div className="case-card-titles">
            <div className="case-card-title">
              {caseId && <span className="case-card-id">{caseId}</span>}
              <span className="case-card-title-text">{caseData.title}</span>
            </div>
            {firstLine && (
              <div className="case-card-reason">{firstLine}</div>
            )}
          </div>
        </div>

        {!compact && showDetails && (caseData.tags.length > 0 || creator) && (
          <div className="case-card-facts">
            {creator && (
              <div className="fact-row">
                <span className="fact-label">CREATED BY</span>
                {onFilter ? (
                  <button type="button" className="fact-value fact-value-filter" onClick={filterClick(creator)} title={`Filter by ${creator}`}>{creator}</button>
                ) : (
                  <span className="fact-value">{creator}</span>
                )}
              </div>
            )}
            <div className="fact-row">
              <span className="fact-label">ALERTS</span>
              {onFilter ? (
                <button type="button" className="fact-value fact-value-filter" onClick={filterClick(String(caseData.totalAlerts))} title="Filter by this alert count">{caseData.totalAlerts}</button>
              ) : (
                <span className="fact-value">{caseData.totalAlerts}</span>
              )}
            </div>
            <div className="fact-row">
              <span className="fact-label">COMMENTS</span>
              {onFilter ? (
                <button type="button" className="fact-value fact-value-filter" onClick={filterClick(String(caseData.totalComment))} title="Filter by this comment count">{caseData.totalComment}</button>
              ) : (
                <span className="fact-value">{caseData.totalComment}</span>
              )}
            </div>
            {caseData.tags.length > 0 && (
              <div className="fact-row">
                <span className="fact-label">TAGS</span>
                <span className="fact-value">
                  {onFilter
                    ? caseData.tags.map((t, i) => (
                        <React.Fragment key={t}>
                          {i > 0 && ", "}
                          <button type="button" className="fact-value-filter fact-value-filter-inline" onClick={filterClick(t)} title={`Filter by ${t}`}>{t}</button>
                        </React.Fragment>
                      ))
                    : caseData.tags.join(", ")}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="case-card-time">{timeAgo(caseData.created_at)}</div>
    </div>
  );
}

// ─── Detail view ─────────────────────────────────────────────────────────────

const ALERTS_PREVIEW = 3;
const COMMENTS_PREVIEW = 3;

function CaseDetailView({ caseData, context, contextLoading, onUpdateStatus, onFilter }: {
  caseData: KibanaCase;
  context: { alerts: unknown[]; comments: unknown[] } | null;
  contextLoading: boolean;
  onUpdateStatus: (status: string) => void;
  onFilter?: (q: string) => void;
}) {
  const [alertsOpen, setAlertsOpen] = useState(false);
  const [commentsOpen, setCommentsOpen] = useState(false);

  const sev = caseData.severity;
  const statusLabel = STATUS_LABEL[caseData.status];
  const creator = caseData.created_by.full_name || caseData.created_by.username;

  // Decide Take Action target: open → in-progress → closed → open
  const nextStatus: Record<StatusKey, { label: string; value: string }> = {
    open: { label: "Move to In Progress", value: "in-progress" },
    "in-progress": { label: "Close Case", value: "closed" },
    closed: { label: "Reopen Case", value: "open" },
  };
  const action = nextStatus[caseData.status];

  return (
    <div className="case-detail">
      <div className="case-detail-top">
        <SeverityChip severity={sev} />
        <button type="button" className="case-detail-action" onClick={() => onUpdateStatus(action.value)}>
          {action.label}
        </button>
      </div>

      <div className="case-detail-head">
        <div className="case-card-tags">
          <span className={`case-status-tag case-status-tag-${caseData.status}`}>{statusLabel}</span>
          {caseData.tags.map((t) => (
            <span key={t} className="case-tag-pill">{t}</span>
          ))}
        </div>
        <h2 className="case-detail-title">{caseData.title}</h2>
        {caseData.incremental_id !== undefined && (
          <div className="case-detail-subtitle">Case #{caseData.incremental_id}</div>
        )}
      </div>

      <div className="case-detail-facts">
        <FactCol label="STATUS" value={statusLabel} icon={FactIcon.status} />
        <FactCol label="SEVERITY" value={SEVERITY_LABEL[sev]} icon={FactIcon.severity} />
        <FactCol label="ALERTS" value={String(caseData.totalAlerts)} icon={FactIcon.alerts} onFilter={onFilter} />
        <FactCol label="COMMENTS" value={String(caseData.totalComment)} icon={FactIcon.comments} onFilter={onFilter} />
        <FactCol label="CREATED BY" value={creator} icon={FactIcon.createdBy} onFilter={onFilter} />
        <FactCol label="CREATED" value={caseData.created_at ? timeAgo(caseData.created_at) : "—"} icon={FactIcon.created} />
        <FactCol label="UPDATED" value={caseData.updated_at ? timeAgo(caseData.updated_at) : "—"} icon={FactIcon.updated} />
      </div>

      {caseData.description && (
        <div className="case-detail-description">
          <div className="case-detail-description-label">Description</div>
          <div className="case-detail-description-body">{caseData.description}</div>
        </div>
      )}

      {contextLoading ? (
        <div className="case-detail-section"><div className="loading-state"><div className="loading-spinner" />Loading case context…</div></div>
      ) : context ? (
        <>
          {context.alerts.length > 0 && (
            <ExpandSection
              title="Attached alerts"
              count={context.alerts.length}
              expanded={alertsOpen}
              onToggle={() => setAlertsOpen((v) => !v)}
              previewCount={ALERTS_PREVIEW}
            >
              <div className="case-detail-alerts">
                {(alertsOpen ? context.alerts : context.alerts.slice(0, ALERTS_PREVIEW)).map((a, i) => (
                  <AttachedAlertRow key={i} alert={a} />
                ))}
              </div>
            </ExpandSection>
          )}

          {context.comments.length > 0 && (
            <ExpandSection
              title="Comments"
              count={context.comments.length}
              expanded={commentsOpen}
              onToggle={() => setCommentsOpen((v) => !v)}
              previewCount={COMMENTS_PREVIEW}
            >
              <div className="case-detail-comments">
                {(commentsOpen ? context.comments : context.comments.slice(0, COMMENTS_PREVIEW)).map((c, i) => (
                  <CommentRow key={i} comment={c} />
                ))}
              </div>
            </ExpandSection>
          )}
        </>
      ) : null}
    </div>
  );
}

function FactCol({ label, value, icon, onFilter }: { label: string; value?: string; icon?: React.ReactNode; onFilter?: (q: string) => void }) {
  const display = value && value.length > 0 ? value : "—";
  const canFilter = !!onFilter && !!value && value.length > 0;
  return (
    <div className="case-detail-fact">
      <div className="case-detail-fact-label">
        {icon && <span className="case-detail-fact-icon" aria-hidden="true">{icon}</span>}
        <span>{label}</span>
      </div>
      {canFilter ? (
        <button
          type="button"
          className="case-detail-fact-value case-detail-fact-filter"
          title={`Filter by ${value}`}
          onClick={() => onFilter!(value!)}
        >
          {display}
        </button>
      ) : (
        <div className="case-detail-fact-value" title={value || undefined}>
          {display}
        </div>
      )}
    </div>
  );
}

// ─── Fact icons ──────────────────────────────────────────────────────────────

const FactIcon = {
  status: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <circle cx="8" cy="8" r="5.5" />
      <circle cx="8" cy="8" r="2" fill="currentColor" stroke="none" />
    </svg>
  ),
  severity: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M8 2.5 1.5 13.5h13z" />
      <path d="M8 7v3" />
      <circle cx="8" cy="12" r="0.4" fill="currentColor" stroke="none" />
    </svg>
  ),
  alerts: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 12.5V7a5 5 0 0 1 10 0v5.5z" />
      <path d="M6.5 14.5a1.5 1.5 0 0 0 3 0" />
    </svg>
  ),
  comments: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 3h10a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1H8l-3 2v-2H3a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" />
    </svg>
  ),
  createdBy: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
      <circle cx="8" cy="6" r="2.5" />
      <path d="M3 13c0-2.5 2.2-4 5-4s5 1.5 5 4" />
    </svg>
  ),
  created: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="8" cy="8" r="6" />
      <path d="M8 4.5V8l2.2 1.5" />
    </svg>
  ),
  updated: (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M13 8a5 5 0 1 1-1.5-3.5" />
      <path d="M13 2.5V5H10.5" />
    </svg>
  ),
};

function ExpandSection({ title, count, expanded, onToggle, previewCount, children }: {
  title: string; count: number; expanded: boolean; onToggle: () => void; previewCount: number; children: React.ReactNode;
}) {
  const canExpand = count > previewCount;
  return (
    <section className="case-detail-section">
      <div className="case-detail-section-head">
        <span className="case-detail-section-title">{title}</span>
        <span className="case-detail-section-count">{count}</span>
      </div>
      {children}
      {canExpand && (
        <button type="button" className="case-detail-expand" onClick={onToggle}>
          <span>{expanded ? "Collapse" : "Expand"}</span>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: expanded ? "rotate(90deg)" : "none", transition: "transform 0.15s" }}>
            <path d="M4.5 3l3 3-3 3" />
          </svg>
        </button>
      )}
    </section>
  );
}

function AttachedAlertRow({ alert }: { alert: unknown }) {
  const a = (alert || {}) as Record<string, unknown>;
  const src = ((a._source as Record<string, unknown>) || a) as Record<string, unknown>;
  const rule = String(src["kibana.alert.rule.name"] || a.ruleName || a.rule || "Unknown rule");
  const severity = String(src["kibana.alert.severity"] || a.severity || "low").toLowerCase() as SeverityKey;
  const ts = String(src["@timestamp"] || a.timestamp || "");
  return (
    <div className={`case-detail-alert-row sev-${severity}`}>
      <div className="case-detail-alert-row-main">
        <div className="case-detail-alert-row-title">{rule}</div>
        <div className="case-detail-alert-row-meta">{SEVERITY_LABEL[severity] || severity}</div>
      </div>
      {ts && <div className="case-detail-alert-row-time">{timeAgo(ts)}</div>}
    </div>
  );
}

function CommentRow({ comment }: { comment: unknown }) {
  const c = (comment || {}) as Record<string, unknown>;
  const by = (c.created_by || {}) as Record<string, unknown>;
  const author = String(by.full_name || by.username || "Unknown");
  const email = typeof by.email === "string" ? by.email : "";
  const body = String(c.comment || c.text || c.body || "");
  const ts = String(c.created_at || c.timestamp || "");
  const initials = author
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() || "")
    .join("") || "?";
  // Deterministic pastel hue from author string
  const hue = (() => {
    let h = 0;
    for (let i = 0; i < author.length; i++) h = (h * 31 + author.charCodeAt(i)) % 360;
    return h;
  })();
  return (
    <div className="case-detail-comment-row">
      <div
        className="case-detail-comment-avatar"
        style={{
          background: `hsl(${hue} 30% 22%)`,
          color: `hsl(${hue} 55% 78%)`,
          borderColor: `hsl(${hue} 30% 32%)`,
        }}
        aria-hidden="true"
      >
        {initials}
      </div>
      <div className="case-detail-comment-main">
        <div className="case-detail-comment-row-head">
          <span className="case-detail-comment-author" title={email || undefined}>{author}</span>
          <span className="case-detail-comment-sep" aria-hidden="true">·</span>
          <span className="case-detail-comment-action">commented</span>
          {ts && (
            <>
              <span className="case-detail-comment-sep" aria-hidden="true">·</span>
              <span className="case-detail-comment-time" title={ts}>{timeAgo(ts)}</span>
            </>
          )}
        </div>
        <div className="case-detail-comment-body">{body}</div>
      </div>
    </div>
  );
}
