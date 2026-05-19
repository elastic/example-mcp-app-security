/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { timeAgo } from "../../shared/theme";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import { renderMarkdown } from "../../shared/markdown";
import type { KibanaCase } from "../../shared/types";
import { CaseForm } from "./components/CaseForm";
import { AttachedAlertRow } from "./components/AttachedAlertRow";
import { CommentRow } from "./components/CommentRow";
import {
  AppHeader,
  AppShell,
  BackButton,
  DetailPane,
  Dropdown,
  EmptyState,
  GroupCard,
  KpiStrip,
  KpiTile,
  ListSubheader,
  LoadingState,
  QueryPill,
  SearchInput,
  SeverityChip,
  SEVERITY_LABEL,
  SEVERITY_RANK,
  SeverityDonut,
  ToastProvider,
  ToggleSwitch,
  TwoPaneLayout,
  useToast,
} from "../../shared/components";
import type { Severity } from "../../shared/components";
import { useFullscreen } from "../../shared/hooks/useFullscreen";
import { useMcpApp } from "../../shared/hooks/useMcpApp";
import "./styles.css";

type SeverityKey = Severity;
type StatusKey = "open" | "in-progress" | "closed";
/** StatusKey plus the UI-only "all" sentinel used by the filter dropdown. */
type StatusFilterKey = StatusKey | "all";
type SortKey = "severity" | "newest" | "oldest" | "title" | "alerts" | "comments";
type GroupKey = "none" | "status" | "severity" | "creator" | "tag";
const GROUP_OPTIONS: { value: GroupKey; label: string }[] = [
  { value: "none", label: "None" },
  { value: "status", label: "Status" },
  { value: "severity", label: "Severity" },
  { value: "creator", label: "Creator" },
  { value: "tag", label: "Tag" },
];
const GROUP_LABEL: Record<GroupKey, string> = Object.fromEntries(
  GROUP_OPTIONS.map((o) => [o.value, o.label]),
) as Record<GroupKey, string>;

const SEV_RANK = SEVERITY_RANK;

const STATUS_ORDER: StatusFilterKey[] = ["all", "open", "in-progress", "closed"];
const STATUS_LABEL: Record<StatusFilterKey, string> = {
  all: "All", open: "Open", "in-progress": "In progress", closed: "Closed",
};
const STATUS_OPTIONS: { value: StatusFilterKey; label: string }[] = STATUS_ORDER.map((s) => ({
  value: s,
  label: STATUS_LABEL[s],
}));

const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: "severity", label: "Severity" },
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "title", label: "Title" },
  { value: "alerts", label: "Alert count" },
  { value: "comments", label: "Comment count" },
];

type ViewMode = "browse" | "create";

interface CaseListParams {
  status?: string;
  search?: string;
  /**
   * Kibana space ID echoed from the model's `manage-cases` tool result.
   * Forwarded on every follow-up `app.callServerTool(...)` so the UI's
   * subsequent reads / writes target the same space the model picked.
   */
  namespace?: string;
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
  return (
    <ToastProvider>
      <AppContent />
    </ToastProvider>
  );
}

function AppContent() {
  const [cases, setCases] = useState<KibanaCase[]>([]);
  const [total, setTotal] = useState(0);
  const [selectedCase, setSelectedCase] = useState<KibanaCase | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>("browse");
  const [loading, setLoading] = useState(true);
  const [searchInput, setSearchInput] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilterKey>("open");
  const [showDetails, setShowDetails] = useState(false);
  const [sortBy, setSortBy] = useState<SortKey>("severity");
  const [groupBy, setGroupBy] = useState<GroupKey>("none");
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const [caseContext, setCaseContext] = useState<{ alerts: unknown[]; comments: unknown[] } | null>(null);
  const [contextLoading, setContextLoading] = useState(false);
  const paramsRef = useRef<CaseListParams>({ status: "open" });

  const loadCasesImpl = useCallback(async (mcpApp: McpApp, override?: Partial<CaseListParams>) => {
    setLoading(true);
    try {
      if (override) {
        paramsRef.current = { ...paramsRef.current, ...override };
        if (override.status !== undefined) setStatusFilter(override.status as StatusFilterKey);
      }
      const { status, search, namespace } = paramsRef.current;
      const result = await mcpApp.callServerTool({
        name: "list-cases",
        arguments: {
          status: status === "all" ? undefined : status,
          search: search?.trim() || undefined,
          perPage: 50,
          namespace,
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

  const { connected, getApp } = useMcpApp({
    name: "case-management",
    version: "1.0.0",
    onToolResult: (result, app) => {
      try {
        const text = extractToolText(result);
        if (text) {
          const data = JSON.parse(text) as { params?: { status?: string; search?: string; namespace?: string } };
          if (data.params) {
            const next: Partial<CaseListParams> = {};
            if (data.params.status) next.status = data.params.status;
            if (data.params.search !== undefined) {
              next.search = data.params.search || undefined;
              if (data.params.search) setSearchInput(data.params.search);
            }
            if (data.params.namespace !== undefined) next.namespace = data.params.namespace;
            paramsRef.current = { ...paramsRef.current, ...next };
            if (next.status) setStatusFilter(next.status as StatusKey);
          }
        }
      } catch { /* ignore */ }
      loadCasesImpl(app);
    },
    onConnect: (app, gotResult) => {
      if (!gotResult) loadCasesImpl(app);
    },
  });

  const fullscreen = useFullscreen(getApp);
  const toast = useToast();

  const loadCases = useCallback((override?: Partial<CaseListParams>) => {
    const app = getApp();
    if (app) loadCasesImpl(app, override);
  }, [getApp, loadCasesImpl]);

  const openCase = useCallback(async (caseId: string) => {
    const app = getApp();
    if (!app) return;
    setContextLoading(true);
    setCaseContext(null);
    try {
      const ns = paramsRef.current.namespace;
      const result = await app.callServerTool({
        name: "get-case",
        arguments: { caseId, namespace: ns },
      });
      const text = extractCallResult(result);
      if (text) {
        const parsed = normalizeCase(JSON.parse(text));
        if (parsed) {
          setSelectedCase(parsed);
          setViewMode("browse");
        }
      }
      try {
        const [alertsR, commentsR] = await Promise.all([
          app.callServerTool({ name: "get-case-alerts", arguments: { caseId, namespace: ns } }),
          app.callServerTool({ name: "get-case-comments", arguments: { caseId, namespace: ns } }),
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
  }, [getApp]);

  const createCase = useCallback(async (data: { title: string; description: string; tags: string; severity: string }) => {
    const app = getApp();
    if (!app) return;
    try {
      await app.callServerTool({
        name: "create-case",
        arguments: { ...data, namespace: paramsRef.current.namespace },
      });
      setViewMode("browse");
      setSelectedCase(null);
      loadCases();
      toast.show({
        message: `Case created: "${data.title}".`,
        tone: "success",
      });
    } catch (e) {
      console.error("Failed to create case:", e);
      toast.show({ message: "Couldn't create case — see console.", tone: "danger" });
    }
  }, [getApp, loadCases, toast]);

  const updateCaseStatus = useCallback(async (caseId: string, version: string, status: string) => {
    const app = getApp();
    if (!app) return;
    try {
      await app.callServerTool({
        name: "update-case",
        arguments: {
          caseId,
          version,
          status,
          namespace: paramsRef.current.namespace,
        },
      });
      loadCases();
      if (selectedCase?.id === caseId) await openCase(caseId);
    } catch (e) {
      console.error("Failed to update case:", e);
    }
  }, [getApp, loadCases, openCase, selectedCase?.id]);

  const handleSearch = useCallback((q: string) => {
    loadCases({ search: q.trim() || undefined });
  }, [loadCases]);

  const clearSearch = useCallback(() => {
    setSearchInput("");
    loadCases({ search: undefined });
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
    return <LoadingState>Connecting…</LoadingState>;
  }

  const activeSearch = paramsRef.current.search;
  const hasDetail = !!selectedCase && viewMode === "browse";
  const isCreating = viewMode === "create";
  const updatedTodayCount = cases.filter((c) => {
    if (!c.updated_at) return false;
    const d = new Date(c.updated_at).getTime();
    return Date.now() - d < 24 * 60 * 60 * 1000;
  }).length;

  const list = (
    <>
      {(hasDetail || isCreating) && (
        <BackButton
          onClick={() => {
            setSelectedCase(null);
            setViewMode("browse");
          }}
        />
      )}

      {!hasDetail && !isCreating && cases.length > 0 && (
        <KpiStrip
          className="cases-kpi-strip"
          tileCount={3}
          summary={
            <>
              <div className="summary-section-title">By severity</div>
              <SeverityDonut bySeverity={summary.bySeverity} />
            </>
          }
        >
          <KpiTile
            label="Open"
            value={summary.byStatus.open}
            meta={`+${summary.byStatus["in-progress"]} in progress`}
          />
          <KpiTile label="Closed" value={summary.byStatus.closed} />
          <KpiTile label="Updated today" value={updatedTodayCount} />
        </KpiStrip>
      )}

      {!hasDetail && !isCreating && cases.length > 0 && (
        <ListSubheader
          left={
            <>
              <span className="list-subheader-count">
                Showing <strong>{cases.length}</strong> case{cases.length !== 1 ? "s" : ""}
              </span>
              <Dropdown<SortKey>
                label="Sort by:"
                options={SORT_OPTIONS}
                value={sortBy}
                onChange={setSortBy}
              />
            </>
          }
          right={
            <>
              <ToggleSwitch
                label="Details"
                checked={showDetails}
                onChange={setShowDetails}
                ariaLabel="Toggle case details"
              />
              <Dropdown<GroupKey>
                label="Group by:"
                options={GROUP_OPTIONS}
                value={groupBy}
                onChange={setGroupByAndReset}
                align="right"
              />
            </>
          }
        />
      )}

      <div className="case-list-content">
        {loading && !cases.length ? (
          <LoadingState>Loading cases…</LoadingState>
        ) : isCreating ? (
          <EmptyState>Fill in the form on the right to create a case.</EmptyState>
        ) : !cases.length ? (
          <EmptyState>{activeSearch ? `No cases matching "${activeSearch}"` : "No cases in this view"}</EmptyState>
        ) : groupedCases ? (
          groupedCases.length === 0 ? (
            <EmptyState>No cases have a {GROUP_LABEL[groupBy].toLowerCase()} to group by.</EmptyState>
          ) : (
            groupedCases.map((group, i) => {
              const expanded = openGroups.has(group.key);
              return (
                <div key={group.key} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
                  <GroupCard
                    name={group.name}
                    subtitle={group.subtitle}
                    topSeverity={group.topSeverity}
                    count={group.cases.length}
                    countLabel="cases"
                    expanded={expanded}
                    onToggle={() => toggleGroup(group.key)}
                    description={`Grouped by ${GROUP_LABEL[groupBy]}`}
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
    </>
  );

  let detailPane: React.ReactNode = null;
  if (hasDetail && selectedCase) {
    detailPane = (
      <DetailPane onClose={() => setSelectedCase(null)}>
        <CaseDetailView
          key={selectedCase.id}
          caseData={selectedCase}
          context={caseContext}
          contextLoading={contextLoading}
          onUpdateStatus={(s) => updateCaseStatus(selectedCase.id, selectedCase.version, s)}
          onSuggestedAction={(prompt) => {
            const liveApp = getApp();
            if (!liveApp) return;
            liveApp.sendMessage({ role: "user", content: [{ type: "text", text: prompt }] }).catch((e) => console.error("sendMessage failed:", e));
          }}
          onFilter={(q) => {
            const value = q.trim();
            if (!value) return;
            const quoted = /\s/.test(value) ? `"${value}"` : value;
            setSearchInput(quoted);
            setSelectedCase(null);
            handleSearch(quoted);
          }}
        />
      </DetailPane>
    );
  } else if (isCreating) {
    detailPane = (
      <DetailPane onClose={() => setViewMode("browse")}>
        <div className="case-create-pane">
          <CaseForm
            onSubmit={createCase}
            onCancel={() => setViewMode("browse")}
          />
        </div>
      </DetailPane>
    );
  }

  return (
    <AppShell className="cases-app">
      <AppHeader
        title="Security Cases"
        leftExtras={activeSearch ? <QueryPill label={activeSearch} onClear={clearSearch} /> : undefined}
        actions={
          <>
            <div className="cases-status-tabs">
              {STATUS_ORDER.map((s) => (
                <button
                  key={s}
                  type="button"
                  className={`cases-status-tab${statusFilter === s ? " active" : ""}`}
                  onClick={() => loadCases({ status: s })}
                >
                  {STATUS_LABEL[s]}
                </button>
              ))}
            </div>
            <div className="cases-status-dropdown-wrap">
              <Dropdown<StatusFilterKey>
                label="Status:"
                options={STATUS_OPTIONS}
                value={statusFilter}
                onChange={(s) => loadCases({ status: s })}
              />
            </div>
            <SearchInput
              value={searchInput}
              onChange={setSearchInput}
              onSubmit={handleSearch}
              onClear={clearSearch}
              placeholder="Filter"
            />
            <button
              type="button"
              className="cases-header-new-btn"
              onClick={() => { setViewMode("create"); setSelectedCase(null); }}
            >
              + New case
            </button>
          </>
        }
        fullscreen={{ isFullscreen: fullscreen.isFullscreen, onToggle: fullscreen.toggle }}
      />

      <TwoPaneLayout list={list} detail={detailPane} />
    </AppShell>
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

function CaseDetailView({ caseData, context, contextLoading, onUpdateStatus, onFilter, onSuggestedAction }: {
  caseData: KibanaCase;
  context: { alerts: unknown[]; comments: unknown[] } | null;
  contextLoading: boolean;
  onUpdateStatus: (status: string) => void;
  onFilter?: (q: string) => void;
  onSuggestedAction?: (prompt: string) => void;
}) {
  const [alertsOpen, setAlertsOpen] = useState(false);
  const [commentsOpen, setCommentsOpen] = useState(false);

  const sev = caseData.severity;
  const statusLabel = STATUS_LABEL[caseData.status];
  const creator = caseData.created_by.full_name || caseData.created_by.username;
  const descriptionHtml = useMemo(
    () => renderMarkdown(caseData.description || ""),
    [caseData.description],
  );

  const STATUS_OPTIONS: { value: StatusKey; label: string }[] = [
    { value: "open", label: STATUS_LABEL.open },
    { value: "in-progress", label: STATUS_LABEL["in-progress"] },
    { value: "closed", label: STATUS_LABEL.closed },
  ];

  return (
    <div className="case-detail">
      <div className="case-detail-top">
        <SeverityChip severity={sev} />
        <Dropdown<StatusKey>
          label="Status:"
          options={STATUS_OPTIONS}
          value={caseData.status}
          onChange={(s) => {
            if (s !== caseData.status) onUpdateStatus(s);
          }}
          align="right"
          ariaLabel="Change case status"
        />
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

      {onSuggestedAction && (
        <SuggestedActionsRow caseData={caseData} onSuggestedAction={onSuggestedAction} />
      )}

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
          <div
            className="case-detail-description-body markdown-body"
            dangerouslySetInnerHTML={{ __html: descriptionHtml }}
          />
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

function SuggestedActionsRow({ caseData, onSuggestedAction }: {
  caseData: KibanaCase;
  onSuggestedAction: (prompt: string) => void;
}) {
  const caseLabel = `case #${caseData.incremental_id ?? ""} ${JSON.stringify(caseData.title)}`.trim();
  const actions: { id: string; label: string; icon: string; prompt: string }[] = [
    {
      id: "summarize",
      label: "Summarize case",
      icon: "\u2728",
      prompt: `Summarize security ${caseLabel} — give me a concise executive summary of the current state, key findings, and what remains to be done.`,
    },
    {
      id: "next-steps",
      label: "Suggest next steps",
      icon: "\u27A1",
      prompt: `For security ${caseLabel} (status: ${caseData.status}, severity: ${caseData.severity}, ${caseData.totalAlerts} alerts) — what are the recommended next investigation steps? Be specific and actionable.`,
    },
    {
      id: "extract-iocs",
      label: "Extract IOCs",
      icon: "\u{1F50D}",
      prompt: `Extract all indicators of compromise (IOCs) from ${caseLabel}. Look at the description, attached alerts, comments, and tags. List each IOC with its type (hash, IP, domain, URL, filename) and the context it appeared in.`,
    },
    {
      id: "timeline",
      label: "Generate timeline",
      icon: "\u{1F4C5}",
      prompt: `Create a chronological investigation timeline for ${caseLabel} based on the available data — alert timestamps, case creation, status changes, and any events mentioned in comments.`,
    },
  ];

  return (
    <div className="case-suggested-actions" role="group" aria-label="Suggested AI actions">
      {actions.map((a) => (
        <button
          key={a.id}
          type="button"
          className="case-suggested-action"
          onClick={() => onSuggestedAction(a.prompt)}
        >
          <span className="case-suggested-action-icon" aria-hidden="true">{a.icon}</span>
          {a.label}
        </button>
      ))}
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

