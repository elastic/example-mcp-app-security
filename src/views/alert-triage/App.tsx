/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useEffect, useCallback, useRef } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import type { SecurityAlert, AlertSummary, AlertContext } from "../../shared/types";
import { AlertCard } from "./components/AlertCard";
import { DetailView } from "./components/DetailView";
import {
  AppHeader,
  AppShell,
  BackButton,
  Dropdown,
  EmptyState,
  GroupCard,
  ListSubheader,
  LoadingState,
  QueryPill,
  SearchInput,
  SeverityDonut,
  ToastProvider,
  ToggleSwitch,
  TwoPaneLayout,
  useToast,
} from "../../shared/components";
import { useFullscreen } from "../../shared/hooks/useFullscreen";
import { useMcpApp } from "../../shared/hooks/useMcpApp";
import { useAlertSort } from "./hooks/useAlertSort";
import type { GroupKey, SortKey } from "./hooks/useAlertSort";
import "./styles.css";

interface FilterParams {
  days: number;
  severity?: string;
  limit: number;
  query?: string;
}

const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: "severity", label: "Severity" },
  { value: "risk", label: "Risk score" },
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "rule", label: "Rule name" },
  { value: "host", label: "Host name" },
];

const GROUP_OPTIONS: { value: GroupKey; label: string }[] = [
  { value: "none", label: "None" },
  { value: "host", label: "Host" },
  { value: "user", label: "User" },
  { value: "process", label: "Process" },
];
const GROUP_LABEL: Record<GroupKey, string> = Object.fromEntries(
  GROUP_OPTIONS.map((o) => [o.value, o.label]),
) as Record<GroupKey, string>;

type LimitKey = "10" | "20" | "50" | "100";
const LIMIT_OPTIONS: { value: LimitKey; label: string }[] = [
  { value: "10", label: "10 alerts" },
  { value: "20", label: "20 alerts" },
  { value: "50", label: "50 alerts" },
  { value: "100", label: "100 alerts" },
];
const DEFAULT_LIMIT: LimitKey = "20";
const DEFAULT_LIMIT_NUM = Number.parseInt(DEFAULT_LIMIT, 10);
const isLimitKey = (v: string): v is LimitKey =>
  LIMIT_OPTIONS.some((o) => o.value === v);

export function App() {
  return (
    <ToastProvider>
      <AppContent />
    </ToastProvider>
  );
}

function AppContent() {
  const [summary, setSummary] = useState<AlertSummary | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [alertContext, setAlertContext] = useState<AlertContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [contextLoading, setContextLoading] = useState(false);
  const [searchInput, setSearchInput] = useState("");
  const [verdicts, setVerdicts] = useState<Array<{rule: string; classification: string; confidence: string; summary: string; action: string; hosts?: string[]}>>([]);
  const [showDetails, setShowDetails] = useState(false);
  const [sortBy, setSortBy] = useState<SortKey>("severity");
  const [groupBy, setGroupBy] = useState<GroupKey>("host");
  const [limit, setLimit] = useState<LimitKey>(DEFAULT_LIMIT);
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  // Lifted out of DetailView so it survives the remount triggered by `key={selectedAlert._id}`
  // when the user navigates between alerts via the Related list.
  const [relatedOpen, setRelatedOpen] = useState(false);
  const paramsRef = useRef<FilterParams>({ days: 7, limit: DEFAULT_LIMIT_NUM });
  const listRef = useRef<HTMLDivElement | null>(null);

  const loadAlertsImpl = useCallback(async (app: McpApp, overrideParams?: Partial<FilterParams>) => {
    setLoading(true);
    try {
      const args = { ...paramsRef.current, ...overrideParams };
      if (overrideParams) paramsRef.current = { ...paramsRef.current, ...overrideParams };
      const result = await app.callServerTool({ name: "poll-alerts", arguments: args });
      const text = extractCallResult(result);
      if (text) setSummary(JSON.parse(text));
    } catch (e) {
      console.error("Load alerts failed:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  const { connected, getApp } = useMcpApp({
    name: "alert-triage",
    version: "1.0.0",
    onToolResult: (result, app) => {
      try {
        const text = extractToolText(result);
        if (text) {
          const data = JSON.parse(text);
          if (data.params) {
            const incomingLimit = data.params.limit || DEFAULT_LIMIT_NUM;
            paramsRef.current = {
              days: data.params.days || 7,
              severity: data.params.severity,
              limit: incomingLimit,
              query: data.params.query,
            };
            if (data.params.query) setSearchInput(data.params.query);
            const limKey = String(incomingLimit);
            if (isLimitKey(limKey)) setLimit(limKey);
          }
          if (Array.isArray(data.verdicts)) setVerdicts(data.verdicts);
        }
      } catch { /* ignore */ }
      loadAlertsImpl(app);
    },
    onConnect: (app, gotResult) => {
      if (!gotResult) loadAlertsImpl(app);
    },
  });

  const loadAlerts = useCallback((overrideParams?: Partial<FilterParams>) => {
    const app = getApp();
    if (app) loadAlertsImpl(app, overrideParams);
  }, [getApp, loadAlertsImpl]);

  const fullscreen = useFullscreen(getApp);

  useEffect(() => {
    if (!connected) return;
    const interval = setInterval(() => loadAlerts(), 60000);
    return () => clearInterval(interval);
  }, [connected, loadAlerts]);

  // Sort + group the current alert summary. The pure helpers and `useMemo`
  // wrappers live in `./hooks/useAlertSort` so they can be unit-tested
  // independently of this component.
  const { sortedAlerts, groupedAlerts } = useAlertSort(summary, sortBy, groupBy);

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

  // Keep the left list in sync with the selected alert: when navigating to an
  // alert from the detail pane (e.g. via the Related list), expand the group
  // that contains it (if grouped) and scroll the row into view. `block: "nearest"`
  // is a no-op when the row is already visible, so direct clicks in the list
  // don't cause unnecessary scrolling.
  useEffect(() => {
    const id = selectedAlert?._id;
    if (!id) return;

    if (groupedAlerts) {
      const bucket = groupedAlerts.find((g) => g.alerts.some((a) => a._id === id));
      if (bucket && !openGroups.has(bucket.key)) {
        setOpenGroups((prev) => {
          const next = new Set(prev);
          next.add(bucket.key);
          return next;
        });
        return;
      }
    }

    const container = listRef.current;
    if (!container) return;
    const node = container.querySelector(`[data-alert-id="${CSS.escape(id)}"]`);
    if (node instanceof HTMLElement) {
      node.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
  }, [selectedAlert?._id, groupedAlerts, openGroups]);

  const setLimitAndReload = useCallback((v: LimitKey) => {
    setLimit(v);
    loadAlerts({ limit: Number.parseInt(v, 10) });
  }, [loadAlerts]);

  const selectAlert = useCallback(async (alert: SecurityAlert) => {
    setSelectedAlert(alert);
    setAlertContext(null);
    setContextLoading(true);
    const app = getApp();
    if (!app) return;
    try {
      const result = await app.callServerTool({
        name: "get-alert-context",
        arguments: { alertId: alert._id, alert: JSON.stringify(alert) },
      });
      const text = extractCallResult(result);
      if (text) setAlertContext(JSON.parse(text));
    } catch { /* optional */ }
    finally { setContextLoading(false); }
  }, [getApp]);

  const toast = useToast();

  const acknowledgeAlert = useCallback(async (alert: SecurityAlert) => {
    const app = getApp();
    if (!app) return;
    const alertId = alert._id;
    // Capture the alert's position in the current list so we can splice it
    // back at the same index if the user hits Undo within the toast window.
    const originalAlerts = summary?.alerts ?? [];
    const originalIndex = originalAlerts.findIndex((a) => a._id === alertId);
    const wasSelected = selectedAlert?._id === alertId;

    try {
      await app.callServerTool({ name: "acknowledge-alert", arguments: { alertId } });
      setSummary((prev) => prev ? { ...prev, total: prev.total - 1, alerts: prev.alerts.filter((a) => a._id !== alertId) } : prev);
      if (wasSelected) setSelectedAlert(null);

      toast.show({
        message: "Alert acknowledged",
        tone: "success",
        actionLabel: "Undo",
        onAction: async () => {
          const liveApp = getApp();
          if (!liveApp) return;
          try {
            await liveApp.callServerTool({ name: "unacknowledge-alert", arguments: { alertId } });
            setSummary((prev) => {
              if (!prev) return prev;
              const next = [...prev.alerts];
              const insertAt = originalIndex >= 0 ? Math.min(originalIndex, next.length) : next.length;
              next.splice(insertAt, 0, alert);
              return { ...prev, total: prev.total + 1, alerts: next };
            });
            if (wasSelected) setSelectedAlert(alert);
            toast.show({ message: "Alert restored", tone: "info", durationMs: 4000 });
          } catch (err) {
            console.error("Failed to undo acknowledge:", err);
            toast.show({ message: "Couldn't undo — see console.", tone: "danger" });
          }
        },
      });
    } catch (e) {
      console.error("Failed to acknowledge alert:", e);
      toast.show({ message: "Couldn't acknowledge alert.", tone: "danger" });
    }
  }, [getApp, selectedAlert, summary, toast]);

  const createCaseFromAlert = useCallback(async (alert: SecurityAlert) => {
    const app = getApp();
    if (!app) return;
    const src = alert._source;
    const rule = String(src["kibana.alert.rule.name"] ?? "Unknown rule");
    const reason = String(src["kibana.alert.reason"] ?? "");
    const sev = String(src["kibana.alert.severity"] ?? "low").toLowerCase();
    const score = Number(src["kibana.alert.risk_score"] ?? 0);
    const host = src.host?.name ?? "—";
    const userName = src.user?.name
      ? (src.user.domain ? `${src.user.domain}\\${src.user.name}` : src.user.name)
      : "—";
    const threat = src["kibana.alert.rule.threat"]?.[0];
    const tactic = threat?.tactic?.name ?? "—";
    const techniqueId = threat?.technique?.[0]?.id ?? "";
    const techniqueName = threat?.technique?.[0]?.name ?? "";
    const technique = techniqueId
      ? techniqueName ? `${techniqueId} ${techniqueName}` : techniqueId
      : "—";
    const ruleDescription = String(src["kibana.alert.rule.description"] ?? "").trim();

    const description = [
      `## Alert Summary`,
      ``,
      `**Rule**: ${rule}`,
      `**Severity**: ${sev}`,
      `**Risk score**: ${score}`,
      `**Host**: ${host}`,
      `**User**: ${userName}`,
      `**MITRE tactic**: ${tactic}`,
      `**MITRE technique**: ${technique}`,
      ``,
      `**Reason**`,
      ``,
      reason || "(no reason provided)",
      ...(ruleDescription
        ? [
          ``,
          `---`,
          ``,
          `### Rule description`,
          ``,
          ruleDescription,
        ]
        : []),
    ].join("\n");

    try {
      await app.callServerTool({
        name: "create-case",
        arguments: {
          title: `[Alert] ${rule}`,
          description,
          severity: sev,
          tags: ["alert-triage", `mitre:${tactic}`].filter((t) => !t.endsWith(":—")).join(","),
          alertIds: [alert._id],
        },
      });
      toast.show({
        message: `Case created for "${rule}".`,
        tone: "success",
        actionLabel: "Open Cases",
        onAction: () => {
          const liveApp = getApp();
          liveApp?.sendMessage({
            role: "user",
            content: [{ type: "text", text: "Use manage-cases to open the cases dashboard." }],
          }).catch(() => {});
        },
      });
    } catch (e) {
      console.error("Failed to create case from alert:", e);
      toast.show({ message: "Couldn't create case — see console.", tone: "danger" });
    }
  }, [getApp, toast]);

  const handleSearch = useCallback((q: string) => {
    loadAlerts({ query: q.trim() || undefined });
  }, [loadAlerts]);

  const clearQuery = useCallback(() => {
    setSearchInput("");
    loadAlerts({ query: undefined });
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
    loadAlerts({ query: q });
  }, [loadAlerts]);

  if (!connected) {
    return <LoadingState>Connecting...</LoadingState>;
  }

  const activeQuery = paramsRef.current.query;
  const hasDetail = !!selectedAlert;

  // verdict lookup removed for stability

  const list = (
    <>
      {hasDetail && <BackButton onClick={() => setSelectedAlert(null)} />}

      {summary && !hasDetail && summary.alerts.length > 0 && (
        <div className="summary-panel">
          <div className="summary-grid">
            <div className="summary-section">
              <div className="summary-section-title">Severity</div>
              <SeverityDonut bySeverity={summary.bySeverity} itemLabel="alerts" />
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
        <ListSubheader
          left={
            <>
              <Dropdown<LimitKey>
                label="Showing"
                options={LIMIT_OPTIONS}
                value={limit}
                onChange={setLimitAndReload}
                ariaLabel="Number of alerts to show"
              />
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
                ariaLabel="Toggle alert details"
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

      <div className="list-pane-content" ref={listRef}>
        {loading && !summary ? (
          <LoadingState>Loading alerts...</LoadingState>
        ) : !summary || summary.alerts.length === 0 ? (
          <EmptyState>{activeQuery ? `No alerts matching "${activeQuery}"` : "No open alerts"}</EmptyState>
        ) : groupedAlerts ? (
          groupedAlerts.length === 0 ? (
            <EmptyState>No alerts have a {GROUP_LABEL[groupBy].toLowerCase()} to group by.</EmptyState>
          ) : (
            groupedAlerts.map((group, i) => {
              const expanded = openGroups.has(group.key);
              return (
                <div key={group.key} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
                  <GroupCard
                    name={group.name}
                    subtitle={group.subtitle}
                    topSeverity={group.topSeverity}
                    count={group.alerts.length}
                    countLabel="alerts"
                    expanded={expanded}
                    onToggle={() => toggleGroup(group.key)}
                    description={`Grouped by ${GROUP_LABEL[groupBy]}`}
                  />
                  {expanded && (
                    <div className={`group-children sev-${group.topSeverity}`}>
                      {group.alerts.map((alert) => (
                        <div key={alert._id} data-alert-id={alert._id}>
                          <AlertCard
                            alert={alert}
                            compact={hasDetail}
                            selected={selectedAlert?._id === alert._id}
                            showDetails={showDetails}
                            onClick={() => selectAlert(alert)}
                            onEntityFilter={entityFilter}
                          />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })
          )
        ) : (
          sortedAlerts.map((alert, i) => (
            <div key={alert._id} data-alert-id={alert._id} className="animate-in" style={{ "--i": i } as React.CSSProperties}>
              <AlertCard alert={alert} compact={hasDetail} selected={selectedAlert?._id === alert._id}
                showDetails={showDetails}
                onClick={() => selectAlert(alert)}
                onEntityFilter={entityFilter} />
            </div>
          ))
        )}
      </div>
    </>
  );

  const detail = hasDetail ? (
    <DetailView key={selectedAlert._id} alert={selectedAlert} context={alertContext} contextLoading={contextLoading}
      onAcknowledge={() => acknowledgeAlert(selectedAlert)}
      onCreateCase={() => { void createCaseFromAlert(selectedAlert); }}
      onSelectAlert={selectAlert}
      onEntityFilter={entityFilter}
      relatedOpen={relatedOpen}
      onToggleRelated={() => setRelatedOpen((v) => !v)} />
  ) : undefined;

  return (
    <AppShell className="triage-app">
      <AppHeader
        title="Alert Triage"
        leftExtras={activeQuery && (
          <QueryPill label={activeQuery} onClear={clearQuery} />
        )}
        actions={
          <SearchInput
            value={searchInput}
            onChange={setSearchInput}
            onSubmit={handleSearch}
            onClear={clearQuery}
          />
        }
        fullscreen={{ isFullscreen: fullscreen.isFullscreen, onToggle: fullscreen.toggle }}
      />
      <TwoPaneLayout list={list} detail={detail} className="triage-body" />
    </AppShell>
  );
}
