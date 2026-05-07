/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import type { SecurityAlert, AlertSummary, AlertContext, ProcessEvent, NetworkEvent } from "../../shared/types";
import { AlertCard, AlertScoreRing, EntityIcon } from "./components/AlertCard";
import {
  AppHeader,
  AppShell,
  BackButton,
  ChevronDownIcon,
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
  SEVERITY_RANK as SEV_RANK,
  useToast,
} from "../../shared/components";
import type { Severity } from "../../shared/components";
import { useClickOutside } from "../../shared/hooks/useClickOutside";
import { useFullscreen } from "../../shared/hooks/useFullscreen";
import { useMcpApp } from "../../shared/hooks/useMcpApp";
import "./styles.css";

type SeverityKey = Severity;

interface FilterParams {
  days: number;
  severity?: string;
  limit: number;
  query?: string;
}

type SortKey = "severity" | "risk" | "newest" | "oldest" | "rule" | "host";
const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: "severity", label: "Severity" },
  { value: "risk", label: "Risk score" },
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "rule", label: "Rule name" },
  { value: "host", label: "Host name" },
];

type GroupKey = "none" | "host" | "user" | "process";
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

  const sendCasePromptForAlert = useCallback(async (alert: SecurityAlert) => {
    const app = getApp();
    if (!app) return;
    const src = alert._source;
    const rule = String(src["kibana.alert.rule.name"] ?? "Unknown rule");
    const reason = String(src["kibana.alert.reason"] ?? "");
    const prompt = [
      `Use manage-cases to create a new Elastic Security case for this alert (or attach it to an existing case when it is clearly the same incident).`,
      ``,
      `Structure the case predictably:`,
      `- **Title**: "[Alert] ${rule}"`,
      `- **Description**: an "Alert Summary" with rule, severity, risk score, host, user, MITRE tactic/technique, and the alert reason.`,
      `- **First comment** (only if you have meaningful additional context): your investigation notes / next steps.`,
      `- Attach the alert via the alertIds parameter.`,
      ``,
      `Alert document _id: ${alert._id}. Rule: ${JSON.stringify(rule)}. Reason: ${reason || "(none)"}`,
    ].join("\n");
    try {
      await app.sendMessage({ role: "user", content: [{ type: "text", text: prompt }] });
    } catch (e) {
      console.error("sendMessage failed:", e);
    }
  }, [getApp]);

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
      onOpenCaseChat={() => { void sendCasePromptForAlert(selectedAlert); }}
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

function DetailView({ alert, context, contextLoading, onAcknowledge, onCreateCase, onOpenCaseChat, onSelectAlert, onEntityFilter, relatedOpen, onToggleRelated }: {
  alert: SecurityAlert; context: AlertContext | null; contextLoading: boolean;
  onAcknowledge: () => void;
  onCreateCase: () => void;
  onOpenCaseChat: () => void;
  onSelectAlert: (a: SecurityAlert) => void;
  onEntityFilter?: (field: string, value: string) => void;
  relatedOpen: boolean;
  onToggleRelated: () => void;
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
  const [takeActionOpen, setTakeActionOpen] = useState(false);
  const takeActionRef = useRef<HTMLDivElement | null>(null);
  useClickOutside(takeActionRef, takeActionOpen, () => setTakeActionOpen(false));

  return (
    <div className="alert-detail">
      <div className="alert-detail-top">
        <AlertScoreRing score={score} severity={sev} />
        <div className="take-action-dropdown" ref={takeActionRef}>
          <button
            type="button"
            className="alert-detail-action take-action-trigger"
            aria-haspopup="menu"
            aria-expanded={takeActionOpen}
            onClick={() => setTakeActionOpen((v) => !v)}
          >
            Take Action
            <ChevronDownIcon open={takeActionOpen} />
          </button>
          {takeActionOpen && (
            <div className="take-action-menu" role="menu">
              <button
                type="button"
                role="menuitem"
                className="take-action-option"
                onClick={() => {
                  setTakeActionOpen(false);
                  onCreateCase();
                }}
              >
                Create case now
              </button>
              <button
                type="button"
                role="menuitem"
                className="take-action-option"
                onClick={() => {
                  setTakeActionOpen(false);
                  onOpenCaseChat();
                }}
              >
                Open case in chat
              </button>
              <button
                type="button"
                role="menuitem"
                className="take-action-option"
                onClick={() => {
                  setTakeActionOpen(false);
                  onAcknowledge();
                }}
              >
                Acknowledge alert
              </button>
            </div>
          )}
        </div>
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
        <div className="alert-detail-section"><LoadingState>Loading context...</LoadingState></div>
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
              onToggle={onToggleRelated}
              previewCount={RELATED_PREVIEW}
            >
              <div className="related-alerts-list">
                {(relatedOpen ? context.relatedAlerts : context.relatedAlerts.slice(0, RELATED_PREVIEW)).map((a) => (
                  <RelatedAlertCard
                    key={a._id}
                    alert={a}
                    selected={a._id === alert._id}
                    onClick={() => onSelectAlert(a)}
                  />
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

function RelatedAlertCard({ alert, selected, onClick }: { alert: SecurityAlert; selected?: boolean; onClick: () => void }) {
  const src = alert._source;
  const sev = ((src["kibana.alert.severity"]?.toLowerCase() || "low") as "low" | "medium" | "high" | "critical");
  const score = src["kibana.alert.risk_score"] ?? 0;
  return (
    <div className={`related-alert-card sev-${sev}${selected ? " selected" : ""}`} onClick={onClick}>
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
