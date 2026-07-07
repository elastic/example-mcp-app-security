/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useCallback, useMemo, useEffect } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import { inspectMcpAppBootstrapResult } from "../../shared/mcp-app-bootstrap";
import type { DetectionRule } from "../../shared/types";
import { RuleTestPanel } from "./components/RuleTestPanel";
import { FactCol } from "./components/FactCol";
import { NoisyRulesView, type NoisyRuleRow as NoisyRuleRowImported } from "./components/NoisyRulesView";
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
  ToggleSwitch,
  TwoPaneLayout,
} from "../../shared/components";
import type { Severity } from "../../shared/components";
import { useFullscreen } from "../../shared/hooks/useFullscreen";
import { useMcpApp, useMcpAppBootstrap, useMcpAppEvents } from "../../shared/hooks/useMcpApp";
import { McpAppProvider } from "../../shared/hooks/McpAppProvider";
import { useAnalytics } from "../../shared/hooks/useAnalytics";
import "./styles.css";

type SeverityKey = Severity;
type StatusFilter = "all" | "enabled" | "disabled";
type SortKey = "severity" | "name" | "risk" | "updated" | "enabled";
type GroupKey = "none" | "severity" | "type" | "language" | "tag";
type View = "list" | "detail" | "noisy";

type NoisyRuleRow = NoisyRuleRowImported;

const SEV_RANK = SEVERITY_RANK;

const STATUS_FILTERS: { value: StatusFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "enabled", label: "Enabled" },
  { value: "disabled", label: "Disabled" },
];

const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: "severity", label: "Severity" },
  { value: "name", label: "Name" },
  { value: "risk", label: "Risk score" },
  { value: "updated", label: "Recently updated" },
  { value: "enabled", label: "Enabled first" },
];

const GROUP_OPTIONS: { value: GroupKey; label: string }[] = [
  { value: "none", label: "None" },
  { value: "severity", label: "Severity" },
  { value: "type", label: "Rule type" },
  { value: "language", label: "Query language" },
  { value: "tag", label: "Tag" },
];
const GROUP_LABEL: Record<GroupKey, string> = Object.fromEntries(
  GROUP_OPTIONS.map((o) => [o.value, o.label]),
) as Record<GroupKey, string>;

export function App() {
  return (
    <McpAppProvider name="detection-rules" version="1.0.0">
      <AppContent />
    </McpAppProvider>
  );
}

function AppContent() {
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
  const [showDetails, setShowDetails] = useState(false);
  const [sortBy, setSortBy] = useState<SortKey>("severity");
  const [groupBy, setGroupBy] = useState<GroupKey>("none");
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());

  const loadRulesImpl = useCallback(async (app: McpApp, filter?: string) => {
    setListLoading(true);
    try {
      const result = await app.callServerTool({
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

  const { connected, getApp } = useMcpApp();
  const bootstrap = useMcpAppBootstrap("detection-rules");
  useMcpAppEvents({
    onToolResult: (params, app) => {
      if (inspectMcpAppBootstrapResult(params).status !== "not_bootstrap") {
        return;
      }
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
      loadRulesImpl(app);
    },
  });

  useEffect(() => {
    if (bootstrap.status === "idle") {
      return;
    }
    if (bootstrap.status === "error") {
      setListLoading(false);
      return;
    }
    const { rules: nextRules, total: nextTotal, params } = bootstrap.payload;
    setRules(nextRules.map((rule) => ({
      id: rule.id,
      rule_id: rule.id,
      name: rule.name,
      description: rule.description ?? "",
      severity:
        rule.severity === "medium" ||
        rule.severity === "high" ||
        rule.severity === "critical" ||
        rule.severity === "low"
          ? rule.severity
          : "low",
      risk_score: rule.risk_score ?? 0,
      type: rule.type ?? "",
      enabled: rule.enabled ?? false,
      query: rule.query,
      language: rule.language,
      tags: rule.tags ? [...rule.tags] : undefined,
      threat: rule.threat?.map((threat) => ({
        framework: "MITRE ATT&CK",
        tactic: { id: "", name: threat.tactic ?? "", reference: "" },
        technique: threat.techniques.map((technique) => {
          const [id, ...nameParts] = technique.split(" ");
          return {
            id,
            name: nameParts.join(" "),
            reference: "",
          };
        }),
      })),
      created_at: "",
      updated_at: "",
      created_by: "",
    })));
    setTotal(nextTotal);
    const filter = params.filter ?? "";
    setSearchInput(filter);
    setActiveFilter(filter);
    setListLoading(false);
  }, [bootstrap]);

  const { trackEvent } = useAnalytics();
  useEffect(() => {
    trackEvent({ eventType: "view_rendered", viewId: "detection-rules" });
  }, [trackEvent]);

  useEffect(() => {
    if (!connected || bootstrap.status !== "idle") return;
    const app = getApp();
    if (app) loadRulesImpl(app);
  }, [connected, bootstrap.status, getApp, loadRulesImpl]);

  const loadRules = useCallback((filter?: string) => {
    const app = getApp();
    if (app) loadRulesImpl(app, filter);
  }, [getApp, loadRulesImpl]);

  const fullscreen = useFullscreen(getApp);

  const openRule = useCallback(async (id: string) => {
    const app = getApp();
    if (!app) return;
    try {
      const result = await app.callServerTool({ name: "get-rule", arguments: { id } });
      const text = extractCallResult(result);
      if (text) {
        setSelectedRule(JSON.parse(text));
        setView("detail");
      }
    } catch (e) { console.error("Failed to load rule:", e); }
  }, [getApp]);

  const toggleRule = useCallback(async (id: string, enabled: boolean) => {
    const app = getApp();
    if (!app) return;
    try {
      await app.callServerTool({ name: "toggle-rule", arguments: { id, enabled } });
      await loadRulesImpl(app, activeFilter || undefined);
      if (selectedRule?.id === id) {
        const result = await app.callServerTool({ name: "get-rule", arguments: { id } });
        const text = extractCallResult(result);
        if (text) setSelectedRule(JSON.parse(text));
      }
    } catch (e) { console.error("Failed to toggle rule:", e); }
  }, [getApp, loadRulesImpl, activeFilter, selectedRule?.id]);

  const validateQuery = useCallback(async (query: string, language: string) => {
    const app = getApp();
    if (!app) return { valid: false, error: "Not connected" };
    try {
      const result = await app.callServerTool({ name: "validate-query", arguments: { query, language } });
      const text = extractCallResult(result);
      if (text) return JSON.parse(text);
      return { valid: false, error: "No response" };
    } catch (e) {
      return { valid: false, error: e instanceof Error ? e.message : String(e) };
    }
  }, [getApp]);

  const loadNoisyRules = useCallback(async () => {
    const app = getApp();
    if (!app) return;
    setView("noisy");
    setSelectedRule(null);
    setNoisyLoading(true);
    setNoisyRules([]);
    try {
      const result = await app.callServerTool({ name: "noisy-rules", arguments: { days: 7, limit: 20 } });
      const text = extractCallResult(result);
      if (text) setNoisyRules(JSON.parse(text));
    } catch (e) { console.error("Failed to load noisy rules:", e); }
    finally { setNoisyLoading(false); }
  }, [getApp]);

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
    loadRules();
  }, [loadRules]);

  const setGroupByAndReset = useCallback((g: GroupKey) => {
    setGroupBy(g);
    setOpenGroups(new Set());
  }, []);

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
    return <LoadingState>Connecting…</LoadingState>;
  }

  const hasDetail = view === "detail" && !!selectedRule;
  const showingNoisy = view === "noisy";

  const list = (
    <>
      {(hasDetail || showingNoisy) && <BackButton onClick={goBackToList} />}

      {!hasDetail && !showingNoisy && rules.length > 0 && (
        <KpiStrip
          tileCount={3}
          className="rules-kpi-strip"
          summary={
            <>
              <div className="summary-section-title">By severity</div>
              <SeverityDonut bySeverity={summary.bySeverity} itemLabel="rules" />
            </>
          }
        >
          <KpiTile label="Total rules" value={total || rules.length} />
          <KpiTile label="Enabled" value={summary.enabled} />
          <KpiTile label="Disabled" value={summary.disabled} />
        </KpiStrip>
      )}

      {!hasDetail && !showingNoisy && rules.length > 0 && (
        <ListSubheader
          left={
            <>
              <span>
                Showing <strong>{filteredRules.length}</strong> rule{filteredRules.length !== 1 ? "s" : ""}
                {total > filteredRules.length && <> of <strong>{total}</strong></>}
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
                ariaLabel="Toggle rule details"
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

      <div className="rules-list-content">
        {listLoading && !rules.length ? (
          <LoadingState>Loading rules…</LoadingState>
        ) : bootstrap.status === "error" && !rules.length ? (
          <EmptyState>{bootstrap.reason}</EmptyState>
        ) : !rules.length ? (
          <EmptyState>{activeFilter ? `No rules matching "${activeFilter}"` : "No rules available"}</EmptyState>
        ) : groupedRules ? (
          groupedRules.length === 0 ? (
            <EmptyState>No rules have a {GROUP_LABEL[groupBy].toLowerCase()} to group by.</EmptyState>
          ) : (
            groupedRules.map((group, gi) => {
              const expanded = openGroups.has(group.key);
              return (
                <div key={group.key} className="animate-in" style={{ "--i": gi } as React.CSSProperties}>
                  <GroupCard
                    name={group.name}
                    subtitle={group.subtitle}
                    topSeverity={group.topSeverity}
                    count={group.rules.length}
                    countLabel="rules"
                    expanded={expanded}
                    onToggle={() => toggleGroup(group.key)}
                    description={`Grouped by ${GROUP_LABEL[groupBy]}`}
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
    </>
  );

  let detail: React.ReactNode = undefined;
  if (hasDetail && selectedRule) {
    detail = (
      <DetailPane onClose={goBackToList}>
        <RuleDetailView
          key={selectedRule.id}
          rule={selectedRule}
          onToggle={(enabled) => toggleRule(selectedRule.id, enabled)}
          onValidate={validateQuery}
        />
      </DetailPane>
    );
  } else if (showingNoisy) {
    detail = (
      <DetailPane onClose={goBackToList}>
        <NoisyRulesView loading={noisyLoading} rows={noisyRules} />
      </DetailPane>
    );
  }

  return (
    <AppShell className="rules-app">
      <AppHeader
        title="Detection Rules"
        leftExtras={activeFilter ? <QueryPill label={activeFilter} onClear={clearSearch} /> : undefined}
        actions={
          <>
            <div className="rules-status-tabs">
              {STATUS_FILTERS.map((s) => (
                <button
                  key={s.value}
                  type="button"
                  className={`rules-status-tab${statusFilter === s.value ? " active" : ""}`}
                  onClick={() => setStatusFilter(s.value)}
                >
                  {s.label}
                </button>
              ))}
            </div>
            <div className="rules-status-dropdown-wrap">
              <Dropdown<StatusFilter>
                label="Status:"
                options={STATUS_FILTERS}
                value={statusFilter}
                onChange={setStatusFilter}
              />
            </div>
            <SearchInput
              value={searchInput}
              onChange={setSearchInput}
              onSubmit={runSearch}
              onClear={clearSearch}
              placeholder="KQL filter…"
            />
            <button
              type="button"
              className="rules-header-ghost-btn"
              onClick={loadNoisyRules}
              disabled={noisyLoading}
            >
              {noisyLoading ? "Loading…" : "Noisy Rules"}
            </button>
          </>
        }
        fullscreen={{ isFullscreen: fullscreen.isFullscreen, onToggle: fullscreen.toggle }}
      />
      <TwoPaneLayout list={list} detail={detail} className="rules-body" />
    </AppShell>
  );
}

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


function formatDateShort(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "—";
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  } catch { return "—"; }
}
