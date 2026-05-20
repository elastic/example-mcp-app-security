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
import { inspectMcpAppBootstrapResult } from "../../shared/mcp-app-bootstrap";
import { SeverityBadge } from "../../shared/severity";
import type { AttackDiscoveryFinding, DiscoveryDetail } from "../../shared/types";
import { AttackFlowDiagram } from "./AttackFlowDiagram";
import { FactCol } from "./components/FactCol";
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
  RefreshIcon,
  SearchInput,
  SeverityChip,
  SeverityDonut,
  ToastProvider,
  ToggleSwitch,
  TwoPaneLayout,
  useToast,
} from "../../shared/components";
import type { Severity } from "../../shared/components";
import { useFullscreen } from "../../shared/hooks/useFullscreen";
import { useMcpApp, useMcpAppBootstrap, useMcpAppEvents } from "../../shared/hooks/useMcpApp";
import { McpAppProvider } from "../../shared/hooks/McpAppProvider";
import { useAnalytics } from "../../shared/hooks/useAnalytics";
import { stripKibanaTemplateSyntax } from "./template-syntax";
import "./styles.css";

import { ConfidenceChip, CONFIDENCE_LABEL, type ConfidenceKey } from "./components/ConfidenceChip";

type SeverityKey = Severity;
type ConfidenceFilter = "all" | ConfidenceKey;

const CONFIDENCE_FILTERS: { key: ConfidenceFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "high", label: "High confidence" },
  { key: "moderate", label: "Moderate" },
  { key: "low", label: "Low" },
];

type SortKey = "risk" | "confidence" | "newest" | "oldest" | "alerts" | "title";
const SORT_OPTIONS: { value: SortKey; label: string }[] = [
  { value: "risk", label: "Risk score" },
  { value: "confidence", label: "Confidence" },
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "alerts", label: "Alert count" },
  { value: "title", label: "Title (A–Z)" },
];
const CONFIDENCE_RANK: Record<string, number> = { high: 3, moderate: 2, low: 1 };

type GroupKey = "none" | "host" | "user" | "confidence" | "tactic";
const GROUP_OPTIONS: { value: GroupKey; label: string }[] = [
  { value: "none", label: "None" },
  { value: "host", label: "Host" },
  { value: "user", label: "User" },
  { value: "confidence", label: "Confidence" },
  { value: "tactic", label: "Tactic" },
];
const GROUP_LABEL: Record<GroupKey, string> = Object.fromEntries(
  GROUP_OPTIONS.map((o) => [o.value, o.label]),
) as Record<GroupKey, string>;

const CONFIDENCE_DROPDOWN_OPTIONS: { value: ConfidenceFilter; label: string }[] = CONFIDENCE_FILTERS.map(
  (f) => ({ value: f.key, label: f.label }),
);

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
  const showRiskPanel = state.type === "host" || state.type === "user";
  const risk = detail?.entityRisk?.find((er) => er.type === state.type && er.name === state.value);
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

      {showRiskPanel && (
        risk && risk.level.toLowerCase() !== "unknown" ? (
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
        )
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

function riskSeverity(score: number): SeverityKey {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function entityRiskColor(level: string): string {
  const l = level.toLowerCase();
  if (l === "critical") return "var(--severity-critical)";
  if (l === "high") return "var(--severity-high)";
  if (l === "moderate") return "var(--severity-medium)";
  if (l === "unknown") return "var(--text-dim)";
  return "var(--severity-low)";
}

export function App() {
  return (
    <ToastProvider>
      <McpAppProvider name="attack-discovery-triage" version="1.0.0">
        <AppContent />
      </McpAppProvider>
    </ToastProvider>
  );
}

function AppContent() {
  const [discoveries, setDiscoveries] = useState<AttackDiscoveryFinding[]>([]);
  const [selected, setSelected] = useState<AttackDiscoveryFinding | null>(null);
  const [detail, setDetail] = useState<DiscoveryDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [actionResult, setActionResult] = useState<string | null>(null);
  const [generations, setGenerations] = useState<Array<{ status: string; connector_id: string; connectorName?: string; discoveries: number; start: string; end?: string; loading_message?: string; execution_uuid: string; reason?: string }>>([]);
  const [searchInput, setSearchInput] = useState("");
  const [activeQuery, setActiveQuery] = useState("");
  const [tab, setTab] = useState<"summary" | "flow" | "alerts" | "entities" | "signals">("summary");
  const [flyout, setFlyout] = useState<FlyoutState | null>(null);
  const [expandedAlerts, setExpandedAlerts] = useState<Set<string>>(new Set());
  const [confidenceFilter, setConfidenceFilter] = useState<ConfidenceFilter>("all");
  const [showDetails, setShowDetails] = useState(false);
  const [sortBy, setSortBy] = useState<SortKey>("risk");
  const [groupBy, setGroupBy] = useState<GroupKey>("none");
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const paramsRef = useRef<{ days: number; limit: number }>({ days: 1, limit: 50 });

  const checkGenerationStatusImpl = useCallback(async (mcpApp: McpApp) => {
    try {
      const result = await mcpApp.callServerTool({ name: "get-generation-status", arguments: { size: 5, start: "now-1h" } });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text) as { generations?: Array<{ status: string; connector_id: string; discoveries: number; start: string; end?: string; loading_message?: string; execution_uuid: string; reason?: string }> };
        const gens = (data.generations || []).map((g) => ({ ...g, connectorName: undefined as string | undefined }));
        try {
          const connResult = await mcpApp.callServerTool({ name: "list-ai-connectors", arguments: {} });
          const connText = extractCallResult(connResult);
          if (connText) {
            const connectors = JSON.parse(connText) as Array<{ id: string; name: string }>;
            const connMap = new Map(connectors.map((c) => [c.id, c.name]));
            for (const g of gens) {
              g.connectorName = connMap.get(g.connector_id) || g.connector_id;
            }
          }
        } catch { /* ignore */ }
        setGenerations(gens);
      }
    } catch { /* ignore */ }
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

  const loadDiscoveriesImpl = useCallback(async (mcpApp: McpApp) => {
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
  }, [assessConfidence]);

  const { connected, getApp } = useMcpApp();
  const bootstrap = useMcpAppBootstrap("attack-discovery");
  useMcpAppEvents({
    onToolResult: (result) => {
      if (inspectMcpAppBootstrapResult(result).status !== "not_bootstrap") {
        return;
      }
      try {
        const text = extractToolText(result);
        if (text) {
          const data = JSON.parse(text);
          if (data.params) {
            paramsRef.current = { days: data.params.days || 1, limit: data.params.limit || 50 };
          }
          if (Array.isArray(data.discoveries)) {
            setDiscoveries(data.discoveries.map((d: Record<string, unknown>) => ({
              ...d,
              alertCount: (d.alertIds as string[])?.length || d.alertCount || 0,
            })));
            setLoading(false);
          }
        }
      } catch { /* ignore */ }
    },
  });

  useEffect(() => {
    if (bootstrap.status === "idle") {
      return;
    }
    if (bootstrap.status === "error") {
      setLoading(false);
      return;
    }
    const { discoveries: nextDiscoveries, params } = bootstrap.payload;
    paramsRef.current = { ...params };
    setDiscoveries(
      nextDiscoveries.map((d) => ({
        ...d,
        alertCount: d.alertIds?.length || d.alertCount || 0,
      })),
    );
    setLoading(false);
  }, [bootstrap]);

  useEffect(() => {
    if (!connected) return;
    const app = getApp();
    if (!app) return;
    void checkGenerationStatusImpl(app);
  }, [checkGenerationStatusImpl, connected, getApp]);

  const { trackEvent } = useAnalytics();
  useEffect(() => {
    trackEvent({ eventType: "view_rendered", viewId: "attack-discovery" });
  }, [trackEvent]);

  const fullscreen = useFullscreen(getApp);

  const loadDiscoveries = useCallback(() => {
    const app = getApp();
    if (app) loadDiscoveriesImpl(app);
  }, [getApp, loadDiscoveriesImpl]);

  const checkGenerationStatus = useCallback(() => {
    const app = getApp();
    if (app) checkGenerationStatusImpl(app);
  }, [getApp, checkGenerationStatusImpl]);

  const loadDetail = useCallback(async (discovery: AttackDiscoveryFinding) => {
    const mcpApp = getApp();
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
  }, [getApp]);

  const toast = useToast();

  const handleApprove = useCallback(async () => {
    const mcpApp = getApp();
    if (!mcpApp || checked.size === 0) return;
    const findings = discoveries.filter((d) => checked.has(d.id));
    try {
      const result = await mcpApp.callServerTool({
        name: "approve-discoveries",
        arguments: { findings },
      });
      const text = extractCallResult(result);
      const data = text ? JSON.parse(text) : { created: findings.length };
      const created = Number(data.created ?? findings.length);
      toast.show({
        message: created === 1 ? "Case created from Attack Discovery." : `Created ${created} cases from Attack Discoveries.`,
        tone: "success",
        actionLabel: "Open in chat",
        onAction: () => {
          const liveApp = getApp();
          liveApp?.sendMessage({
            role: "user",
            content: [{ type: "text", text: "Use manage-cases to open the cases dashboard so I can review the cases just created from Attack Discoveries." }],
          }).catch(() => {});
        },
      });
    } catch (e) {
      console.error("Approve failed:", e);
      toast.show({ message: "Couldn't create case(s) — see console.", tone: "danger" });
    }
  }, [getApp, checked, discoveries, toast]);

  const handleAcknowledge = useCallback(async () => {
    const mcpApp = getApp();
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
  }, [getApp, checked]);

  const acknowledgeSingleDiscovery = useCallback(async (id: string) => {
    const mcpApp = getApp();
    if (!mcpApp) return;
    try {
      const result = await mcpApp.callServerTool({
        name: "acknowledge-discoveries",
        arguments: { discoveryIds: [id] },
      });
      const text = extractCallResult(result);
      if (text) {
        const data = JSON.parse(text);
        setActionResult(`Acknowledged ${data.updated} discovery(ies)`);
        setDiscoveries((prev) => prev.filter((d) => d.id !== id));
        setSelected((s) => (s?.id === id ? null : s));
        setDetail(null);
        setTimeout(() => setActionResult(null), 5000);
      }
    } catch (e) {
      console.error("Acknowledge failed:", e);
    }
  }, [getApp]);

  const approveSingleDiscovery = useCallback(async (finding: AttackDiscoveryFinding) => {
    const mcpApp = getApp();
    if (!mcpApp) return;
    try {
      await mcpApp.callServerTool({
        name: "approve-discoveries",
        arguments: { findings: [finding] },
      });
      const title = finding.title || "Attack Discovery";
      toast.show({
        message: `Case created from "${title}".`,
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
      console.error("Approve failed:", e);
      toast.show({ message: "Couldn't create case — see console.", tone: "danger" });
    }
  }, [getApp, toast]);

  const sendDiscoveryCasePrompt = useCallback(async (d: AttackDiscoveryFinding) => {
    const app = getApp();
    if (!app) return;
    const ids = (d.alertIds || []).join(", ") || "none";
    const prompt = [
      `Use manage-cases to create or update a case for this Attack Discovery: ${JSON.stringify(d.title)} (discovery id: ${d.id}).`,
      `Linked alert IDs: ${ids}.`,
      ``,
      `Structure the case predictably:`,
      `- **Description**: an "Attack Discovery Finding" header with risk score, confidence, MITRE tactics, alert count, the discovery summary, and an "Immediate actions" bullet list (parse from the discovery details if available, otherwise propose 3 concise next steps).`,
      `- **First comment**: the full attack chain narrative (everything from the discovery details *except* the Immediate actions section, which is already in the description).`,
      `- Attach all linked alerts via the alertIds parameter. Do not duplicate the summary or attack chain across description and comments.`,
    ].join("\n");
    try {
      await app.sendMessage({ role: "user", content: [{ type: "text", text: prompt }] });
    } catch (e) {
      console.error("sendMessage failed:", e);
    }
  }, [getApp]);

  useEffect(() => {
    if (!connected || !generations.some((g) => g.status === "started")) return;
    const interval = setInterval(async () => {
      checkGenerationStatus();
      loadDiscoveries();
    }, 10000);
    return () => clearInterval(interval);
  }, [connected, generations, checkGenerationStatus, loadDiscoveries]);

  useEffect(() => {
    if (!flyout) return;
    const close = () => setFlyout(null);
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, [flyout]);

  const openFlyout = useCallback((type: string, value: string, x: number, y: number) => {
    setFlyout({ type, value, x, y });
  }, []);

  const runSearch = useCallback(() => {
    setActiveQuery(searchInput.trim());
  }, [searchInput]);

  const clearSearch = useCallback(() => {
    setSearchInput("");
    setActiveQuery("");
  }, []);

  const filtered = useMemo(() => {
    const q = activeQuery.toLowerCase();
    let arr = discoveries;
    if (q) {
      arr = arr.filter((d) =>
        d.title.toLowerCase().includes(q) ||
        d.mitreTactics?.some((t) => t.toLowerCase().includes(q)) ||
        d.hosts?.some((h) => h.toLowerCase().includes(q)) ||
        d.users?.some((u) => u.toLowerCase().includes(q))
      );
    }
    if (confidenceFilter !== "all") {
      arr = arr.filter((d) => (d.confidence || "low") === confidenceFilter);
    }
    const sorted = [...arr];
    switch (sortBy) {
      case "risk":
        sorted.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));
        break;
      case "confidence":
        sorted.sort((a, b) => (CONFIDENCE_RANK[b.confidence || ""] || 0) - (CONFIDENCE_RANK[a.confidence || ""] || 0));
        break;
      case "newest":
        sorted.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        break;
      case "oldest":
        sorted.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
        break;
      case "alerts":
        sorted.sort((a, b) => (b.alertCount || b.alertIds?.length || 0) - (a.alertCount || a.alertIds?.length || 0));
        break;
      case "title":
        sorted.sort((a, b) => a.title.localeCompare(b.title));
        break;
    }
    return sorted;
  }, [discoveries, activeQuery, confidenceFilter, sortBy]);

  const groupedDiscoveries = useMemo(() => {
    if (groupBy === "none") return null;
    const buckets = new Map<string, {
      key: string;
      name: string;
      subtitle?: string;
      topRisk: number;
      discoveries: AttackDiscoveryFinding[];
    }>();
    const add = (key: string, name: string, subtitle: string | undefined, d: AttackDiscoveryFinding) => {
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { key, name, subtitle, topRisk: 0, discoveries: [] };
        buckets.set(key, bucket);
      }
      bucket.discoveries.push(d);
      if ((d.riskScore || 0) > bucket.topRisk) bucket.topRisk = d.riskScore || 0;
    };
    for (const d of filtered) {
      if (groupBy === "host") {
        const hosts = d.hosts || [];
        if (hosts.length === 0) continue;
        for (const h of hosts) add(h, h, hosts.length > 1 ? `${hosts.length} hosts in this discovery` : undefined, d);
      } else if (groupBy === "user") {
        const users = d.users || [];
        if (users.length === 0) continue;
        for (const u of users) add(u, u, users.length > 1 ? `${users.length} users in this discovery` : undefined, d);
      } else if (groupBy === "confidence") {
        const conf = (d.confidence || "low") as ConfidenceKey;
        add(conf, CONFIDENCE_LABEL[conf] || "Unknown", undefined, d);
      } else if (groupBy === "tactic") {
        const tactics = d.mitreTactics || [];
        if (tactics.length === 0) {
          add("__none__", "No MITRE tactic", undefined, d);
        } else {
          for (const t of tactics) add(t, t, tactics.length > 1 ? `${tactics.length} tactics in this discovery` : undefined, d);
        }
      }
    }
    return [...buckets.values()].sort((a, b) => {
      const d = b.topRisk - a.topRisk;
      if (d !== 0) return d;
      const c = b.discoveries.length - a.discoveries.length;
      if (c !== 0) return c;
      return a.name.localeCompare(b.name);
    });
  }, [filtered, groupBy]);

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
    const byConfidence: Record<ConfidenceKey, number> = { high: 0, moderate: 0, low: 0 };
    const bySeverity: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    let totalAlerts = 0;
    let peakRisk = 0;
    let latestTs = 0;
    const hosts = new Set<string>();
    const users = new Set<string>();
    const tactics = new Set<string>();
    for (const d of discoveries) {
      const conf = (d.confidence || "low") as ConfidenceKey;
      if (conf in byConfidence) byConfidence[conf]++;
      bySeverity[riskSeverity(d.riskScore || 0)]++;
      totalAlerts += d.alertCount || d.alertIds?.length || 0;
      if ((d.riskScore || 0) > peakRisk) peakRisk = d.riskScore || 0;
      d.hosts?.forEach((h) => hosts.add(h));
      d.users?.forEach((u) => users.add(u));
      d.mitreTactics?.forEach((t) => tactics.add(t));
      const ts = d.timestamp ? new Date(d.timestamp).getTime() : 0;
      if (ts > latestTs) latestTs = ts;
    }
    return {
      byConfidence, bySeverity, totalAlerts, peakRisk, latestTs,
      hosts: hosts.size, users: users.size, tactics: tactics.size,
    };
  }, [discoveries]);

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

  const hasDetail = !!selected;

  if (!connected) {
    return <LoadingState>Connecting...</LoadingState>;
  }

  const list = (
    <>
      {hasDetail && (
        <BackButton onClick={() => { setSelected(null); setDetail(null); }} />
      )}

      {!hasDetail && discoveries.length > 0 && (
        <KpiStrip
          className="discoveries-kpi-strip"
          tileCount={4}
          summary={
            <>
              <div className="summary-section-title">By severity</div>
              <SeverityDonut bySeverity={summary.bySeverity} />
            </>
          }
        >
          <KpiTile
            label="Active attacks"
            value={discoveries.length}
            meta={summary.byConfidence.high > 0 ? `${summary.byConfidence.high} high-confidence` : undefined}
          />
          <KpiTile
            label="Peak risk"
            value={summary.peakRisk}
            meta={summary.latestTs ? timeAgo(new Date(summary.latestTs)) : "—"}
          />
          <KpiTile
            label="MITRE tactics"
            value={summary.tactics}
            meta={`${summary.totalAlerts} alerts linked`}
          />
          <KpiTile
            label="Entities at risk"
            value={summary.hosts + summary.users}
            meta={`${summary.hosts} hosts · ${summary.users} users`}
          />
        </KpiStrip>
      )}

          {/* Generation banner — rendered beneath the KPI strip so the status
              message sits directly above the discovery list without pushing
              the widgets down. */}
          {!hasDetail && (() => {
            const running = generations.filter((g) => g.status === "started");
            const justFinished = generations.filter((g) => {
              if (g.status !== "succeeded" && g.status !== "failed") return false;
              if (!g.end) return false;
              return Date.now() - new Date(g.end).getTime() < 60000;
            }).slice(0, 1);
            const visible = [...running, ...justFinished];
            if (visible.length === 0) return null;
            return (
              <div className="generation-banners">
                {visible.map((g) => {
                  const isRunning = g.status === "started";
                  const succeeded = g.status === "succeeded";
                  const failed = g.status === "failed";
                  const name = g.connectorName || g.connector_id;
                  const ts = g.end || g.start;
                  const time = ts ? new Date(ts).toLocaleString() : "";
                  return (
                    <div
                      key={g.execution_uuid}
                      className={`generation-banner ${isRunning ? "running" : succeeded ? "succeeded" : "failed"}`}
                    >
                      {isRunning && <div className="loading-spinner generation-banner-spinner" />}
                      {succeeded && <span className="generation-banner-icon">&#10003;</span>}
                      {failed && <span className="generation-banner-icon fail">&#10007;</span>}
                      <div className="generation-banner-body">
                        {isRunning ? (
                          <>
                            <strong>Attack discovery in progress via {name}</strong>
                            <div className="generation-banner-sub">{g.loading_message || "Analyzing alerts..."}</div>
                          </>
                        ) : succeeded ? (
                          <span>
                            Attack discovery ran successfully via {name} at {time} and <strong>{g.discoveries} new attack{g.discoveries !== 1 ? "s" : ""}</strong> {g.discoveries === 1 ? "was" : "were"} discovered.
                            {g.discoveries > 0 && <span className="generation-banner-cta"> Refresh to view the results.</span>}
                          </span>
                        ) : (
                          <span>Attack discovery failed via {name}. {g.reason || ""}</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          })()}

      {!hasDetail && discoveries.length > 0 && (
        <ListSubheader
          left={
            <>
              <span className="list-subheader-count">
                Showing <strong>{filtered.length}</strong> discover{filtered.length !== 1 ? "ies" : "y"}
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
                ariaLabel="Toggle discovery details"
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

      <div className="discoveries-list-content">
        {loading && discoveries.length === 0 ? (
          <LoadingState>Loading attack discoveries...</LoadingState>
        ) : bootstrap.status === "error" && discoveries.length === 0 ? (
          <EmptyState>{bootstrap.reason}</EmptyState>
        ) : filtered.length === 0 ? (
          <EmptyState>
            <div style={{ fontSize: 28, marginBottom: 8 }}>&#128737;</div>
            <div>{activeQuery ? `No discoveries matching "${activeQuery}"` : "No open attack discoveries"}</div>
            <div style={{ fontSize: 12, marginTop: 4, color: "var(--text-muted)" }}>
              {generations.some((g) => g.status === "started")
                ? "A generation is in progress — results will appear here automatically."
                : "Try adjusting the time range or running a new generation."}
            </div>
          </EmptyState>
        ) : groupedDiscoveries ? (
          groupedDiscoveries.length === 0 ? (
            <EmptyState>No discoveries have a {GROUP_LABEL[groupBy].toLowerCase()} to group by.</EmptyState>
          ) : (
            groupedDiscoveries.map((group, gi) => {
              const expanded = openGroups.has(group.key);
              return (
                <div key={group.key} className="animate-in" style={{ "--i": gi } as React.CSSProperties}>
                  <GroupCard
                    name={group.name}
                    subtitle={group.subtitle}
                    topSeverity={riskSeverity(group.topRisk)}
                    count={group.discoveries.length}
                    countLabel="discoveries"
                    expanded={expanded}
                    onToggle={() => toggleGroup(group.key)}
                    description={`Grouped by ${GROUP_LABEL[groupBy]}`}
                  />
                  {expanded && (
                    <div className={`group-children sev-${riskSeverity(group.topRisk)}`}>
                      {group.discoveries.map((d, i) => (
                        <DiscoveryCard
                          key={`${group.key}-${d.id}`}
                          discovery={d}
                          compact={hasDetail}
                          selected={selected?.id === d.id}
                          checked={checked.has(d.id)}
                          showDetails={showDetails}
                          index={i}
                          onClick={() => {
                            setSelected(d);
                            setTab("summary");
                            setDetail(null);
                            setExpandedAlerts(new Set());
                            loadDetail(d);
                          }}
                          onToggleCheck={(e) => toggleCheck(d.id, e)}
                        />
                      ))}
                    </div>
                  )}
                </div>
              );
            })
          )
        ) : (
          filtered.map((d, i) => (
            <DiscoveryCard
              key={d.id}
              discovery={d}
              compact={hasDetail}
              selected={selected?.id === d.id}
              checked={checked.has(d.id)}
              showDetails={showDetails}
              index={i}
              onClick={() => {
                setSelected(d);
                setTab("summary");
                setDetail(null);
                setExpandedAlerts(new Set());
                loadDetail(d);
              }}
              onToggleCheck={(e) => toggleCheck(d.id, e)}
            />
          ))
        )}
      </div>
    </>
  );

  const detailPane = hasDetail && selected ? (
    <DetailPane onClose={() => { setSelected(null); setDetail(null); }}>
      <DetailView
        key={selected.id}
        discovery={selected}
        detail={detail}
        detailLoading={detailLoading}
        tab={tab}
        setTab={setTab}
        expandedAlerts={expandedAlerts}
        setExpandedAlerts={setExpandedAlerts}
        openFlyout={openFlyout}
        getApp={getApp}
        onAcknowledge={() => { void acknowledgeSingleDiscovery(selected.id); }}
        onCreateCase={() => { void approveSingleDiscovery(selected); }}
        onOpenCaseChat={() => { void sendDiscoveryCasePrompt(selected); }}
      />
    </DetailPane>
  ) : null;

  return (
    <AppShell className="discoveries-app">
      <AppHeader
        title="Attack Discovery"
        leftExtras={
          <>
            <div className="discoveries-confidence-tabs" role="tablist">
              {CONFIDENCE_FILTERS.map((f) => {
                const count = f.key === "all"
                  ? discoveries.length
                  : summary.byConfidence[f.key as ConfidenceKey];
                return (
                  <button
                    key={f.key}
                    role="tab"
                    aria-selected={confidenceFilter === f.key}
                    className={`discoveries-confidence-tab${confidenceFilter === f.key ? " active" : ""}`}
                    onClick={() => setConfidenceFilter(f.key)}
                  >
                    <span>{f.label}</span>
                    <span className="discoveries-confidence-tab-count">{count}</span>
                  </button>
                );
              })}
            </div>
            {activeQuery && <QueryPill label={activeQuery} onClear={clearSearch} />}
          </>
        }
        actions={
          <>
            <div className="discoveries-confidence-dropdown-wrap">
              <Dropdown<ConfidenceFilter>
                label="Confidence:"
                options={CONFIDENCE_DROPDOWN_OPTIONS}
                value={confidenceFilter}
                onChange={setConfidenceFilter}
              />
            </div>
            <SearchInput
              value={searchInput}
              onChange={setSearchInput}
              onSubmit={runSearch}
              onClear={clearSearch}
              placeholder="Filter discoveries..."
            />
            <button
              type="button"
              className="app-header-icon-btn"
              onClick={() => { loadDiscoveries(); checkGenerationStatus(); }}
              title="Refresh"
              aria-label="Refresh"
            >
              <RefreshIcon />
            </button>
          </>
        }
        fullscreen={{ isFullscreen: fullscreen.isFullscreen, onToggle: fullscreen.toggle }}
      />

      <TwoPaneLayout list={list} detail={detailPane} />

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
    </AppShell>
  );
}

function DiscoveryCard({
  discovery,
  compact,
  selected,
  checked,
  showDetails,
  index,
  onClick,
  onToggleCheck,
}: {
  discovery: AttackDiscoveryFinding;
  compact: boolean;
  selected: boolean;
  checked: boolean;
  showDetails: boolean;
  index: number;
  onClick: () => void;
  onToggleCheck: (e: React.MouseEvent) => void;
}) {
  const d = discovery;
  const sev = riskSeverity(d.riskScore || 0);
  const conf = (d.confidence || "low") as ConfidenceKey;
  const alertCount = d.alertCount || d.alertIds?.length || 0;

  return (
    <div
      className={`discovery-card sev-${sev}${selected ? " selected" : ""}${compact ? " compact" : ""} animate-in`}
      style={{ "--i": index } as React.CSSProperties}
      onClick={onClick}
    >
      <div className="discovery-card-main">
        <div className="discovery-card-head">
          <div className="discovery-card-tags">
            <div
              className={`discovery-card-check${checked ? " checked" : ""}`}
              onClick={onToggleCheck}
            >
              {checked && <span>&#10003;</span>}
            </div>
            <SeverityChip severity={sev} />
            <ConfidenceChip level={conf} />
            {d.mitreTactics && d.mitreTactics.length > 0 && (
              <span className="discovery-mitre-pill">{d.mitreTactics[0]}</span>
            )}
            {d.mitreTactics && d.mitreTactics.length > 1 && (
              <span className="discovery-mitre-more">+{d.mitreTactics.length - 1}</span>
            )}
          </div>
          <span className="discovery-card-time">{timeAgo(d.timestamp)}</span>
        </div>
        <h3 className="discovery-card-title">{stripKibanaTemplateSyntax(d.title)}</h3>
        {!compact && d.summaryMarkdown && (
          <p className="discovery-card-reason">
            {stripKibanaTemplateSyntax((d.summaryMarkdown || "").replace(/[#*_`]/g, "").slice(0, 200))}
            {(d.summaryMarkdown || "").length > 200 ? "…" : ""}
          </p>
        )}
        <div className="discovery-card-meta">
          <span className="discovery-card-meta-item">
            <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1a5 5 0 0 1 5 5v2l1.5 3H1.5L3 8V6a5 5 0 0 1 5-5Zm0 13a2.5 2.5 0 0 1-2.5-2.5h5A2.5 2.5 0 0 1 8 14Z" /></svg>
            <span>{alertCount} alert{alertCount !== 1 ? "s" : ""}</span>
          </span>
          {d.hosts && d.hosts.length > 0 && (
            <span className="discovery-card-meta-item">
              <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true"><rect x="2" y="3" width="12" height="8" rx="1" /><path d="M5 13h6" /><path d="M8 11v2" /></svg>
              <span>{d.hosts.length === 1 ? d.hosts[0] : `${d.hosts.length} hosts`}</span>
            </span>
          )}
          {d.users && d.users.length > 0 && (
            <span className="discovery-card-meta-item">
              <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" aria-hidden="true"><circle cx="8" cy="6" r="2.5" /><path d="M3 13c0-2.5 2.25-4 5-4s5 1.5 5 4" /></svg>
              <span>{d.users.length === 1 ? d.users[0] : `${d.users.length} users`}</span>
            </span>
          )}
          <span className="discovery-card-meta-item discovery-card-meta-risk">
            Risk <strong>{(d.riskScore || 0).toFixed(0)}</strong>
          </span>
        </div>
        {showDetails && !compact && d.detailsMarkdown && (
          <div className="discovery-card-facts">
            <div className="discovery-card-facts-label">Attack Chain</div>
            <div className="discovery-card-facts-body">
              {d.detailsMarkdown
                .split(/\n/)
                .filter((line) => line.trim())
                .slice(0, 3)
                .map((line, i) => {
                  const cleaned = line.replace(/^[-*•]\s*/, "").replace(/[#*_`]/g, "").trim();
                  if (!cleaned) return null;
                  return (
                    <div key={i} className="discovery-card-facts-item">
                      <span className="discovery-card-facts-dot" />
                      <span>{cleaned}</span>
                    </div>
                  );
                })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function DetailView({
  discovery,
  detail,
  detailLoading,
  tab,
  setTab,
  expandedAlerts,
  setExpandedAlerts,
  openFlyout,
  getApp,
  onAcknowledge,
  onCreateCase,
  onOpenCaseChat,
}: {
  discovery: AttackDiscoveryFinding;
  detail: DiscoveryDetail | null;
  detailLoading: boolean;
  tab: "summary" | "flow" | "alerts" | "entities" | "signals";
  setTab: (t: "summary" | "flow" | "alerts" | "entities" | "signals") => void;
  expandedAlerts: Set<string>;
  setExpandedAlerts: React.Dispatch<React.SetStateAction<Set<string>>>;
  openFlyout: (type: string, value: string, x: number, y: number) => void;
  getApp: () => McpApp | null;
  onAcknowledge: () => void;
  onCreateCase: () => void;
  onOpenCaseChat: () => void;
}) {
  const sev = riskSeverity(discovery.riskScore || 0);
  const conf = (discovery.confidence || "low") as ConfidenceKey;
  const alertCount = discovery.alertCount || discovery.alertIds?.length || 0;
  const [takeActionOpen, setTakeActionOpen] = useState(false);
  const takeActionRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!takeActionOpen) return;
    const onClick = (e: MouseEvent) => {
      if (takeActionRef.current && !takeActionRef.current.contains(e.target as Node)) {
        setTakeActionOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [takeActionOpen]);

  return (
    <div className="discovery-detail">
      <div className="discovery-detail-top">
        <div className="discovery-detail-top-chips">
          <SeverityChip severity={sev} />
          <ConfidenceChip level={conf} />
        </div>
        <div className="take-action-dropdown" ref={takeActionRef}>
          <button
            type="button"
            className="discovery-detail-action take-action-trigger"
            aria-haspopup="menu"
            aria-expanded={takeActionOpen}
            onClick={() => setTakeActionOpen((v) => !v)}
          >
            Take Action
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: takeActionOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
              <path d="M2.5 3.75L5 6.25L7.5 3.75" />
            </svg>
          </button>
          {takeActionOpen && (
            <div className="take-action-menu" role="menu">
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
                  onAcknowledge();
                }}
              >
                Acknowledge discovery
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="discovery-detail-head">
        {discovery.mitreTactics && discovery.mitreTactics.length > 0 && (
          <div className="discovery-detail-tags">
            {discovery.mitreTactics.map((t) => (
              <span key={t} className="discovery-mitre-pill">{t}</span>
            ))}
          </div>
        )}
        <h2 className="discovery-detail-title">
          <SummaryContent
            text={detail?.titleWithReplacements || discovery.title}
            onEntity={openFlyout}
          />
        </h2>
        <div className="discovery-detail-subtitle">
          <SummaryContent
            text={detail?.summaryWithReplacements || discovery.summaryMarkdown || ""}
            onEntity={openFlyout}
          />
        </div>
      </div>

      <div className="discovery-detail-facts">
        <FactCol label="RISK SCORE" value={String((discovery.riskScore || 0).toFixed(0))} />
        <FactCol label="ALERTS" value={String(alertCount)} />
        <FactCol
          label="HOSTS"
          value={discovery.hosts?.join(", ") || "—"}
          entities={discovery.hosts?.map((h) => ({ type: "host", value: h }))}
          onEntityClick={openFlyout}
          truncate
        />
        <FactCol
          label="USERS"
          value={discovery.users?.join(", ") || "—"}
          entities={discovery.users?.map((u) => ({ type: "user", value: u }))}
          onEntityClick={openFlyout}
          truncate
        />
        <FactCol label="TIMESTAMP" value={timeAgo(discovery.timestamp)} />
      </div>

      <div className="discovery-detail-tabs">
        <button className={`discovery-detail-tab${tab === "summary" ? " active" : ""}`} onClick={() => setTab("summary")}>
          Summary
        </button>
        {discovery.mitreTactics && discovery.mitreTactics.length > 0 && (
          <button className={`discovery-detail-tab${tab === "flow" ? " active" : ""}`} onClick={() => setTab("flow")}>
            Attack Flow
            <span className="discovery-detail-tab-count">{discovery.mitreTactics.length}</span>
          </button>
        )}
        <button className={`discovery-detail-tab${tab === "alerts" ? " active" : ""}`} onClick={() => setTab("alerts")}>
          Alerts
          <span className="discovery-detail-tab-count">{detail?.alerts?.length ?? "…"}</span>
        </button>
        <button className={`discovery-detail-tab${tab === "entities" ? " active" : ""}`} onClick={() => setTab("entities")}>
          Entity Risk
          <span className="discovery-detail-tab-count">{detail?.entityRisk?.length ?? "…"}</span>
        </button>
        {discovery.signals && (
          <button className={`discovery-detail-tab${tab === "signals" ? " active" : ""}`} onClick={() => setTab("signals")}>
            Signals
          </button>
        )}
      </div>

      {detailLoading && (
        <div className="loading-state" style={{ padding: "30px 20px" }}>
          <div className="loading-spinner" />
          <span>Enriching finding...</span>
        </div>
      )}

      {tab === "summary" && !detailLoading && (
        <div className="discovery-detail-section">
          {(detail?.detailsWithReplacements || discovery.detailsMarkdown) ? (
            <div className="details-timeline">
              <div className="details-timeline-title">Attack Chain</div>
              {(detail?.detailsWithReplacements || discovery.detailsMarkdown || "")
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
          ) : (
            <div className="discovery-detail-description">
              <SummaryContent
                text={detail?.summaryWithReplacements || discovery.summaryMarkdown || ""}
                onEntity={openFlyout}
              />
            </div>
          )}
        </div>
      )}

      {tab === "flow" && discovery.mitreTactics && discovery.mitreTactics.length > 0 && (
        <div className="discovery-detail-section">
          <AttackFlowDiagram discovery={discovery} detail={detail} getApp={getApp} />
        </div>
      )}

      {tab === "alerts" && !detailLoading && detail?.alerts && (
        <div className="discovery-detail-section">
          {detail.alerts.length === 0 ? (
            <div className="empty-state" style={{ padding: "30px" }}>No alerts loaded</div>
          ) : (
            detail.alerts.map((a) => {
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
            })
          )}
        </div>
      )}

      {tab === "entities" && !detailLoading && detail?.entityRisk && (
        <div className="discovery-detail-section">
          {detail.entityRisk.length === 0 ? (
            <div className="empty-state" style={{ padding: "30px" }}>No entity risk data available</div>
          ) : (
            detail.entityRisk.map((er) => {
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
            })
          )}
        </div>
      )}

      {tab === "signals" && discovery.signals && (
        <div className="discovery-detail-section">
          <div className="signals-grid">
            <div className="signal-card">
              <div className="signal-card-header">
                <span className="signal-card-title">Alert Diversity</span>
              </div>
              <div className="signal-card-value">{discovery.signals.alertDiversity.alertCount}</div>
              <div className="signal-card-detail">
                {discovery.signals.alertDiversity.ruleCount} rule{discovery.signals.alertDiversity.ruleCount !== 1 ? "s" : ""}
                {" "}&#183;{" "}
                {discovery.signals.alertDiversity.severities.join(", ") || "—"}
              </div>
            </div>
            <div className="signal-card">
              <div className="signal-card-header">
                <span className="signal-card-title">Rule Noise</span>
              </div>
              <div className="signal-card-value">
                {discovery.signals.ruleFrequency.length} rule{discovery.signals.ruleFrequency.length !== 1 ? "s" : ""}
              </div>
              <div className="signal-card-detail">
                {discovery.signals.ruleFrequency.map((rf) => (
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
                {discovery.signals.entityRisk.length} entit{discovery.signals.entityRisk.length !== 1 ? "ies" : "y"}
              </div>
              <div className="signal-card-detail">
                {discovery.signals.entityRisk.map((er) => (
                  <div key={`${er.type}:${er.name}`} style={{ marginBottom: 2 }}>
                    <span style={{ color: entityRiskColor(er.riskLevel) }}>{er.riskLevel}</span>
                    {" "}&#8212;{" "}
                    {er.name} ({er.type})
                  </div>
                ))}
                {discovery.signals.entityRisk.length === 0 && "No risk data"}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

