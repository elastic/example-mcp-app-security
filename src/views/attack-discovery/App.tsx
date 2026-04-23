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
import { SeverityBadge } from "../../shared/severity";
import type { AttackDiscoveryFinding, DiscoveryDetail } from "../../shared/types";
import { AttackFlowDiagram } from "./AttackFlowDiagram";
import "./styles.css";

type ConfidenceKey = "high" | "moderate" | "low";
type SeverityKey = "critical" | "high" | "medium" | "low";
type ConfidenceFilter = "all" | ConfidenceKey;

const CONFIDENCE_LABEL: Record<ConfidenceKey, string> = {
  high: "High",
  moderate: "Moderate",
  low: "Low",
};

const CONFIDENCE_FILTERS: { key: ConfidenceFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "high", label: "High confidence" },
  { key: "moderate", label: "Moderate" },
  { key: "low", label: "Low" },
];

const SEVERITY_ORDER: SeverityKey[] = ["critical", "high", "medium", "low"];
const SEVERITY_LABEL: Record<SeverityKey, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};
const SEVERITY_STROKE: Record<SeverityKey, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
};

type SortKey = "risk" | "confidence" | "newest" | "oldest" | "alerts" | "title";
const SORT_LABEL: Record<SortKey, string> = {
  risk: "Risk score",
  confidence: "Confidence",
  newest: "Newest first",
  oldest: "Oldest first",
  alerts: "Alert count",
  title: "Title (A–Z)",
};
const CONFIDENCE_RANK: Record<string, number> = { high: 3, moderate: 2, low: 1 };

type GroupKey = "none" | "host" | "user" | "confidence" | "tactic";
const GROUP_LABEL: Record<GroupKey, string> = {
  none: "None",
  host: "Host",
  user: "User",
  confidence: "Confidence",
  tactic: "Tactic",
};

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

const RefreshIcon = () => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3.5 7a4.5 4.5 0 0 1 8-2.5L13 6" />
    <path d="M12.5 9a4.5 4.5 0 0 1-8 2.5L3 10" />
    <path d="M13 3v3h-3" />
    <path d="M3 13v-3h3" />
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

function ConfidenceChip({ level }: { level: ConfidenceKey }) {
  return (
    <span className={`conf-chip conf-chip-${level}`} aria-label={`Confidence: ${CONFIDENCE_LABEL[level]}`}>
      <span className="conf-chip-dot" />
      <span className="conf-chip-label">{CONFIDENCE_LABEL[level]}</span>
    </span>
  );
}

/**
 * Severity donut chart — matches the one in detection-rules and alert-triage
 * so the "By severity" widget renders identically across every view.
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
        aria-label={`Severity breakdown: ${total} discoveries total`}
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
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
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
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [flyout, setFlyout] = useState<FlyoutState | null>(null);
  const [expandedAlerts, setExpandedAlerts] = useState<Set<string>>(new Set());
  const [confidenceFilter, setConfidenceFilter] = useState<ConfidenceFilter>("all");
  const [confidenceMenuOpen, setConfidenceMenuOpen] = useState(false);
  const confidenceRef = useRef<HTMLDivElement | null>(null);
  const [showDetails, setShowDetails] = useState(false);
  const [sortBy, setSortBy] = useState<SortKey>("risk");
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const sortRef = useRef<HTMLDivElement | null>(null);
  const [groupBy, setGroupBy] = useState<GroupKey>("none");
  const [groupMenuOpen, setGroupMenuOpen] = useState(false);
  const groupRef = useRef<HTMLDivElement | null>(null);
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const paramsRef = useRef<{ days: number; limit: number }>({ days: 1, limit: 50 });

  const checkGenerationStatus = useCallback(async (app?: McpApp) => {
    const mcpApp = app || appRef.current;
    if (!mcpApp) return;
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
  }, [assessConfidence]);

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
    const app = new McpApp({ name: "attack-discovery-triage", version: "1.0.0" });
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
      checkGenerationStatus(app);
    });

    return () => { appRef.current = null; };
  }, [loadDiscoveries, checkGenerationStatus]);

  useEffect(() => {
    if (!connected || !generations.some((g) => g.status === "started")) return;
    const interval = setInterval(async () => {
      await checkGenerationStatus();
      await loadDiscoveries();
    }, 10000);
    return () => clearInterval(interval);
  }, [connected, generations, checkGenerationStatus, loadDiscoveries]);

  useEffect(() => {
    if (!flyout) return;
    const close = () => setFlyout(null);
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, [flyout]);

  useEffect(() => {
    if (!confidenceMenuOpen) return;
    const onClick = (e: MouseEvent) => {
      if (confidenceRef.current && !confidenceRef.current.contains(e.target as Node)) {
        setConfidenceMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [confidenceMenuOpen]);

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

  // Group filtered discoveries by the selected key. A single discovery can land in multiple
  // buckets when grouping by host/user/tactic (since each discovery may reference many of each).
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
    setGroupMenuOpen(false);
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
    return <div className="loading-state"><div className="loading-spinner" />Connecting...</div>;
  }

  return (
    <div className="discoveries-app">
      <header className="discoveries-header">
        <div className="discoveries-header-left">
          <div className="discoveries-header-brand">
            <span className="discoveries-header-glyph" aria-hidden="true"><AppGlyph /></span>
            <h1 className="discoveries-header-title">Attack Discovery</h1>
          </div>
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
          {activeQuery && (
            <span className="query-pill">
              {activeQuery}
              <button onClick={clearSearch} aria-label="Clear filter">
                <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                  <path d="m7.293 8-3.147 3.146a.5.5 0 0 0 .708.708L8 8.707l3.146 3.147a.5.5 0 0 0 .708-.708L8.707 8l3.147-3.146a.5.5 0 1 0-.708-.708L8 7.293 4.854 4.146a.5.5 0 1 0-.708.708L7.293 8Z" />
                </svg>
              </button>
            </span>
          )}
        </div>
        <div className="discoveries-header-actions">
          <div className="discoveries-confidence-dropdown" ref={confidenceRef}>
            <button
              type="button"
              className="discoveries-confidence-dropdown-trigger"
              onClick={() => setConfidenceMenuOpen((v) => !v)}
              aria-haspopup="listbox"
              aria-expanded={confidenceMenuOpen}
            >
              <span>Confidence: <span className="discoveries-confidence-dropdown-value">{CONFIDENCE_FILTERS.find((f) => f.key === confidenceFilter)?.label ?? "All"}</span></span>
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: confidenceMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                <path d="M2 3.5 5 6.5 8 3.5" />
              </svg>
            </button>
            {confidenceMenuOpen && (
              <div className="discoveries-confidence-dropdown-menu" role="listbox">
                {CONFIDENCE_FILTERS.map((f) => {
                  const count = f.key === "all"
                    ? discoveries.length
                    : summary.byConfidence[f.key as ConfidenceKey];
                  return (
                    <button
                      key={f.key}
                      type="button"
                      role="option"
                      aria-selected={f.key === confidenceFilter}
                      className={`discoveries-confidence-dropdown-option${f.key === confidenceFilter ? " active" : ""}`}
                      onClick={() => { setConfidenceFilter(f.key); setConfidenceMenuOpen(false); }}
                    >
                      <span>{f.label}</span>
                      <span className="discoveries-confidence-dropdown-option-count">{count}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
          <div className="discoveries-header-search">
            <SearchIcon />
            <input
              type="text"
              placeholder="Filter discoveries..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") runSearch();
                if (e.key === "Escape") clearSearch();
              }}
            />
          </div>
          <button
            type="button"
            className="discoveries-header-icon-btn"
            onClick={() => { loadDiscoveries(); checkGenerationStatus(); }}
            title="Refresh"
            aria-label="Refresh"
          >
            <RefreshIcon />
          </button>
          <button
            type="button"
            className="discoveries-header-icon-btn"
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

      <div className="discoveries-body">
        <div className={`discoveries-list-pane ${hasDetail ? "narrow" : ""}`}>
          {hasDetail && (
            <button
              type="button"
              className="discoveries-list-back"
              onClick={() => { setSelected(null); setDetail(null); }}
            >
              <span aria-hidden="true">&larr;</span> Back to list
            </button>
          )}

          {!hasDetail && discoveries.length > 0 && (
            <div className="discoveries-kpi-strip">
              <div className="summary-section">
                <div className="summary-section-title">By severity</div>
                <SeverityDonut bySeverity={summary.bySeverity} />
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">Active attacks</div>
                <div className="kpi-tile-value-row">
                  <div className="kpi-tile-value">{discoveries.length}</div>
                  {summary.byConfidence.high > 0 && (
                    <span className="kpi-tile-meta-inline">{summary.byConfidence.high} high-confidence</span>
                  )}
                </div>
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">Peak risk</div>
                <div className="kpi-tile-value-row">
                  <div className="kpi-tile-value">{summary.peakRisk}</div>
                  <span className="kpi-tile-meta-inline">
                    {summary.latestTs ? timeAgo(new Date(summary.latestTs)) : "—"}
                  </span>
                </div>
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">MITRE tactics</div>
                <div className="kpi-tile-value-row">
                  <div className="kpi-tile-value">{summary.tactics}</div>
                  <span className="kpi-tile-meta-inline">{summary.totalAlerts} alerts linked</span>
                </div>
              </div>
              <div className="kpi-tile">
                <div className="kpi-tile-label">Entities at risk</div>
                <div className="kpi-tile-value-row">
                  <div className="kpi-tile-value">{summary.hosts + summary.users}</div>
                  <span className="kpi-tile-meta-inline">{summary.hosts} hosts · {summary.users} users</span>
                </div>
              </div>
            </div>
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
            <div className="discoveries-list-subheader">
              <div className="discoveries-list-subheader-left">
                <span className="discoveries-list-subheader-count">
                  Showing <strong>{filtered.length}</strong> discover{filtered.length !== 1 ? "ies" : "y"}
                </span>
                <div className="discoveries-list-subheader-sort" ref={sortRef}>
                  <button
                    type="button"
                    className="discoveries-list-subheader-sort-trigger"
                    onClick={() => setSortMenuOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={sortMenuOpen}
                  >
                    <span>Sort by: <span className="discoveries-list-subheader-sort-value">{SORT_LABEL[sortBy]}</span></span>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: sortMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                      <path d="M2.5 3.75L5 6.25L7.5 3.75" />
                    </svg>
                  </button>
                  {sortMenuOpen && (
                    <div className="discoveries-list-subheader-sort-menu" role="listbox">
                      {(Object.keys(SORT_LABEL) as SortKey[]).map((k) => (
                        <button
                          key={k}
                          type="button"
                          role="option"
                          aria-selected={k === sortBy}
                          className={`discoveries-list-subheader-sort-option${k === sortBy ? " active" : ""}`}
                          onClick={() => { setSortBy(k); setSortMenuOpen(false); }}
                        >
                          {SORT_LABEL[k]}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              <div className="discoveries-list-subheader-controls">
                <label className="discoveries-list-subheader-toggle">
                  <span className="discoveries-list-subheader-toggle-label">Details</span>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={showDetails}
                    aria-label="Toggle discovery details"
                    className={`toggle-switch${showDetails ? " on" : ""}`}
                    onClick={() => setShowDetails((v) => !v)}
                  >
                    <span className="toggle-switch-thumb" />
                  </button>
                </label>
                <div className="discoveries-list-subheader-sort discoveries-list-subheader-group" ref={groupRef}>
                  <button
                    type="button"
                    className="discoveries-list-subheader-sort-trigger"
                    onClick={() => setGroupMenuOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={groupMenuOpen}
                  >
                    <span>Group by: <span className="discoveries-list-subheader-sort-value">{GROUP_LABEL[groupBy]}</span></span>
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ transform: groupMenuOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }}>
                      <path d="M2.5 3.75L5 6.25L7.5 3.75" />
                    </svg>
                  </button>
                  {groupMenuOpen && (
                    <div className="discoveries-list-subheader-sort-menu discoveries-list-subheader-sort-menu-right" role="listbox">
                      {(Object.keys(GROUP_LABEL) as GroupKey[]).map((k) => (
                        <button
                          key={k}
                          type="button"
                          role="option"
                          aria-selected={k === groupBy}
                          className={`discoveries-list-subheader-sort-option${k === groupBy ? " active" : ""}`}
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

          <div className="discoveries-list-content">
            {loading && discoveries.length === 0 ? (
              <div className="loading-state"><div className="loading-spinner" />Loading attack discoveries...</div>
            ) : filtered.length === 0 ? (
              <div className="empty-state">
                <div style={{ fontSize: 28, marginBottom: 8 }}>&#128737;</div>
                <div>{activeQuery ? `No discoveries matching "${activeQuery}"` : "No open attack discoveries"}</div>
                <div style={{ fontSize: 12, marginTop: 4, color: "var(--text-muted)" }}>
                  {generations.some((g) => g.status === "started")
                    ? "A generation is in progress — results will appear here automatically."
                    : "Try adjusting the time range or running a new generation."}
                </div>
              </div>
            ) : groupedDiscoveries ? (
              groupedDiscoveries.length === 0 ? (
                <div className="empty-state">No discoveries have a {GROUP_LABEL[groupBy].toLowerCase()} to group by.</div>
              ) : (
                groupedDiscoveries.map((group, gi) => {
                  const expanded = openGroups.has(group.key);
                  return (
                    <div key={group.key} className="animate-in" style={{ "--i": gi } as React.CSSProperties}>
                      <DiscoveryGroupCard
                        group={group}
                        groupBy={groupBy}
                        expanded={expanded}
                        onToggle={() => toggleGroup(group.key)}
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
        </div>

        {hasDetail && selected && (
          <div className="detail-pane">
            <button
              type="button"
              className="detail-pane-close"
              onClick={() => { setSelected(null); setDetail(null); }}
              aria-label="Close discovery details"
            >
              <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <path d="m7.293 8-3.147 3.146a.5.5 0 0 0 .708.708L8 8.707l3.146 3.147a.5.5 0 0 0 .708-.708L8.707 8l3.147-3.146a.5.5 0 1 0-.708-.708L8 7.293 4.854 4.146a.5.5 0 1 0-.708.708L7.293 8Z" />
              </svg>
            </button>
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
            />
          </div>
        )}
      </div>

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

function DiscoveryGroupCard({ group, groupBy, expanded, onToggle }: {
  group: {
    key: string;
    name: string;
    subtitle?: string;
    topRisk: number;
    discoveries: AttackDiscoveryFinding[];
  };
  groupBy: GroupKey;
  expanded: boolean;
  onToggle: () => void;
}) {
  const sev = riskSeverity(group.topRisk);
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
          discoveries: <span className="group-card-count-value">{group.discoveries.length}</span>
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
        <h3 className="discovery-card-title">{d.title}</h3>
        {!compact && d.summaryMarkdown && (
          <p className="discovery-card-reason">
            {(d.summaryMarkdown || "").replace(/[#*_`]/g, "").slice(0, 200)}
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
}: {
  discovery: AttackDiscoveryFinding;
  detail: DiscoveryDetail | null;
  detailLoading: boolean;
  tab: "summary" | "flow" | "alerts" | "entities" | "signals";
  setTab: (t: "summary" | "flow" | "alerts" | "entities" | "signals") => void;
  expandedAlerts: Set<string>;
  setExpandedAlerts: React.Dispatch<React.SetStateAction<Set<string>>>;
  openFlyout: (type: string, value: string, x: number, y: number) => void;
}) {
  const sev = riskSeverity(discovery.riskScore || 0);
  const conf = (discovery.confidence || "low") as ConfidenceKey;
  const alertCount = discovery.alertCount || discovery.alertIds?.length || 0;

  return (
    <div className="discovery-detail">
      <div className="discovery-detail-top">
        <div className="discovery-detail-top-chips">
          <SeverityChip severity={sev} />
          <ConfidenceChip level={conf} />
        </div>
        <button type="button" className="discovery-detail-action">
          Take Action
        </button>
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
          <AttackFlowDiagram discovery={discovery} detail={detail} />
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

function FactCol({ label, value, truncate, entities, onEntityClick }: {
  label: string;
  value?: string;
  truncate?: boolean;
  entities?: { type: string; value: string }[];
  onEntityClick?: (type: string, value: string, x: number, y: number) => void;
}) {
  const hasEntities = entities && entities.length > 0 && onEntityClick;
  return (
    <div className="discovery-detail-fact">
      <div className="discovery-detail-fact-label">{label}</div>
      {hasEntities ? (
        <div className={`discovery-detail-fact-value${truncate ? " truncate" : ""}`} title={value || undefined}>
          {entities.map((e, i) => (
            <React.Fragment key={`${e.type}:${e.value}`}>
              {i > 0 && <span className="discovery-detail-fact-sep">, </span>}
              <button
                type="button"
                className="discovery-detail-fact-entity"
                onClick={(ev) => {
                  ev.stopPropagation();
                  const r = (ev.currentTarget as HTMLElement).getBoundingClientRect();
                  onEntityClick(e.type, e.value, r.left, r.bottom + 6);
                }}
                title={`${e.type}: ${e.value}`}
              >
                {e.value}
              </button>
            </React.Fragment>
          ))}
        </div>
      ) : (
        <div className={`discovery-detail-fact-value${truncate ? " truncate" : ""}`} title={value || undefined}>
          {value || "—"}
        </div>
      )}
    </div>
  );
}
