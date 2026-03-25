import React from "react";
import { severityColor } from "../../../shared/severity";
import type { AlertSummary, SecurityAlert } from "../../../shared/types";

interface SummaryPanelProps {
  summary: AlertSummary;
  query?: string;
}

export function SummaryPanel({ summary, query }: SummaryPanelProps) {
  const topHosts = summary.byHost.slice(0, 6);
  const topRules = summary.byRule.slice(0, 6);
  const maxHostCount = topHosts[0]?.count || 1;
  const maxRuleCount = topRules[0]?.count || 1;

  const mitreTactics = extractMitreTactics(summary.alerts);

  return (
    <div className="summary-panel">
      <div className="summary-grid">
        {/* Hosts */}
        <div className="summary-section">
          <div className="summary-section-title">
            <span>Affected Hosts</span>
            <span className="summary-section-count">{summary.byHost.length}</span>
          </div>
          {topHosts.map((h) => (
            <div key={h.name} className="summary-bar-row">
              <span className="summary-bar-label" title={h.name}>{h.name}</span>
              <div className="summary-bar-track">
                <div
                  className="summary-bar-fill summary-bar-host"
                  style={{ width: `${(h.count / maxHostCount) * 100}%` }}
                />
              </div>
              <span className="summary-bar-value">{h.count}</span>
            </div>
          ))}
        </div>

        {/* Rules */}
        <div className="summary-section">
          <div className="summary-section-title">
            <span>Detection Rules</span>
            <span className="summary-section-count">{summary.byRule.length}</span>
          </div>
          {topRules.map((r) => (
            <div key={r.name} className="summary-bar-row">
              <span className="summary-bar-label" title={r.name}>{r.name}</span>
              <div className="summary-bar-track">
                <div
                  className="summary-bar-fill summary-bar-rule"
                  style={{ width: `${(r.count / maxRuleCount) * 100}%` }}
                />
              </div>
              <span className="summary-bar-value">{r.count}</span>
            </div>
          ))}
        </div>

        {/* MITRE + Severity */}
        <div className="summary-section">
          <div className="summary-section-title">
            <span>Severity Distribution</span>
          </div>
          <div className="severity-bars">
            {Object.entries(summary.bySeverity)
              .sort(([, a], [, b]) => b - a)
              .map(([sev, count]) => (
                <div key={sev} className="severity-bar-row">
                  <span className="severity-bar-label">{sev}</span>
                  <div className="summary-bar-track">
                    <div
                      className="summary-bar-fill"
                      style={{
                        width: `${(count / summary.total) * 100}%`,
                        backgroundColor: severityColor(sev),
                      }}
                    />
                  </div>
                  <span className="summary-bar-value">{count}</span>
                </div>
              ))}
          </div>
          {mitreTactics.length > 0 && (
            <>
              <div className="summary-section-title" style={{ marginTop: 12 }}>
                <span>MITRE ATT&CK</span>
              </div>
              <div className="summary-mitre">
                {mitreTactics.map((t) => (
                  <span key={t.id} className="mitre-tag mitre-tactic" title={t.name}>
                    {t.name}
                    <span style={{ opacity: 0.6, marginLeft: 4 }}>{t.count}</span>
                  </span>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function extractMitreTactics(alerts: SecurityAlert[]): { id: string; name: string; count: number }[] {
  const map = new Map<string, { name: string; count: number }>();
  for (const alert of alerts) {
    const threats = alert._source["kibana.alert.rule.threat"];
    if (!threats) continue;
    for (const t of threats) {
      const existing = map.get(t.tactic.id);
      if (existing) {
        existing.count++;
      } else {
        map.set(t.tactic.id, { name: t.tactic.name, count: 1 });
      }
    }
  }
  return Array.from(map.entries())
    .map(([id, v]) => ({ id, ...v }))
    .sort((a, b) => b.count - a.count);
}
