/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import React, { useState, useEffect, useCallback, useRef } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme } from "../../shared/theme";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import type { DetectionRule } from "../../shared/types";
import { RuleList } from "./components/RuleList";
import { RuleEditor } from "./components/RuleEditor";
import { RuleTestPanel } from "./components/RuleTestPanel";
import "./styles.css";

type View = "list" | "detail" | "noisy";

type NoisyRuleRow = { ruleName: string; ruleId: string; alertCount: number };

const SearchIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <circle cx="11" cy="11" r="7" />
    <path d="m21 21-4.35-4.35" />
  </svg>
);

export function App() {
  const appRef = useRef<McpApp | null>(null);
  const [connected, setConnected] = useState(false);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [total, setTotal] = useState(0);
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);
  const [view, setView] = useState<View>("list");
  const [searchFilter, setSearchFilter] = useState("");
  const [noisyRules, setNoisyRules] = useState<NoisyRuleRow[]>([]);
  const [listLoading, setListLoading] = useState(true);
  const [noisyLoading, setNoisyLoading] = useState(false);

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
    const app = new McpApp({ name: "detection-rules", version: "0.1.0" });
    appRef.current = app;
    applyTheme(app);

    let gotResult = false;
    app.ontoolresult = (params) => {
      gotResult = true;
      try {
        const text = extractToolText(params);
        if (text) {
          const data = JSON.parse(text);
          if (typeof data.params?.filter === "string") setSearchFilter(data.params.filter);
        }
      } catch {
        /* ignore param extract */
      }
      loadRules(undefined, app);
    };

    app.connect().then(() => {
      setConnected(true);
      setTimeout(() => {
        if (!gotResult) loadRules(undefined, app);
      }, 1500);
    });

    return () => {
      app.close();
    };
  }, [loadRules]);

  const openRule = useCallback(async (id: string) => {
    if (!appRef.current) return;
    try {
      const result = await appRef.current.callServerTool({ name: "get-rule", arguments: { id } });
      const text = extractCallResult(result);
      if (text) {
        setSelectedRule(JSON.parse(text));
        setView("detail");
      }
    } catch (e) {
      console.error("Failed to load rule:", e);
    }
  }, []);

  const toggleRule = useCallback(
    async (id: string, enabled: boolean) => {
      if (!appRef.current) return;
      try {
        await appRef.current.callServerTool({ name: "toggle-rule", arguments: { id, enabled } });
        await loadRules(searchFilter);
        if (selectedRule?.id === id) {
          const result = await appRef.current.callServerTool({ name: "get-rule", arguments: { id } });
          const text = extractCallResult(result);
          if (text) setSelectedRule(JSON.parse(text));
        }
      } catch (e) {
        console.error("Failed to toggle rule:", e);
      }
    },
    [loadRules, searchFilter, selectedRule?.id],
  );

  const validateQuery = useCallback(async (query: string, language: string): Promise<{ valid: boolean; error?: string }> => {
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
    setNoisyLoading(true);
    setNoisyRules([]);
    try {
      const result = await appRef.current.callServerTool({ name: "noisy-rules", arguments: { days: 7, limit: 20 } });
      const text = extractCallResult(result);
      if (text) setNoisyRules(JSON.parse(text));
    } catch (e) {
      console.error("Failed to load noisy rules:", e);
    } finally {
      setNoisyLoading(false);
    }
  }, []);

  const goBackToList = useCallback(() => {
    setView("list");
    setSelectedRule(null);
  }, []);

  const runSearch = useCallback(() => {
    loadRules(searchFilter);
  }, [loadRules, searchFilter]);

  if (!connected) {
    return (
      <div className="app-layout detection-rules-app">
        <div className="loading-state">
          <div className="loading-spinner" />
          <span>Connecting…</span>
        </div>
      </div>
    );
  }

  if (view === "noisy") {
    const maxCount = noisyRules[0]?.alertCount || 1;
    return (
      <div className="app-layout detection-rules-app">
        <header className="filter-bar">
          <span className="filter-bar-title">Noisy rules</span>
          <span className="filter-bar-count">Last 7 days · top {noisyRules.length}</span>
          <div className="filter-bar-actions">
            <button type="button" className="btn btn-sm" onClick={goBackToList}>
              ← Rules
            </button>
          </div>
        </header>
        <div className="app-body">
          <div className="detail-pane" style={{ flex: 1 }}>
            <div className="noisy-view-card animate-in" style={{ ["--i" as string]: 0 }}>
              <h2 className="noisy-view-title">Noisiest detection rules</h2>
              <p className="noisy-view-sub">Ranked by alert volume. Use this to tune or disable high-chatter rules.</p>
              {noisyLoading ? (
                <div className="loading-state" style={{ padding: 48 }}>
                  <div className="loading-spinner" />
                  <span>Loading volume data…</span>
                </div>
              ) : noisyRules.length === 0 ? (
                <div className="empty-state">No noisy-rule data available for this window.</div>
              ) : (
                <table className="noisy-table">
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th style={{ width: 100 }}>Alerts</th>
                      <th style={{ width: "38%" }}>Relative volume</th>
                    </tr>
                  </thead>
                  <tbody>
                    {noisyRules.map((r, i) => (
                      <tr key={r.ruleId} className="animate-in" style={{ ["--i" as string]: Math.min(i, 12) }}>
                        <td className="cell-name" title={r.ruleName}>
                          {r.ruleName}
                        </td>
                        <td className="cell-count">{r.alertCount.toLocaleString()}</td>
                        <td>
                          <div className="noisy-bar-track">
                            <div className="noisy-bar" style={{ width: `${(r.alertCount / maxCount) * 100}%` }} />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-layout detection-rules-app">
      <header className="filter-bar">
        <span className="filter-bar-title">Detection Rules</span>
        <span className="filter-bar-count">
          {listLoading ? "…" : `${rules.length}${total > rules.length ? ` of ${total}` : ""}`}
        </span>
        <div className="filter-bar-search">
          <SearchIcon />
          <input
            type="text"
            placeholder="KQL filter…"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runSearch()}
            aria-label="KQL search"
          />
        </div>
        <div className="filter-bar-actions">
          <button type="button" className="btn btn-sm btn-primary" onClick={runSearch}>
            Search
          </button>
          <button type="button" className="btn btn-sm" onClick={loadNoisyRules} disabled={noisyLoading}>
            {noisyLoading ? "Loading…" : "Noisy Rules"}
          </button>
        </div>
      </header>

      <div className="app-body">
        <div className="list-pane narrow">
          {listLoading ? (
            <div className="loading-state">
              <div className="loading-spinner" />
              <span>Loading rules…</span>
            </div>
          ) : rules.length === 0 ? (
            <div className="empty-state">No rules match this filter.</div>
          ) : (
            <RuleList
              rules={rules}
              selectedId={selectedRule?.id ?? null}
              onSelect={(r) => openRule(r.id)}
              onToggle={toggleRule}
            />
          )}
        </div>

        <div className="detail-pane">
          {view === "detail" && selectedRule ? (
            <div key={selectedRule.id}>
              <button type="button" className="back-btn" onClick={goBackToList}>
                ← Back to list
              </button>
              <div className="animate-in" style={{ ["--i" as string]: 0 }}>
                <RuleEditor rule={selectedRule} onToggle={(enabled) => toggleRule(selectedRule.id, enabled)} />
              </div>
              {selectedRule.query ? (
                <div className="animate-in" style={{ ["--i" as string]: 1 }}>
                  <RuleTestPanel
                    query={selectedRule.query}
                    language={selectedRule.language || "kuery"}
                    onValidate={validateQuery}
                  />
                </div>
              ) : null}
            </div>
          ) : (
            <div className="rules-detail-empty animate-in" style={{ ["--i" as string]: 0 }}>
              <div className="rules-detail-empty-title">Select a rule</div>
              <div>Choose a detection rule from the list to inspect query, MITRE mapping, and validation.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
