import React, { useState } from "react";
import type { EsqlResult } from "../../../shared/types";

interface ResultsTableProps {
  results: EsqlResult | null;
  executing: boolean;
  hasExecuted: boolean;
  queryError: string | null;
  onEntityClick?: (type: "user" | "host" | "ip" | "process", value: string) => void;
}

const ENTITY_COLUMNS: Record<string, "user" | "host" | "ip" | "process"> = {
  "user.name": "user",
  "host.name": "host",
  "source.ip": "ip",
  "destination.ip": "ip",
  "process.name": "process",
  "process.parent.name": "process",
};

export function ResultsTable({ results, executing, hasExecuted, queryError, onEntityClick }: ResultsTableProps) {
  const [view, setView] = useState<"table" | "chart">("table");

  if (executing) {
    return (
      <div className="results-panel animate-in">
        <div className="results-header">
          <span className="results-header-title">Results</span>
          <span className="results-count">Running...</span>
        </div>
        <div className="results-loading">
          <div className="loading-spinner" />
          <span>Executing query...</span>
        </div>
      </div>
    );
  }

  if (!hasExecuted || results === null) {
    return (
      <div className="results-panel animate-in">
        <div className="results-header">
          <span className="results-header-title">Results</span>
        </div>
        <div className="results-empty">
          {hasExecuted && queryError ? (
            <>
              <span className="results-empty-title">Query failed</span>
              <span className="results-empty-hint">Fix the error above and run again.</span>
            </>
          ) : (
            <>
              <span className="results-empty-title">No results yet</span>
              <span className="results-empty-hint">
                Write an ES|QL query, then press <strong>Cmd+Enter</strong> to execute.
              </span>
            </>
          )}
        </div>
      </div>
    );
  }

  const rowCount = results.values?.length ?? 0;
  const colCount = results.columns?.length ?? 0;
  const chartData = extractChartData(results);
  const canChart = chartData !== null;

  return (
    <div className="results-panel animate-in">
      <div className="results-header">
        <span className="results-header-title">Results</span>
        <span className="results-count">{rowCount} rows &middot; {colCount} columns</span>
        {canChart && (
          <div style={{ marginLeft: "auto", display: "flex", gap: 2 }}>
            <button
              className={`btn btn-sm ${view === "table" ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setView("table")}
            >Table</button>
            <button
              className={`btn btn-sm ${view === "chart" ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setView("chart")}
            >Chart</button>
          </div>
        )}
      </div>

      {view === "chart" && chartData ? (
        <BarChart data={chartData} />
      ) : (
        <div className="results-scroll">
          <table className="data-table">
            <thead>
              <tr>
                {results.columns.map((col, i) => (
                  <th key={i} title={`${col.name} (${col.type})`}>{col.name}</th>
                ))}
              </tr>
            </thead>
            <tbody>
            {results.values.map((row, ri) => (
              <tr key={ri}>
                {row.map((cell, ci) => {
                  const colName = results.columns[ci]?.name || "";
                  const entityType = ENTITY_COLUMNS[colName];
                  const cellStr = formatCell(cell);
                  const isClickable = entityType && onEntityClick && cellStr !== "\u2014" && cellStr.length > 0;
                  return (
                    <td key={ci} title={String(cell ?? "")}
                      onClick={isClickable ? () => onEntityClick(entityType, cellStr) : undefined}
                      style={isClickable ? { color: "var(--accent)", cursor: "pointer", textDecoration: "underline", textDecorationColor: "rgba(92,124,250,0.3)" } : undefined}
                    >{cellStr}</td>
                  );
                })}
              </tr>
            ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

interface ChartItem { label: string; value: number }

function extractChartData(results: EsqlResult): ChartItem[] | null {
  if (!results.columns || results.columns.length < 2 || results.values.length === 0) return null;

  const numericTypes = new Set(["long", "integer", "double", "float", "unsigned_long", "short", "byte"]);
  const numIdx = results.columns.findIndex((c) => numericTypes.has(c.type));
  if (numIdx === -1) return null;

  const labelIdx = results.columns.findIndex((c, i) => i !== numIdx && (c.type === "keyword" || c.type === "text" || !numericTypes.has(c.type)));
  if (labelIdx === -1) return null;

  const items: ChartItem[] = [];
  for (const row of results.values.slice(0, 25)) {
    const label = String(row[labelIdx] ?? "");
    const value = Number(row[numIdx]) || 0;
    if (label && value > 0) items.push({ label, value });
  }

  return items.length >= 2 ? items : null;
}

function BarChart({ data }: { data: ChartItem[] }) {
  const maxValue = Math.max(...data.map((d) => d.value));

  return (
    <div style={{ padding: "16px 20px", maxHeight: 500, overflowY: "auto" }}>
      {data.map((item, i) => (
        <div key={i} style={{
          display: "flex", alignItems: "center", gap: 10,
          marginBottom: 6, animation: "fadeInUp 0.3s ease-out both",
          animationDelay: `${i * 30}ms`,
        }}>
          <span style={{
            flex: "0 0 180px", fontSize: 11, fontFamily: "var(--font-mono)",
            color: "var(--text-secondary)", overflow: "hidden",
            textOverflow: "ellipsis", whiteSpace: "nowrap", textAlign: "right",
          }} title={item.label}>
            {item.label}
          </span>
          <div style={{
            flex: 1, height: 22, background: "var(--bg-primary)",
            borderRadius: "var(--radius-sm)", overflow: "hidden",
          }}>
            <div style={{
              height: "100%", borderRadius: "var(--radius-sm)",
              background: `linear-gradient(90deg, var(--accent), var(--accent-hover))`,
              width: `${(item.value / maxValue) * 100}%`,
              transition: "width 0.5s cubic-bezier(0.4, 0, 0.2, 1)",
              display: "flex", alignItems: "center", justifyContent: "flex-end",
              paddingRight: 8,
            }}>
              {item.value / maxValue > 0.15 && (
                <span style={{ fontSize: 10, fontWeight: 700, color: "white", fontFamily: "var(--font-mono)" }}>
                  {item.value.toLocaleString()}
                </span>
              )}
            </div>
          </div>
          {item.value / maxValue <= 0.15 && (
            <span style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", fontFamily: "var(--font-mono)", minWidth: 40 }}>
              {item.value.toLocaleString()}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return "\u2014";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
