import React, { useState, useEffect, useCallback, useRef } from "react";
import { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { applyTheme, timeAgo } from "../../shared/theme";
import { extractToolText, extractCallResult } from "../../shared/extract-tool-text";
import type { KibanaCase } from "../../shared/types";
import { CaseList } from "./components/CaseList";
import { CaseDetail } from "./components/CaseDetail";
import { CaseForm } from "./components/CaseForm";
import "./styles.css";

type ViewMode = "browse" | "create";

interface CaseListParams {
  status: string;
  search?: string;
}

const SearchIcon = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <circle cx="11" cy="11" r="7" />
    <path d="m21 21-4.35-4.35" />
  </svg>
);

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
  const paramsRef = useRef<CaseListParams>({ status: "open" });
  const [statusFilter, setStatusFilter] = useState("open");

  const loadCases = useCallback(async (app?: McpApp, override?: Partial<CaseListParams>) => {
    const mcpApp = app || appRef.current;
    if (!mcpApp) return;
    setLoading(true);
    try {
      if (override) {
        paramsRef.current = { ...paramsRef.current, ...override };
        if (override.status !== undefined) setStatusFilter(override.status);
      }
      const { status, search } = paramsRef.current;
      const result = await mcpApp.callServerTool({
        name: "list-cases",
        arguments: {
          status,
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
    const app = new McpApp({ name: "case-management", version: "0.1.0" });
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
            if (next.status) setStatusFilter(next.status);
          }
        }
      } catch {
        /* ignore */
      }
      loadCases(app);
    };

    app.connect().then(() => {
      setConnected(true);
      setTimeout(() => {
        if (!gotResult) loadCases(app);
      }, 1500);
    });

    return () => {
      app.close();
    };
  }, [loadCases]);

  const openCase = useCallback(async (caseId: string) => {
    if (!appRef.current) return;
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
    } catch (e) {
      console.error("Failed to load case:", e);
    }
  }, []);

  const createCase = useCallback(
    async (data: { title: string; description: string; tags: string; severity: string }) => {
      if (!appRef.current) return;
      try {
        await appRef.current.callServerTool({ name: "create-case", arguments: data });
        setViewMode("browse");
        setSelectedCase(null);
        await loadCases();
      } catch (e) {
        console.error("Failed to create case:", e);
      }
    },
    [loadCases]
  );

  const updateCaseStatus = useCallback(
    async (caseId: string, version: string, status: string) => {
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
    },
    [loadCases, openCase, selectedCase?.id]
  );

  const addComment = useCallback(
    async (caseId: string, comment: string) => {
      if (!appRef.current) return;
      try {
        await appRef.current.callServerTool({
          name: "add-case-comment",
          arguments: { caseId, comment },
        });
        await openCase(caseId);
        await loadCases();
      } catch (e) {
        console.error("Failed to add comment:", e);
      }
    },
    [loadCases, openCase]
  );

  const handleSearch = useCallback(
    (q: string) => {
      loadCases(undefined, { search: q.trim() || undefined });
    },
    [loadCases]
  );

  const clearSearch = useCallback(() => {
    setSearchInput("");
    loadCases(undefined, { search: undefined });
  }, [loadCases]);

  const setStatus = useCallback(
    (s: string) => {
      loadCases(undefined, { status: s });
    },
    [loadCases]
  );

  if (!connected) {
    return (
      <div className="loading-state">
        <div className="loading-spinner" />
        Connecting…
      </div>
    );
  }

  const activeSearch = paramsRef.current.search;
  const hasDetail = !!selectedCase && viewMode === "browse";

  return (
    <div className="app-layout">
      <header className="filter-bar">
        <span className="filter-bar-title">Security Cases</span>
        {!loading && <span className="filter-bar-count">{total} case{total !== 1 ? "s" : ""}</span>}
        {activeSearch && (
          <span className="query-pill">
            {activeSearch}
            <button type="button" onClick={clearSearch} aria-label="Clear search">
              &times;
            </button>
          </span>
        )}
        <div className="case-status-filters">
          {(["open", "in-progress", "closed"] as const).map((s) => (
            <button
              key={s}
              type="button"
              className={`case-status-filter ${statusFilter === s ? "active" : ""}`}
              onClick={() => setStatus(s)}
            >
              {s === "in-progress" ? "In progress" : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        <div className="filter-bar-actions">
          <div className="filter-bar-search">
            <SearchIcon />
            <input
              type="search"
              placeholder="Search cases…"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSearch(searchInput);
                if (e.key === "Escape") {
                  setSearchInput("");
                  clearSearch();
                }
              }}
            />
          </div>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => {
              setViewMode("create");
              setSelectedCase(null);
            }}
          >
            + New case
          </button>
        </div>
      </header>

      <div className="app-body">
        <div className={`list-pane ${hasDetail || viewMode === "create" ? "narrow" : ""}`}>
          {loading && !cases.length ? (
            <div className="loading-state">
              <div className="loading-spinner" />
              Loading cases…
            </div>
          ) : viewMode === "create" ? (
            <div className="empty-state animate-in" style={{ "--i": 0 } as React.CSSProperties}>
              Fill in the form on the right to create a case.
            </div>
          ) : !cases.length ? (
            <div className="empty-state animate-in" style={{ "--i": 0 } as React.CSSProperties}>
              {activeSearch ? `No cases matching “${activeSearch}”.` : "No cases in this view."}
            </div>
          ) : (
            <CaseList
              cases={cases}
              selectedId={selectedCase?.id}
              onSelect={(c) => openCase(c.id)}
              timeAgo={timeAgo}
            />
          )}
        </div>

        <div className="detail-pane">
          {viewMode === "create" ? (
            <div className="case-form-panel animate-in" style={{ "--i": 1 } as React.CSSProperties}>
              <button
                type="button"
                className="back-btn"
                onClick={() => setViewMode("browse")}
              >
                ← Back to cases
              </button>
              <CaseForm onSubmit={createCase} />
            </div>
          ) : hasDetail && selectedCase ? (
            <div className="animate-in" style={{ "--i": 1 } as React.CSSProperties}>
              <button
                type="button"
                className="back-btn"
                onClick={() => setSelectedCase(null)}
              >
                ← Back to list
              </button>
              <CaseDetail
                caseData={selectedCase}
                onUpdateStatus={(status) =>
                  updateCaseStatus(selectedCase.id, selectedCase.version, status)
                }
                onAddComment={(comment) => addComment(selectedCase.id, comment)}
                timeAgo={timeAgo}
              />
            </div>
          ) : (
            <div className="case-detail-empty animate-in" style={{ "--i": 1 } as React.CSSProperties}>
              Select a case to view details, or create a new one.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
