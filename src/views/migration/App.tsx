/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useCallback, useEffect, useMemo, useRef } from "react";
import type { App as McpApp } from "@modelcontextprotocol/ext-apps";
import { extractCallResult } from "../../shared/extract-tool-text";
import {
  AppHeader,
  AppShell,
  BackButton,
  EmptyState,
  KpiStrip,
  KpiTile,
  LoadingState,
} from "../../shared/components";
import { useFullscreen } from "../../shared/hooks/useFullscreen";
import { useMcpApp } from "../../shared/hooks/useMcpApp";
import "./styles.css";

// ---------------------------------------------------------------------------
// Local domain types (shapes returned by the app-only migration tools)
// ---------------------------------------------------------------------------

interface MigrationStats {
  id: string;
  name?: string;
  /** Lifecycle status returned by get-migration. */
  status: "ready" | "running" | "finished" | "error" | string;
  rules: {
    total: number;
    pending: number;
    processing: number;
    completed: number;
    failed: number;
    installable: number;
    installed: number;
    partially_translated: number;
    untranslatable: number;
  };
}

interface TranslatedRule {
  id: string;
  status: string;
  translation_result?: "full" | "partial" | "untranslatable";
  original_rule: Record<string, unknown>;
  elastic_rule?: Record<string, unknown>;
  comments?: string[];
}

interface MigrationResource {
  type: "macro" | "lookup";
  name: string;
  content: string;
}

interface InstallResult {
  installed: number;
  failed: number;
}

// ---------------------------------------------------------------------------
// WorkbenchState discriminated union
//
// Each stage carries exactly the data it needs and no more. Transitions
// always move forward through the pipeline — no implicit shared state.
// ---------------------------------------------------------------------------

export type WorkbenchState =
  | {
      stage: "vendor-select";
    }
  | {
      stage: "upload";
      vendor: string;
      migrationId: string;
    }
  | {
      stage: "translating";
      vendor: string;
      migrationId: string;
      stats: MigrationStats | null;
    }
  | {
      stage: "review";
      vendor: string;
      migrationId: string;
      translations: TranslatedRule[];
      resources: MigrationResource[];
    }
  | {
      stage: "fix-rule-drawer";
      vendor: string;
      migrationId: string;
      translations: TranslatedRule[];
      resources: MigrationResource[];
      selectedRule: TranslatedRule;
    }
  | {
      stage: "fix-resources-drawer";
      vendor: string;
      migrationId: string;
      translations: TranslatedRule[];
      resources: MigrationResource[];
    }
  | {
      stage: "install";
      vendor: string;
      migrationId: string;
      translations: TranslatedRule[];
      resources: MigrationResource[];
    }
  | {
      stage: "done";
      installed: number;
      failed: number;
    };

// ---------------------------------------------------------------------------
// Vendor catalogue — re-enabling a vendor is a one-line change here
// ---------------------------------------------------------------------------

const SUPPORTED_VENDORS: readonly string[] = ["splunk"];

const VENDOR_CATALOGUE = [
  { id: "splunk", label: "Splunk" },
  { id: "qradar", label: "IBM QRadar" },
  { id: "sentinel-one", label: "Sentinel One" },
] as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function callTool<T = unknown>(
  app: McpApp,
  name: string,
  args: Record<string, unknown>
): Promise<T | null> {
  try {
    const result = await app.callServerTool({ name, arguments: args });
    const text = extractCallResult(result);
    if (!text) return null;
    return JSON.parse(text) as T;
  } catch (e) {
    console.error(`[migration] ${name} failed:`, e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

export function App() {
  const [state, setState] = useState<WorkbenchState>({ stage: "vendor-select" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // For the translating stage: poll stats until translation completes
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearPoll = useCallback(() => {
    if (pollTimerRef.current !== null) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  useEffect(() => () => clearPoll(), [clearPoll]);

  const { connected, getApp } = useMcpApp({
    name: "migration",
    version: "1.0.0",
    onConnect: (_app, _gotResult) => {
      // No initial data load needed — the workbench starts at vendor-select.
    },
  });

  const fullscreen = useFullscreen(getApp);

  // ── Stage transitions ──────────────────────────────────────────────────────

  const selectVendor = useCallback(
    async (vendor: string) => {
      const app = getApp();
      if (!app) return;
      setLoading(true);
      setError(null);
      try {
        const res = await callTool<{ migration_id: string }>(app, "create-migration", {
          name: `Migration ${new Date().toISOString().slice(0, 10)}`,
        });
        if (!res?.migration_id) throw new Error("Failed to create migration");
        setState({ stage: "upload", vendor, migrationId: res.migration_id });
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    },
    [getApp]
  );

  const uploadRules = useCallback(
    async (rulesJson: string) => {
      const app = getApp();
      if (!app || state.stage !== "upload") return;
      const { vendor, migrationId } = state;
      setLoading(true);
      setError(null);
      try {
        const rules = JSON.parse(rulesJson) as Record<string, unknown>[];
        await callTool(app, "upload-rules", { migrationId, vendor, rules });
        await callTool(app, "start-translation", { migrationId, vendor });
        const stats = await callTool<MigrationStats>(app, "get-stats", { migrationId });
        setState({ stage: "translating", vendor, migrationId, stats: stats ?? null });
        schedulePoll(app, vendor, migrationId);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    },
    [getApp, state]
  );

  const schedulePoll = useCallback(
    (app: McpApp, vendor: string, migrationId: string) => {
      clearPoll();
      pollTimerRef.current = setTimeout(async () => {
        // Use get-migration (not get-stats) so we get the strongly-typed status
        // field ("ready" | "running" | "finished" | "error") alongside the rule counts.
        const migration = await callTool<MigrationStats>(app, "get-migration", { migrationId });
        setState((prev) => {
          if (prev.stage !== "translating") return prev;
          return { ...prev, stats: migration ?? prev.stats };
        });
        // Translation is complete when Kibana sets status to "finished" or "error".
        if (migration && (migration.status === "finished" || migration.status === "error")) {
          void (async () => {
            const translationsRes = await callTool<{ data: TranslatedRule[] }>(
              app, "get-translated-rules", { migrationId, vendor, perPage: 500 }
            );
            const resources =
              (await callTool<MigrationResource[]>(app, "get-resources", { migrationId, vendor })) ?? [];
            setState({
              stage: "review",
              vendor,
              migrationId,
              translations: translationsRes?.data ?? [],
              resources,
            });
          })();
        } else {
          schedulePoll(app, vendor, migrationId);
        }
      }, 3000);
    },
    [clearPoll]
  );

  const openRuleDrawer = useCallback((rule: TranslatedRule) => {
    setState((prev) => {
      if (prev.stage !== "review") return prev;
      return { ...prev, stage: "fix-rule-drawer", selectedRule: rule };
    });
  }, []);

  const saveRuleFix = useCallback(
    async (elasticRuleJson: string, translationResult: "full" | "partial" | "untranslatable") => {
      const app = getApp();
      if (!app || state.stage !== "fix-rule-drawer") return;
      const { vendor, migrationId, translations, resources, selectedRule } = state;
      setLoading(true);
      setError(null);
      try {
        const updated = await callTool<TranslatedRule>(
          app,
          "update-translated-rule",
          { migrationId, ruleId: selectedRule.id, vendor, elasticRule: elasticRuleJson, translationResult }
        );
        setState({
          stage: "review",
          vendor,
          migrationId,
          resources,
          translations: translations.map((t) =>
            t.id === selectedRule.id ? (updated ?? t) : t
          ),
        });
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    },
    [getApp, state]
  );

  const saveRuleInline = useCallback(
    async (
      ruleId: string,
      elasticRuleJson: string,
      translationResult: "full" | "partial" | "untranslatable"
    ) => {
      const app = getApp();
      if (!app || state.stage !== "review") return;
      const { vendor, migrationId, translations, resources } = state;
      setLoading(true);
      setError(null);
      try {
        const updated = await callTool<TranslatedRule>(app, "update-translated-rule", {
          migrationId,
          ruleId,
          vendor,
          elasticRule: elasticRuleJson,
          translationResult,
        });
        setState({
          stage: "review",
          vendor,
          migrationId,
          resources,
          translations: translations.map((t) => (t.id === ruleId ? (updated ?? t) : t)),
        });
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    },
    [getApp, state]
  );

  const openResourcesDrawer = useCallback(() => {
    setState((prev) => {
      if (prev.stage !== "review") return prev;
      return { ...prev, stage: "fix-resources-drawer" };
    });
  }, []);

  const saveResources = useCallback(
    async (resource: MigrationResource) => {
      const app = getApp();
      if (!app || state.stage !== "fix-resources-drawer") return;
      const { vendor, migrationId, translations } = state;
      setLoading(true);
      setError(null);
      try {
        await callTool(app, "upsert-resource", { migrationId, vendor, ...resource });
        const resources =
          (await callTool<MigrationResource[]>(app, "get-resources", { migrationId, vendor })) ?? [];
        setState({ stage: "fix-resources-drawer", vendor, migrationId, translations, resources });
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    },
    [getApp, state]
  );

  const closeDrawer = useCallback(() => {
    setState((prev) => {
      if (prev.stage === "fix-rule-drawer" || prev.stage === "fix-resources-drawer") {
        const { stage: _stage, ...rest } = prev as WorkbenchState & {
          stage: "fix-rule-drawer" | "fix-resources-drawer";
        };
        void _stage;
        return { ...(rest as { vendor: string; migrationId: string; translations: TranslatedRule[]; resources: MigrationResource[] }), stage: "review" };
      }
      if (prev.stage === "install") {
        return { stage: "review", vendor: prev.vendor, migrationId: prev.migrationId, translations: prev.translations, resources: prev.resources };
      }
      return prev;
    });
  }, []);

  const startInstall = useCallback(() => {
    setState((prev) => {
      if (prev.stage !== "review") return prev;
      return { stage: "install", vendor: prev.vendor, migrationId: prev.migrationId, translations: prev.translations, resources: prev.resources };
    });
  }, []);

  const confirmInstall = useCallback(async () => {
    const app = getApp();
    if (!app || state.stage !== "install") return;
    const { vendor, migrationId } = state;
    setLoading(true);
    setError(null);
    try {
      const result = await callTool<InstallResult>(app, "install-rules", { migrationId, vendor });
      setState({ stage: "done", installed: result?.installed ?? 0, failed: result?.failed ?? 0 });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [getApp, state]);

  const reset = useCallback(() => {
    clearPoll();
    setState({ stage: "vendor-select" });
    setError(null);
  }, [clearPoll]);

  // ── Render ─────────────────────────────────────────────────────────────────

  // AppHeader expects { isFullscreen, onToggle } — useFullscreen returns { isFullscreen, toggle }
  const fullscreenProp = { isFullscreen: fullscreen.isFullscreen, onToggle: fullscreen.toggle };

  if (!connected) {
    return (
      <AppShell>
        <AppHeader title="SIEM Migration" fullscreen={fullscreenProp} />
        <LoadingState>Connecting to Elastic Security…</LoadingState>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <AppHeader
        title="SIEM Migration"
        fullscreen={fullscreenProp}
        actions={
          state.stage !== "vendor-select" && state.stage !== "done" ? (
            <BackButton onClick={reset} label="Start over" />
          ) : undefined
        }
      />

      {error && (
        <div className="p-3 m-4 rounded bg-red-50 border border-red-200 text-red-700 text-sm">
          {error}
          <button className="ml-2 underline" onClick={() => setError(null)}>
            Dismiss
          </button>
        </div>
      )}

      {loading && <LoadingState>Working…</LoadingState>}

      {!loading && renderStage(state, {
        selectVendor,
        uploadRules,
        openRuleDrawer,
        saveRuleFix,
        saveRuleInline,
        openResourcesDrawer,
        saveResources,
        closeDrawer,
        startInstall,
        confirmInstall,
        reset,
      })}
    </AppShell>
  );
}

// ---------------------------------------------------------------------------
// Per-stage renderers (extracted to keep App() readable)
// ---------------------------------------------------------------------------

interface StageHandlers {
  selectVendor: (vendor: string) => void;
  uploadRules: (json: string) => void;
  openRuleDrawer: (rule: TranslatedRule) => void;
  saveRuleFix: (json: string, result: "full" | "partial" | "untranslatable") => void;
  saveRuleInline: (id: string, json: string, result: "full" | "partial" | "untranslatable") => void;
  openResourcesDrawer: () => void;
  saveResources: (resource: MigrationResource) => void;
  closeDrawer: () => void;
  startInstall: () => void;
  confirmInstall: () => void;
  reset: () => void;
}

function renderStage(state: WorkbenchState, h: StageHandlers): React.ReactNode {
  switch (state.stage) {
    case "vendor-select":
      return <VendorSelect onSelect={h.selectVendor} />;

    case "upload":
      return <Upload vendor={state.vendor} onUpload={h.uploadRules} />;

    case "translating":
      return <Translating stats={state.stats} />;

    case "review":
      return (
        <Review
          translations={state.translations}
          resources={state.resources}
          onOpenRule={h.openRuleDrawer}
          onSaveRule={h.saveRuleInline}
          onOpenResources={h.openResourcesDrawer}
          onInstall={h.startInstall}
        />
      );

    case "fix-rule-drawer":
      return (
        <>
          <Review
            translations={state.translations}
            resources={state.resources}
            onOpenRule={h.openRuleDrawer}
            onSaveRule={h.saveRuleInline}
            onOpenResources={h.openResourcesDrawer}
            onInstall={h.startInstall}
            dimmed
          />
          <RuleDrawer rule={state.selectedRule} onSave={h.saveRuleFix} onClose={h.closeDrawer} />
        </>
      );

    case "fix-resources-drawer":
      return (
        <>
          <Review
            translations={state.translations}
            resources={state.resources}
            onOpenRule={h.openRuleDrawer}
            onSaveRule={h.saveRuleInline}
            onOpenResources={h.openResourcesDrawer}
            onInstall={h.startInstall}
            dimmed
          />
          <ResourcesDrawer resources={state.resources} onSave={h.saveResources} onClose={h.closeDrawer} />
        </>
      );

    case "install":
      return (
        <Install
          count={state.translations.filter((t) => t.translation_result !== "untranslatable").length}
          onConfirm={h.confirmInstall}
          onBack={h.closeDrawer}
        />
      );

    case "done":
      return <Done installed={state.installed} failed={state.failed} onReset={h.reset} />;
  }
}

// ---------------------------------------------------------------------------
// Stage components
// ---------------------------------------------------------------------------

function VendorSelect({ onSelect }: { onSelect: (vendor: string) => void }) {
  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h2 className="text-lg font-semibold mb-1">Select your source SIEM</h2>
      <p className="text-sm text-gray-500 mb-4">
        Choose the platform you are migrating detection rules from.
      </p>
      <div className="migration-vendor-grid">
        {VENDOR_CATALOGUE.map(({ id, label }) => {
          // ≤5-LOC client-side gate: only Splunk is production-ready.
          // Add a vendor to SUPPORTED_VENDORS to re-enable it.
          const active = SUPPORTED_VENDORS.includes(id);
          return (
            <button
              key={id}
              className={`migration-vendor-card${active ? "" : " opacity-50 cursor-not-allowed"}`}
              disabled={!active}
              onClick={() => active && onSelect(id)}
            >
              <span className="migration-vendor-label">{label}</span>
              {!active && <span className="migration-vendor-badge">Coming soon</span>}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function Upload({ vendor, onUpload }: { vendor: string; onUpload: (json: string) => void }) {
  const [text, setText] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const readFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => setText((e.target?.result as string | null) ?? "");
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) readFile(file);
  };

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h2 className="text-lg font-semibold mb-1">Upload {vendor} rules</h2>
      <p className="text-sm text-gray-500 mb-4">
        Drop a JSON export file, use the file picker, or paste the rules array directly.
      </p>

      {/* Hidden file input wired to the drop zone button */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".json,application/json"
        className="sr-only"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) readFile(file);
          e.target.value = "";
        }}
      />

      <div
        className={`migration-upload-area${dragOver ? " border-blue-400 bg-blue-50" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
      >
        <button
          type="button"
          className="mb-3 px-3 py-1.5 text-sm border border-gray-300 rounded hover:bg-gray-50"
          onClick={() => fileInputRef.current?.click()}
        >
          Choose file…
        </button>
        <p className="text-xs text-gray-400 mb-2">or drop a .json file here, or paste below</p>
        <textarea
          className="w-full h-36 p-2 text-xs font-mono border border-gray-200 rounded resize-y"
          placeholder={`[\n  { "search": "index=main sourcetype=syslog..." },\n  ...\n]`}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </div>

      <button
        className="mt-3 px-4 py-2 bg-blue-600 text-white rounded text-sm font-medium disabled:opacity-50"
        disabled={!text.trim()}
        onClick={() => onUpload(text)}
      >
        Upload &amp; start translation
      </button>
    </div>
  );
}

function Translating({ stats }: { stats: MigrationStats | null }) {
  const rules = stats?.rules;
  const done = stats?.rules.total ?? 0;
  const pending = rules?.pending ?? 0;
  const pct = done > 0 ? Math.round(((done - pending) / done) * 100) : 0;
  const isError = stats?.status === "error";

  return (
    <div className="p-6 max-w-xl mx-auto">
      <h2 className="text-lg font-semibold mb-1">
        {isError ? "Translation encountered an error" : "Translating rules…"}
      </h2>
      <p className="text-sm text-gray-500 mb-6">
        {isError
          ? "Some rules could not be translated. Loading results…"
          : "The AI translator is converting your rules to Elastic detection rule format. This may take a few minutes."}
      </p>
      {rules && (
        <>
          <KpiStrip tileCount={4}>
            <KpiTile label="Total" value={rules.total} />
            <KpiTile label="Translated" value={rules.completed} />
            <KpiTile label="Pending" value={rules.pending} />
            <KpiTile label="Failed" value={rules.failed} />
          </KpiStrip>
          {!isError && (
            <>
              <div className="migration-progress-bar-track mt-4">
                <div className="migration-progress-bar-fill" style={{ width: `${pct}%` }} />
              </div>
              <p className="text-xs text-gray-400 mt-1">{pct}% complete</p>
            </>
          )}
        </>
      )}
      {!rules && <LoadingState>Waiting for translation to start…</LoadingState>}
    </div>
  );
}

function Review({
  translations,
  resources,
  onOpenRule,
  onSaveRule,
  onOpenResources,
  onInstall,
  dimmed,
}: {
  translations: TranslatedRule[];
  resources: MigrationResource[];
  onOpenRule: (rule: TranslatedRule) => void;
  onSaveRule: (id: string, json: string, result: "full" | "partial" | "untranslatable") => void;
  onOpenResources: () => void;
  onInstall: () => void;
  dimmed?: boolean;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const installable = translations.filter(
    (t) => t.translation_result && t.translation_result !== "untranslatable"
  ).length;
  const needsFix = translations.filter((t) => t.translation_result === "partial").length;

  const toggleExpand = (id: string) =>
    setExpandedId((prev) => (prev === id ? null : id));

  return (
    <div className={`p-6${dimmed ? " opacity-50 pointer-events-none" : ""}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold">Review translated rules</h2>
        <div className="flex gap-2">
          {resources.length > 0 && (
            <button
              className="px-3 py-1.5 text-sm border border-gray-300 rounded"
              onClick={onOpenResources}
            >
              Fix resources ({resources.length})
            </button>
          )}
          <button
            className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded disabled:opacity-50"
            disabled={installable === 0}
            onClick={onInstall}
          >
            Install {installable} rules
          </button>
        </div>
      </div>

      {needsFix > 0 && (
        <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded text-sm text-yellow-800">
          {needsFix} rule{needsFix !== 1 ? "s" : ""} need manual review before installation.
        </div>
      )}

      {translations.length === 0 ? (
        <EmptyState>No translated rules found.</EmptyState>
      ) : (
        <div className="space-y-2">
          {translations.map((rule) => (
            <div key={rule.id} className="border border-gray-200 rounded overflow-hidden">
              <RuleRow
                rule={rule}
                expanded={expandedId === rule.id}
                onToggle={() => toggleExpand(rule.id)}
                onOpenDrawer={() => onOpenRule(rule)}
              />
              {expandedId === rule.id && (
                <RuleDiff
                  rule={rule}
                  onSave={(json, result) => {
                    onSaveRule(rule.id, json, result);
                    setExpandedId(null);
                  }}
                  onCancel={() => setExpandedId(null)}
                />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RuleRow({
  rule,
  expanded,
  onToggle,
  onOpenDrawer,
}: {
  rule: TranslatedRule;
  expanded: boolean;
  onToggle: () => void;
  onOpenDrawer: () => void;
}) {
  const name =
    (rule.elastic_rule?.name as string | undefined) ??
    (rule.original_rule?.title as string | undefined) ??
    rule.id;
  return (
    <div
      className="flex items-center justify-between p-3 cursor-pointer hover:bg-gray-50 select-none"
      onClick={onToggle}
    >
      <div className="flex items-center gap-3 min-w-0">
        <TranslationBadge result={rule.translation_result} />
        <span className="text-sm truncate">{name}</span>
      </div>
      <div className="flex items-center gap-2 shrink-0" onClick={(e) => e.stopPropagation()}>
        {(rule.translation_result === "partial" || !rule.elastic_rule) && (
          <button
            className="text-xs text-blue-600 underline"
            onClick={(e) => { e.stopPropagation(); onOpenDrawer(); }}
          >
            Drawer
          </button>
        )}
        <span className="text-xs text-gray-400">{expanded ? "▲" : "▼"}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Three-column diff panel (inline within the review step)
//
// Monaco editor is intentionally omitted to keep the singlefile HTML bundle
// under 1 MB. The generated column uses a styled <pre>; the editable column
// uses a <textarea> with the same monospace style.
// ---------------------------------------------------------------------------

function RuleDiff({
  rule,
  onSave,
  onCancel,
}: {
  rule: TranslatedRule;
  onSave: (json: string, result: "full" | "partial" | "untranslatable") => void;
  onCancel: () => void;
}) {
  const [editedJson, setEditedJson] = useState(() =>
    JSON.stringify(rule.elastic_rule ?? {}, null, 2)
  );
  const [result, setResult] = useState<"full" | "partial" | "untranslatable">(
    rule.translation_result ?? "partial"
  );

  const originalSpl = useMemo(() => {
    const r = rule.original_rule;
    return (r.search as string | undefined) ?? (r.spl as string | undefined) ??
      JSON.stringify(r, null, 2);
  }, [rule.original_rule]);

  const generatedJson = useMemo(
    () => JSON.stringify(rule.elastic_rule ?? {}, null, 2),
    [rule.elastic_rule]
  );

  return (
    <div className="migration-diff-panel border-t border-gray-200">
      <div className="migration-diff-columns">
        {/* Left: original SPL */}
        <div className="migration-diff-col">
          <div className="migration-diff-col-header">Original SPL</div>
          <pre className="migration-diff-spl">{originalSpl}</pre>
        </div>

        {/* Middle: generated Elastic rule JSON (read-only) */}
        <div className="migration-diff-col">
          <div className="migration-diff-col-header">Generated (read-only)</div>
          <pre className="migration-diff-spl">{generatedJson}</pre>
        </div>

        {/* Right: user-editable Elastic rule JSON */}
        <div className="migration-diff-col">
          <div className="migration-diff-col-header">Edit</div>
          <textarea
            className="migration-diff-spl migration-diff-textarea"
            value={editedJson}
            onChange={(e) => setEditedJson(e.target.value)}
            spellCheck={false}
          />
        </div>
      </div>

      <div className="migration-diff-footer">
        <select
          className="text-sm border border-gray-200 rounded p-1"
          value={result}
          onChange={(e) => setResult(e.target.value as typeof result)}
        >
          <option value="full">Full — production-ready</option>
          <option value="partial">Partial — needs tuning</option>
          <option value="untranslatable">Untranslatable — skip</option>
        </select>
        <div className="flex gap-2">
          <button className="text-sm text-gray-500 px-3 py-1.5" onClick={onCancel}>
            Cancel
          </button>
          <button
            className="text-sm px-3 py-1.5 bg-blue-600 text-white rounded"
            onClick={() => onSave(editedJson, result)}
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

function TranslationBadge({ result }: { result?: string }) {
  const cls = `migration-rule-status-badge migration-rule-status-badge--${result ?? "pending"}`;
  const label = result ?? "pending";
  return <span className={cls}>{label}</span>;
}

// ---------------------------------------------------------------------------
// ElasticRulePartial — key fields of an Elastic detection rule
// ---------------------------------------------------------------------------

interface ElasticRulePartial {
  name: string;
  description: string;
  type: string;
  query: string;
  language: string;
  severity: string;
  risk_score: number;
  [key: string]: unknown;
}

function fromRuleJson(raw: Record<string, unknown>): ElasticRulePartial {
  return {
    name: (raw.name as string | undefined) ?? "",
    description: (raw.description as string | undefined) ?? "",
    type: (raw.type as string | undefined) ?? "query",
    query: (raw.query as string | undefined) ?? "",
    language: (raw.language as string | undefined) ?? "kuery",
    severity: (raw.severity as string | undefined) ?? "medium",
    risk_score: typeof raw.risk_score === "number" ? raw.risk_score : 50,
    ...raw,
  };
}

function ElasticRuleForm({
  fields,
  onChange,
}: {
  fields: ElasticRulePartial;
  onChange: (patch: Partial<ElasticRulePartial>) => void;
}) {
  return (
    <div className="space-y-3 text-sm">
      <FormRow label="Name">
        <input
          className="migration-form-input"
          value={fields.name}
          onChange={(e) => onChange({ name: e.target.value })}
        />
      </FormRow>
      <FormRow label="Description">
        <textarea
          className="migration-form-input h-16 resize-none"
          value={fields.description}
          onChange={(e) => onChange({ description: e.target.value })}
        />
      </FormRow>
      <div className="flex gap-3">
        <FormRow label="Type" className="flex-1">
          <select
            className="migration-form-input"
            value={fields.type}
            onChange={(e) => onChange({ type: e.target.value })}
          >
            {["query", "eql", "esql", "threshold", "machine_learning", "new_terms"].map(
              (t) => <option key={t} value={t}>{t}</option>
            )}
          </select>
        </FormRow>
        <FormRow label="Language" className="flex-1">
          <select
            className="migration-form-input"
            value={fields.language}
            onChange={(e) => onChange({ language: e.target.value })}
          >
            {["kuery", "eql", "esql", "lucene"].map(
              (l) => <option key={l} value={l}>{l}</option>
            )}
          </select>
        </FormRow>
      </div>
      <FormRow label="Query">
        <textarea
          className="migration-form-input h-28 resize-y font-mono text-xs"
          value={fields.query}
          onChange={(e) => onChange({ query: e.target.value })}
        />
      </FormRow>
      <div className="flex gap-3">
        <FormRow label="Severity" className="flex-1">
          <select
            className="migration-form-input"
            value={fields.severity}
            onChange={(e) => onChange({ severity: e.target.value })}
          >
            {["low", "medium", "high", "critical"].map(
              (s) => <option key={s} value={s}>{s}</option>
            )}
          </select>
        </FormRow>
        <FormRow label="Risk score" className="flex-1">
          <input
            type="number"
            min={0}
            max={100}
            className="migration-form-input"
            value={fields.risk_score}
            onChange={(e) => onChange({ risk_score: Math.min(100, Math.max(0, Number(e.target.value))) })}
          />
        </FormRow>
      </div>
    </div>
  );
}

function FormRow({
  label,
  className,
  children,
}: {
  label: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={className}>
      <label className="block text-xs font-medium text-gray-600 mb-1">{label}</label>
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// RuleDrawer — slide-over with ElasticRulePartial form
// ---------------------------------------------------------------------------

function RuleDrawer({
  rule,
  onSave,
  onClose,
}: {
  rule: TranslatedRule;
  onSave: (json: string, result: "full" | "partial" | "untranslatable") => void;
  onClose: () => void;
}) {
  const rawRule = rule.elastic_rule ?? {};
  const [fields, setFields] = useState<ElasticRulePartial>(() => fromRuleJson(rawRule));
  const [result, setResult] = useState<"full" | "partial" | "untranslatable">(
    rule.translation_result ?? "partial"
  );
  const [revalidating, setRevalidating] = useState(false);

  const patch = (update: Partial<ElasticRulePartial>) =>
    setFields((prev) => ({ ...prev, ...update }));

  const toJson = () => JSON.stringify({ ...rawRule, ...fields }, null, 2);

  const handleRevalidate = async () => {
    setRevalidating(true);
    try {
      // Save the current edits; caller persists via update-translated-rule
      // and can determine a new translation result from the API response.
      onSave(toJson(), "partial");
    } finally {
      setRevalidating(false);
    }
  };

  const ruleName =
    fields.name ||
    (rule.original_rule?.title as string | undefined) ||
    rule.id;

  return (
    <div className="migration-drawer">
      <div className="migration-drawer-header">
        <div className="min-w-0">
          <h3 className="font-semibold text-sm truncate">{ruleName}</h3>
          <TranslationBadge result={rule.translation_result} />
        </div>
        <button className="text-gray-400 hover:text-gray-700 shrink-0" onClick={onClose}>
          ✕
        </button>
      </div>

      <div className="migration-drawer-body">
        <ElasticRuleForm fields={fields} onChange={patch} />

        <div className="mt-4">
          <label className="block text-xs font-medium text-gray-600 mb-1">
            Translation result
          </label>
          <select
            className="migration-form-input"
            value={result}
            onChange={(e) => setResult(e.target.value as typeof result)}
          >
            <option value="full">Full — rule is production-ready</option>
            <option value="partial">Partial — rule needs tuning</option>
            <option value="untranslatable">Untranslatable — skip this rule</option>
          </select>
        </div>
      </div>

      <div className="migration-drawer-footer">
        <button className="text-sm text-gray-500" onClick={onClose}>
          Cancel
        </button>
        <button
          className="text-sm px-3 py-1.5 border border-gray-300 rounded disabled:opacity-50"
          disabled={revalidating}
          onClick={() => void handleRevalidate()}
          title="Save edits and mark as partial for further review"
        >
          {revalidating ? "Saving…" : "Re-validate"}
        </button>
        <button
          className="text-sm px-3 py-1.5 bg-blue-600 text-white rounded"
          onClick={() => onSave(toJson(), result)}
        >
          Save
        </button>
      </div>
    </div>
  );
}

function ResourcesDrawer({
  resources,
  onSave,
  onClose,
}: {
  resources: MigrationResource[];
  onSave: (resource: MigrationResource) => void;
  onClose: () => void;
}) {
  const [addName, setAddName] = useState("");
  const [addType, setAddType] = useState<"macro" | "lookup">("macro");
  const [addContent, setAddContent] = useState("");

  const unresolved = resources.filter((r) => !r.content.trim());
  const resolved = resources.filter((r) => r.content.trim());

  return (
    <div className="migration-drawer">
      <div className="migration-drawer-header">
        <div className="min-w-0">
          <h3 className="font-semibold text-sm">Manage resources</h3>
          {unresolved.length > 0 && (
            <span className="text-xs text-yellow-700">
              {unresolved.length} unresolved
            </span>
          )}
        </div>
        <button className="text-gray-400 hover:text-gray-700 shrink-0" onClick={onClose}>
          ✕
        </button>
      </div>

      <div className="migration-drawer-body space-y-4">
        {unresolved.length > 0 && (
          <section>
            <p className="text-xs font-semibold text-yellow-700 uppercase tracking-wide mb-2">
              Unresolved ({unresolved.length})
            </p>
            <div className="space-y-2">
              {unresolved.map((r) => (
                <ResourceEditRow
                  key={`${r.type}:${r.name}`}
                  resource={r}
                  defaultExpanded
                  onSave={onSave}
                />
              ))}
            </div>
          </section>
        )}

        {resolved.length > 0 && (
          <section>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              Defined ({resolved.length})
            </p>
            <div className="space-y-2">
              {resolved.map((r) => (
                <ResourceEditRow
                  key={`${r.type}:${r.name}`}
                  resource={r}
                  defaultExpanded={false}
                  onSave={onSave}
                />
              ))}
            </div>
          </section>
        )}

        {resources.length === 0 && (
          <p className="text-sm text-gray-400 text-center py-8">No resources found.</p>
        )}

        <section>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
            Add resource
          </p>
          <div className="space-y-2">
            <div className="flex gap-2">
              <select
                className="migration-form-input"
                value={addType}
                onChange={(e) => setAddType(e.target.value as typeof addType)}
              >
                <option value="macro">Macro</option>
                <option value="lookup">Lookup</option>
              </select>
              <input
                className="migration-form-input"
                placeholder="Resource name"
                value={addName}
                onChange={(e) => setAddName(e.target.value)}
              />
            </div>
            <textarea
              className="migration-rule-json-editor h-20"
              placeholder="Paste definition…"
              value={addContent}
              onChange={(e) => setAddContent(e.target.value)}
            />
            <div className="flex justify-end">
              <button
                className="text-xs px-3 py-1.5 bg-blue-600 text-white rounded disabled:opacity-50"
                disabled={!addName.trim()}
                onClick={() => {
                  onSave({ type: addType, name: addName.trim(), content: addContent });
                  setAddName("");
                  setAddContent("");
                }}
              >
                Add
              </button>
            </div>
          </div>
        </section>
      </div>

      <div className="migration-drawer-footer">
        <button className="text-sm text-gray-500" onClick={onClose}>
          Done
        </button>
      </div>
    </div>
  );
}

function ResourceEditRow({
  resource,
  defaultExpanded,
  onSave,
}: {
  resource: MigrationResource;
  defaultExpanded: boolean;
  onSave: (r: MigrationResource) => void;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [content, setContent] = useState(resource.content);
  const isUnresolved = !resource.content.trim();
  const isDirty = content !== resource.content;

  useEffect(() => {
    setContent(resource.content);
  }, [resource.content]);

  return (
    <div
      className={`border rounded p-2 space-y-2${isUnresolved ? " border-yellow-300 bg-yellow-50" : " border-gray-200"}`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xs font-mono bg-gray-100 px-1 rounded shrink-0">
            {resource.type}
          </span>
          <span className="text-sm font-medium truncate">{resource.name}</span>
          {isUnresolved && (
            <span className="text-xs text-yellow-600 shrink-0">unresolved</span>
          )}
        </div>
        <button
          className="text-xs text-gray-400 shrink-0 ml-2"
          onClick={() => setExpanded((p) => !p)}
        >
          {expanded ? "▲" : "▼"}
        </button>
      </div>

      {expanded && (
        <>
          <textarea
            className="migration-rule-json-editor h-24 w-full"
            placeholder="Paste macro or lookup definition…"
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />
          <div className="flex justify-end">
            <button
              className="text-xs px-3 py-1.5 bg-blue-600 text-white rounded disabled:opacity-50"
              disabled={!isDirty && !isUnresolved}
              onClick={() => onSave({ ...resource, content })}
            >
              Save
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function Install({
  count,
  onConfirm,
  onBack,
}: {
  count: number;
  onConfirm: () => void;
  onBack: () => void;
}) {
  return (
    <div className="p-6 max-w-xl mx-auto text-center">
      <h2 className="text-lg font-semibold mb-2">Install {count} rules</h2>
      <p className="text-sm text-gray-500 mb-6">
        The translated rules will be installed as disabled detection rules in Elastic Security.
        You can enable them after reviewing their configuration.
      </p>
      <div className="flex gap-3 justify-center">
        <button className="px-4 py-2 text-sm border border-gray-300 rounded" onClick={onBack}>
          Back to review
        </button>
        <button
          className="px-4 py-2 text-sm bg-blue-600 text-white rounded"
          onClick={onConfirm}
        >
          Confirm install
        </button>
      </div>
    </div>
  );
}

function Done({
  installed,
  failed,
  onReset,
}: {
  installed: number;
  failed: number;
  onReset: () => void;
}) {
  return (
    <div className="p-6 max-w-xl mx-auto text-center">
      <div className="text-4xl mb-4">✓</div>
      <h2 className="text-lg font-semibold mb-2">Migration complete</h2>
      <KpiStrip tileCount={failed > 0 ? 2 : 1}>
        <KpiTile label="Installed" value={installed} />
        {failed > 0 && <KpiTile label="Failed" value={failed} />}
      </KpiStrip>
      <p className="text-sm text-gray-500 mt-4 mb-6">
        Rules have been installed as disabled. Navigate to Detection Rules to enable and tune them.
      </p>
      <button className="px-4 py-2 text-sm border border-gray-300 rounded" onClick={onReset}>
        Start another migration
      </button>
    </div>
  );
}
