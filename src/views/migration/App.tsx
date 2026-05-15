/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useState, useCallback, useEffect, useRef } from "react";
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
  status: string;
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
        const stats = await callTool<MigrationStats>(app, "get-stats", { migrationId });
        setState((prev) => {
          if (prev.stage !== "translating") return prev;
          return { ...prev, stats: stats ?? prev.stats };
        });
        if (stats && stats.rules.processing === 0 && stats.status !== "running") {
          // Translation finished — load translated rules and resources, move to review
          void (async () => {
            const translationsRes = await callTool<{
              data: TranslatedRule[];
            }>(app, "get-translated-rules", { migrationId, vendor, perPage: 500 });
            const resources =
              (await callTool<MigrationResource[]>(app, "get-resources", {
                migrationId,
                vendor,
              })) ?? [];
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
        setState({ stage: "review", vendor, migrationId, translations, resources });
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
      return prev;
    });
  }, []);

  const startInstall = useCallback(() => {
    setState((prev) => {
      if (prev.stage !== "review") return prev;
      return { stage: "install", vendor: prev.vendor, migrationId: prev.migrationId, translations: prev.translations };
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
  const pct = rules && rules.total > 0 ? Math.round(((rules.total - rules.pending) / rules.total) * 100) : 0;
  return (
    <div className="p-6 max-w-xl mx-auto">
      <h2 className="text-lg font-semibold mb-1">Translating rules…</h2>
      <p className="text-sm text-gray-500 mb-6">
        The AI translator is converting your rules to Elastic detection rule format. This may take a few minutes.
      </p>
      {rules && (
        <>
          <KpiStrip tileCount={4}>
            <KpiTile label="Total" value={rules.total} />
            <KpiTile label="Translated" value={rules.completed} />
            <KpiTile label="Pending" value={rules.pending} />
            <KpiTile label="Failed" value={rules.failed} />
          </KpiStrip>
          <div className="migration-progress-bar-track mt-4">
            <div className="migration-progress-bar-fill" style={{ width: `${pct}%` }} />
          </div>
          <p className="text-xs text-gray-400 mt-1">{pct}% complete</p>
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
  onOpenResources,
  onInstall,
  dimmed,
}: {
  translations: TranslatedRule[];
  resources: MigrationResource[];
  onOpenRule: (rule: TranslatedRule) => void;
  onOpenResources: () => void;
  onInstall: () => void;
  dimmed?: boolean;
}) {
  const installable = translations.filter(
    (t) => t.translation_result && t.translation_result !== "untranslatable"
  ).length;
  const needsFix = translations.filter((t) => t.translation_result === "partial").length;

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
            <RuleRow key={rule.id} rule={rule} onFix={() => onOpenRule(rule)} />
          ))}
        </div>
      )}
    </div>
  );
}

function RuleRow({ rule, onFix }: { rule: TranslatedRule; onFix: () => void }) {
  const name =
    (rule.elastic_rule?.name as string | undefined) ??
    (rule.original_rule?.title as string | undefined) ??
    rule.id;
  return (
    <div className="flex items-center justify-between p-3 border border-gray-200 rounded">
      <div className="flex items-center gap-3 min-w-0">
        <TranslationBadge result={rule.translation_result} />
        <span className="text-sm truncate">{name}</span>
      </div>
      {(rule.translation_result === "partial" || !rule.elastic_rule) && (
        <button className="text-xs text-blue-600 underline shrink-0" onClick={onFix}>
          Fix
        </button>
      )}
    </div>
  );
}

function TranslationBadge({ result }: { result?: string }) {
  const cls = `migration-rule-status-badge migration-rule-status-badge--${result ?? "pending"}`;
  const label = result ?? "pending";
  return <span className={cls}>{label}</span>;
}

function RuleDrawer({
  rule,
  onSave,
  onClose,
}: {
  rule: TranslatedRule;
  onSave: (json: string, result: "full" | "partial" | "untranslatable") => void;
  onClose: () => void;
}) {
  const [json, setJson] = useState(() =>
    JSON.stringify(rule.elastic_rule ?? {}, null, 2)
  );
  const [result, setResult] = useState<"full" | "partial" | "untranslatable">(
    rule.translation_result ?? "partial"
  );

  return (
    <div className="migration-drawer">
      <div className="migration-drawer-header">
        <h3 className="font-semibold text-sm">Fix translated rule</h3>
        <button className="text-gray-400 hover:text-gray-700" onClick={onClose}>
          ✕
        </button>
      </div>
      <div className="migration-drawer-body">
        <p className="text-xs text-gray-500 mb-2">
          Edit the Elastic rule JSON and select the translation quality.
        </p>
        <textarea
          className="migration-rule-json-editor"
          value={json}
          onChange={(e) => setJson(e.target.value)}
        />
        <div className="mt-3">
          <label className="block text-xs font-medium mb-1">Translation result</label>
          <select
            className="w-full text-sm border border-gray-200 rounded p-1.5"
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
          className="text-sm px-3 py-1.5 bg-blue-600 text-white rounded"
          onClick={() => onSave(json, result)}
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
  const [name, setName] = useState("");
  const [type, setType] = useState<"macro" | "lookup">("macro");
  const [content, setContent] = useState("");

  return (
    <div className="migration-drawer">
      <div className="migration-drawer-header">
        <h3 className="font-semibold text-sm">Manage resources</h3>
        <button className="text-gray-400 hover:text-gray-700" onClick={onClose}>
          ✕
        </button>
      </div>
      <div className="migration-drawer-body">
        {resources.length > 0 && (
          <div className="mb-4">
            <p className="text-xs font-medium mb-2 text-gray-600">Existing resources</p>
            {resources.map((r) => (
              <div key={`${r.type}:${r.name}`} className="migration-resource-row">
                <span className="text-xs font-mono bg-gray-100 px-1 rounded">{r.type}</span>
                <span className="text-sm">{r.name}</span>
              </div>
            ))}
          </div>
        )}
        <p className="text-xs font-medium mb-2 text-gray-600">Add / update resource</p>
        <div className="space-y-2">
          <select
            className="w-full text-sm border border-gray-200 rounded p-1.5"
            value={type}
            onChange={(e) => setType(e.target.value as typeof type)}
          >
            <option value="macro">Macro</option>
            <option value="lookup">Lookup</option>
          </select>
          <input
            className="w-full text-sm border border-gray-200 rounded p-1.5"
            placeholder="Resource name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <textarea
            className="migration-rule-json-editor h-24"
            placeholder="Resource content / definition"
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />
        </div>
      </div>
      <div className="migration-drawer-footer">
        <button className="text-sm text-gray-500" onClick={onClose}>
          Close
        </button>
        <button
          className="text-sm px-3 py-1.5 bg-blue-600 text-white rounded disabled:opacity-50"
          disabled={!name.trim()}
          onClick={() => onSave({ type, name: name.trim(), content })}
        >
          Save resource
        </button>
      </div>
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
