/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Storybook-like harness shim for `@modelcontextprotocol/ext-apps`.
 *
 * Replaces the real MCP transport with a local stub so view code can run in a
 * plain Vite dev server — no MCP server, no Claude Desktop, no postMessage
 * handshake. Tool calls are resolved against canned fixtures in `./fixtures`.
 *
 * The active view is detected from the URL pathname
 * (`/src/views/<slug>/mcp-app.html`) so each view loads its own fixture map.
 *
 * Supported controls via URL/localStorage:
 *   ?theme=light        → start in light mode
 *   ?latency=NN         → per-call simulated latency in ms (default 120)
 *   ?fixture=VARIANT    → pick an alternate fixture variant if the file exports one
 *
 * Designers can also press the "T" key to toggle theme live.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

// ──────────────────────────────────────────────────────────────────────────
// Fixtures — auto-loaded at dev-server start.
// Each fixture file exports:
//   default: Record<string, unknown | ((args: any) => unknown)>
//   optionally: variants: Record<string, Record<string, unknown | ((args: any) => unknown)>>
// ──────────────────────────────────────────────────────────────────────────

type ToolHandler = unknown | ((args: any) => unknown | Promise<unknown>);
type ToolMap = Record<string, ToolHandler>;
type FixtureModule = {
  default: ToolMap;
  variants?: Record<string, ToolMap>;
};

const fixtureModules = import.meta.glob<FixtureModule>("./fixtures/*.ts", {
  eager: true,
});

/** `./fixtures/alert-triage.ts` → `alert-triage` */
function fixtureKeyFromPath(path: string): string {
  const m = path.match(/\.\/fixtures\/([^/]+)\.ts$/);
  return m ? m[1] : path;
}

const fixturesByView: Record<string, FixtureModule> = {};
for (const [path, mod] of Object.entries(fixtureModules)) {
  fixturesByView[fixtureKeyFromPath(path)] = mod;
}

// ──────────────────────────────────────────────────────────────────────────
// URL / runtime config
// ──────────────────────────────────────────────────────────────────────────

const params = new URLSearchParams(window.location.search);
const configLatency = Number(params.get("latency") ?? "120");
const configVariant = params.get("fixture") ?? undefined;
const configTheme =
  params.get("theme") ??
  (typeof localStorage !== "undefined"
    ? localStorage.getItem("harness-theme") ?? "dark"
    : "dark");

/** Detect which view this harness iframe is serving. */
function detectViewSlug(): string {
  // Match `/src/views/<slug>/...`
  const m = window.location.pathname.match(/\/views\/([^/]+)\//);
  if (m) return m[1];
  // Fallback: ?view=<slug>
  const q = params.get("view");
  if (q) return q;
  return "unknown";
}

const activeView = detectViewSlug();
const activeFixture: FixtureModule | undefined = fixturesByView[activeView];
const activeToolMap: ToolMap = (() => {
  if (!activeFixture) return {};
  if (configVariant && activeFixture.variants?.[configVariant]) {
    return { ...activeFixture.default, ...activeFixture.variants[configVariant] };
  }
  return activeFixture.default;
})();

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

async function sleep(ms: number): Promise<void> {
  if (ms <= 0) return;
  return new Promise((r) => setTimeout(r, ms));
}

function wrapToolResult(data: unknown): any {
  if (data === undefined || data === null) {
    return { content: [{ type: "text", text: "" }] };
  }
  if (typeof data === "string") {
    return { content: [{ type: "text", text: data }] };
  }
  return { content: [{ type: "text", text: JSON.stringify(data) }] };
}

function toolError(message: string): any {
  return { isError: true, content: [{ type: "text", text: message }] };
}

function logCall(kind: string, name: string, args: unknown, result?: unknown) {
  // Grouped log so the designer can see what the view is asking for.
  /* eslint-disable no-console */
  console.groupCollapsed(
    `%c[harness] ${kind}%c ${name}`,
    "color:#5c7cfa;font-weight:bold",
    "color:inherit",
  );
  if (args !== undefined) console.log("args:", args);
  if (result !== undefined) console.log("result:", result);
  console.groupEnd();
  /* eslint-enable no-console */
}

// ──────────────────────────────────────────────────────────────────────────
// Theme banner / controls
// ──────────────────────────────────────────────────────────────────────────

function applyTheme(theme: "dark" | "light") {
  if (theme === "light") {
    document.documentElement.setAttribute("data-theme", "light");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  try {
    localStorage.setItem("harness-theme", theme);
  } catch { /* ignore */ }
}

let currentTheme: "dark" | "light" = configTheme === "light" ? "light" : "dark";
applyTheme(currentTheme);

window.addEventListener("keydown", (e) => {
  if (e.key !== "t" && e.key !== "T") return;
  const target = e.target as HTMLElement | null;
  if (target && /^(input|textarea|select)$/i.test(target.tagName)) return;
  if (target && target.isContentEditable) return;
  currentTheme = currentTheme === "dark" ? "light" : "dark";
  applyTheme(currentTheme);
  // Tell the App instance(s) so views wired to onhostcontextchanged also react.
  for (const app of liveApps) {
    app._emitHostContextChanged({ theme: currentTheme });
  }
});

// ──────────────────────────────────────────────────────────────────────────
// PostMessageTransport stub — inert; App.connect() won't use it.
// ──────────────────────────────────────────────────────────────────────────

export class PostMessageTransport {
  constructor(..._args: unknown[]) {
    /* inert */
  }
  start() { return Promise.resolve(); }
  send() { return Promise.resolve(); }
  close() { return Promise.resolve(); }
}

// ──────────────────────────────────────────────────────────────────────────
// App — minimal surface covering everything the views use.
// ──────────────────────────────────────────────────────────────────────────

type McpUiHostContext = {
  theme?: "dark" | "light";
  locale?: string;
  displayMode?: "inline" | "fullscreen" | "pip";
  availableDisplayModes?: Array<"inline" | "fullscreen" | "pip">;
  [key: string]: unknown;
};

const liveApps: App[] = [];

export class App {
  private _hostContext: McpUiHostContext = {
    theme: currentTheme,
    locale: "en-US",
    displayMode: "inline",
    availableDisplayModes: ["inline", "fullscreen"],
  };

  private _onhostcontextchanged?: (params: { hostContext: McpUiHostContext }) => void;
  private _ontoolinput?: (params: unknown) => void;
  private _ontoolinputpartial?: (params: unknown) => void;
  private _ontoolresult?: (params: unknown) => void;
  private _ontoolcancelled?: (params: unknown) => void;
  private _onteardown?: (params: unknown, extra: unknown) => unknown;

  constructor(
    _appInfo: { name: string; version: string },
    _capabilities?: unknown,
    _options?: unknown,
  ) {
    liveApps.push(this);
  }

  // ── Connection & handshake ─────────────────────────────────────────────
  async connect(_transport?: unknown, _options?: unknown): Promise<void> {
    // No-op in the harness — pretend we're connected.
    // Small delay so ontoolresult/initial state effects aren't synchronous.
    await sleep(10);
  }

  getHostCapabilities() {
    return { serverTools: true, resources: true };
  }

  getHostVersion() {
    return { name: "mcp-harness", version: "0.0.1" };
  }

  getHostContext(): McpUiHostContext {
    return { ...this._hostContext };
  }

  // ── Tool call (the main thing) ─────────────────────────────────────────
  async callServerTool(
    params: { name: string; arguments?: Record<string, unknown> },
    _options?: unknown,
  ): Promise<any> {
    await sleep(configLatency);
    const handler = activeToolMap[params.name];
    if (handler === undefined) {
      const msg = `[harness] no fixture for tool "${params.name}" in view "${activeView}". ` +
        `Add it to harness/fixtures/${activeView}.ts`;
      console.warn(msg, "args:", params.arguments);
      return toolError(msg);
    }
    let data: unknown;
    try {
      data = typeof handler === "function"
        ? await (handler as (args: any) => unknown)(params.arguments ?? {})
        : handler;
    } catch (e) {
      const msg = `[harness] fixture "${params.name}" threw: ${e instanceof Error ? e.message : String(e)}`;
      console.error(msg, e);
      return toolError(msg);
    }
    const result = wrapToolResult(data);
    logCall("callServerTool", params.name, params.arguments, data);
    return result;
  }

  async readServerResource(params: { uri: string }, _options?: unknown): Promise<any> {
    logCall("readServerResource", params.uri, undefined, "(stub)");
    return { contents: [{ uri: params.uri, mimeType: "text/plain", text: "" }] };
  }

  async listServerResources(_params?: unknown, _options?: unknown): Promise<any> {
    return { resources: [] };
  }

  // ── Outgoing messages & context ────────────────────────────────────────
  async sendMessage(params: unknown, _options?: unknown): Promise<any> {
    logCall("sendMessage", "(host)", params);
    return { isError: false };
  }

  async sendLog(params: unknown): Promise<void> {
    logCall("sendLog", "(log)", params);
  }

  async updateModelContext(params: unknown, _options?: unknown): Promise<any> {
    logCall("updateModelContext", "(host)", params);
    return {};
  }

  async openLink(params: { url: string }, _options?: unknown): Promise<any> {
    logCall("openLink", params.url, undefined);
    window.open(params.url, "_blank", "noopener");
    return { isError: false };
  }

  async downloadFile(params: unknown, _options?: unknown): Promise<any> {
    logCall("downloadFile", "(host)", params);
    return { isError: false };
  }

  async requestTeardown(_params?: unknown): Promise<void> {
    logCall("requestTeardown", "(host)", undefined);
  }

  async requestDisplayMode(
    params: { mode: "inline" | "fullscreen" | "pip" },
    _options?: unknown,
  ): Promise<any> {
    this._hostContext.displayMode = params.mode;
    logCall("requestDisplayMode", params.mode, undefined);
    return { mode: params.mode };
  }

  async sendSizeChanged(_params: unknown): Promise<void> {
    /* no-op */
  }

  setupSizeChangedNotifications(): () => void {
    return () => { /* no-op */ };
  }

  // ── Notification handler setters ───────────────────────────────────────
  set ontoolinput(cb: (params: unknown) => void) { this._ontoolinput = cb; }
  set ontoolinputpartial(cb: (params: unknown) => void) { this._ontoolinputpartial = cb; }
  set ontoolresult(cb: (params: unknown) => void) { this._ontoolresult = cb; }
  set ontoolcancelled(cb: (params: unknown) => void) { this._ontoolcancelled = cb; }

  set onhostcontextchanged(cb: (params: { hostContext: McpUiHostContext }) => void) {
    this._onhostcontextchanged = cb;
    // Fire once so views that read `ctx.theme` on mount pick up the initial value.
    queueMicrotask(() => cb({ hostContext: { ...this._hostContext } }));
  }

  set onteardown(cb: (params: unknown, extra: unknown) => unknown) {
    this._onteardown = cb;
  }

  set oncalltool(_cb: unknown) { /* view-as-server tools not used here */ }
  set onlisttools(_cb: unknown) { /* view-as-server tools not used here */ }

  // ── Manual fan-out helpers for the harness itself ──────────────────────
  /** @internal — called by the harness when the user toggles theme. */
  _emitHostContextChanged(patch: Partial<McpUiHostContext>) {
    this._hostContext = { ...this._hostContext, ...patch };
    this._onhostcontextchanged?.({ hostContext: { ...this._hostContext } });
  }

  /** @internal — not used, reserved for future harness scripting. */
  _emitToolResult(params: unknown) {
    this._ontoolresult?.(params);
  }

  // ── Inherited Protocol API stubs (unused by views but typed for parity) ─
  setRequestHandler(_schema: unknown, _handler: unknown): void { /* no-op */ }
  setNotificationHandler(_schema: unknown, _handler: unknown): void { /* no-op */ }
  close(): void {
    const i = liveApps.indexOf(this);
    if (i >= 0) liveApps.splice(i, 1);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// Style applicators — re-exports expected by the real package.
// ──────────────────────────────────────────────────────────────────────────

export function applyHostStyleVariables(_el?: Element) { /* no-op */ }
export function applyHostFonts(_el?: Element) { /* no-op */ }
export function getDocumentTheme(): "dark" | "light" { return currentTheme; }
export function applyDocumentTheme(theme: "dark" | "light") { applyTheme(theme); }

// Constants the views don't use directly but some typings reference.
export const RESOURCE_URI_META_KEY = "ui/resourceUri";
export const RESOURCE_MIME_TYPE = "text/html;profile=mcp-app";

// ──────────────────────────────────────────────────────────────────────────
// Dev banner — small corner chip so the designer knows they're in the harness
// ──────────────────────────────────────────────────────────────────────────

function injectBanner() {
  if (document.getElementById("harness-banner")) return;
  const banner = document.createElement("div");
  banner.id = "harness-banner";
  banner.textContent = `harness · ${activeView} · ${currentTheme} (press T)`;
  banner.style.cssText = [
    "position:fixed",
    "bottom:8px",
    "right:8px",
    "z-index:2147483647",
    "padding:4px 10px",
    "font:11px/1.4 'Fira Mono', ui-monospace, monospace",
    "color:#b9b9ae",
    "background:rgba(23,23,22,0.85)",
    "border:1px solid #474745",
    "border-radius:4px",
    "pointer-events:none",
    "user-select:none",
    "letter-spacing:0.02em",
  ].join(";");
  document.body.appendChild(banner);
}

// Keep banner text in sync with theme toggle.
const updateBanner = () => {
  const el = document.getElementById("harness-banner");
  if (el) el.textContent = `harness · ${activeView} · ${currentTheme} (press T)`;
};
window.addEventListener("keydown", (e) => {
  if (e.key === "t" || e.key === "T") queueMicrotask(updateBanner);
});

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", injectBanner);
} else {
  injectBanner();
}
