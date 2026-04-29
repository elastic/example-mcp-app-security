/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { App } from "@modelcontextprotocol/ext-apps";

/**
 * Injects the shared design-system stylesheet into the page and wires up the
 * host-context theme toggle. All views call this on mount.
 *
 * The design system is derived from the Alert Triage view (Figma "One Workflow"
 * alert-triage screens). It exposes:
 *
 *  1. CSS variables for color, typography, radii and motion (dark + light)
 *  2. A set of `.ds-*` utility classes covering the recurring surface patterns:
 *     headers, cards, widget panels, tags, search input, "Showing N" subheader,
 *     progress bars, fact sub-box, icon buttons, and severity stripes.
 *
 *  Any view can drop these classes into JSX directly — no per-view boilerplate.
 */
export function applyTheme(app: App) {
  const style = document.createElement("style");
  style.textContent = `
    :root {
      /* ── Surfaces (dark, Figma-derived) ─────────────────────────────── */
      --bg-primary: #1f1f1e;        /* page + widget panel background */
      --bg-secondary: #1f1f1e;      /* secondary surface — same as primary in DS */
      --bg-tertiary: #171716;       /* deepest surface: tracks, inset inputs */
      --bg-elevated: #262626;       /* cards, search input, elevated surfaces */
      --bg-hover: #2a2a2a;          /* hover state on elevated */
      --bg-active: #333333;         /* active/pressed */

      /* ── Text ───────────────────────────────────────────────────────── */
      --text-primary: #e6e6e5;      /* headings, primary content */
      --text-secondary: #adaca1;    /* body copy, reason */
      --text-muted: #817f78;        /* labels, dim metadata, placeholder */
      --text-dim: #7b7972;          /* even dimmer */
      --ds-text-label: #b9b9ae;     /* Fira Mono data labels (facts, legends) */

      /* ── Borders ────────────────────────────────────────────────────── */
      --border: #474745;            /* primary border for cards/panels/inputs */
      --border-subtle: #2a2a2a;     /* subtle divider when #474745 is too hot */
      --border-focus: #5c7cfa;

      /* ── Accent + severity (Figma palette) ──────────────────────────── */
      --accent: #5c7cfa;
      --accent-hover: #7c97fb;
      --accent-dim: rgba(92, 124, 250, 0.12);
      --severity-low: #40c790;
      --severity-medium: #f0b840;
      --severity-high: #f07840;
      --severity-critical: #f04040;
      --severity-low-bg: rgba(64, 199, 144, 0.08);
      --severity-medium-bg: rgba(240, 184, 64, 0.08);
      --severity-high-bg: rgba(240, 120, 64, 0.08);
      --severity-critical-bg: rgba(240, 64, 64, 0.08);
      --severity-low-border: rgba(64, 199, 144, 0.25);
      --severity-medium-border: rgba(240, 184, 64, 0.25);
      --severity-high-border: rgba(240, 120, 64, 0.25);
      --severity-critical-border: rgba(240, 64, 64, 0.25);
      --success: #40c790;
      --warning: #f0b840;
      --error: #f04040;

      /* ── Typography (Fira Sans / Fira Mono per Figma) ───────────────── */
      --font-sans: 'Fira Sans', -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', system-ui, sans-serif;
      --font-mono: 'Fira Mono', 'SF Mono', 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;

      /* ── Radii ──────────────────────────────────────────────────────── */
      --radius-sm: 4px;
      --radius-md: 8px;
      --radius-lg: 12px;
      --radius-tag: 6px;            /* MITRE-style pill/tag */
      --radius-input: 7px;          /* search input */
      --radius-track: 10px;         /* progress bar track/fill */

      /* ── Elevation + motion ─────────────────────────────────────────── */
      --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
      --shadow-md: 0 4px 12px rgba(0,0,0,0.4);
      --shadow-lg: 0 8px 32px rgba(0,0,0,0.5);
      --transition-fast: 0.15s cubic-bezier(0.4, 0, 0.2, 1);
      --transition-normal: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }

    [data-theme="light"] {
      --bg-primary: #f7f7f6;
      --bg-secondary: #f7f7f6;
      --bg-tertiary: #ececea;
      --bg-elevated: #ffffff;
      --bg-hover: #ececea;
      --bg-active: #dddcd8;
      --text-primary: #1a1a19;
      --text-secondary: #4a4a46;
      --text-muted: #817f78;
      --text-dim: #a3a3a0;
      --ds-text-label: #4a4a46;
      --border: #d8d8d4;
      --border-subtle: #ececea;
      --shadow-sm: 0 1px 2px rgba(0,0,0,0.06);
      --shadow-md: 0 4px 12px rgba(0,0,0,0.08);
      --shadow-lg: 0 8px 32px rgba(0,0,0,0.12);
    }

    /* ──────────────────────────────────────────────────────────────────
     * Design System — reusable pattern classes
     * Derived 1:1 from the Alert Triage view.
     * ────────────────────────────────────────────────────────────────── */

    /* Root view container — 100vh column flex with an outer 1px stroke */
    .ds-view {
      height: 100vh;
      min-height: 500px;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      border: 1px solid var(--border);
      background: var(--bg-primary);
      color: var(--text-primary);
      font-family: var(--font-sans);
    }

    /* Top header bar — title on the left, actions on the right */
    .ds-header {
      display: flex;
      align-items: center;
      gap: 24px;
      padding: 16px;
      background: var(--bg-primary);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
      z-index: 10;
    }

    .ds-header-title {
      margin: 0;
      font-family: var(--font-sans);
      font-size: 20px;
      font-weight: 600;
      line-height: 16px;
      color: var(--text-primary);
      letter-spacing: 0;
      white-space: nowrap;
    }

    .ds-header-actions {
      display: flex;
      align-items: center;
      gap: 16px;
      flex-shrink: 0;
      margin-left: auto;
    }

    /* Card surface — bordered, flat, 24px padding */
    .ds-card {
      position: relative;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 0;
      padding: 24px;
    }

    /* Widget panel — bg same as page, right+bottom borders so panels chain
     * together with shared edges. Use inside a flex container. */
    .ds-panel {
      flex: 1 1 0;
      min-width: 0;
      display: flex;
      flex-direction: column;
      gap: 16px;
      padding: 24px;
      background: var(--bg-primary);
      border-right: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
    }

    .ds-panel:last-child { border-right: none; }

    .ds-panel-title {
      font-family: var(--font-sans);
      font-size: 12px;
      font-weight: 400;
      line-height: 16px;
      color: var(--text-muted);
    }

    /* Search input — used in every view's header */
    .ds-search {
      position: relative;
      display: flex;
      align-items: center;
      gap: 9px;
      width: 366px;
      max-width: 100%;
      padding: 10px 24px 10px 8px;
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: var(--radius-input);
      transition: border-color var(--transition-fast);
    }

    .ds-search:focus-within { border-color: var(--accent); }
    .ds-search svg { color: var(--text-muted); flex-shrink: 0; }

    .ds-search input {
      flex: 1 1 0;
      min-width: 0;
      padding: 0;
      background: transparent;
      border: none;
      outline: none;
      font-family: var(--font-sans);
      font-size: 12px;
      line-height: 16px;
      color: var(--text-primary);
    }

    .ds-search input::placeholder { color: var(--text-muted); }

    /* 16px icon button — header-right utility */
    .ds-btn-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 16px;
      height: 16px;
      padding: 0;
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      transition: color var(--transition-fast);
    }
    .ds-btn-icon:hover { color: var(--text-primary); }

    /* MITRE-style tags — two variants, both rounded 6px */
    .ds-tag {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 3px 8px;
      border-radius: var(--radius-tag);
      font-family: var(--font-sans);
      font-size: 12px;
      line-height: 16px;
      color: var(--text-muted);
      white-space: nowrap;
      border: 1px solid var(--border);
      background: transparent;
    }
    .ds-tag-secondary {
      background: var(--bg-primary);
      border-color: var(--bg-primary);
    }

    /* "Showing N alerts    Group by: None" subheader bar */
    .ds-subheader {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 16px;
      color: var(--ds-text-label);
      white-space: nowrap;
    }
    .ds-subheader strong { font-weight: 400; color: #ffffff; }
    [data-theme="light"] .ds-subheader strong { color: #000000; }

    /* Progress-bar rows — track + fill */
    .ds-bar-row {
      display: flex;
      align-items: center;
      gap: 36px;
      height: 16px;
    }
    .ds-bar-label {
      flex: 0 0 130px;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 16px;
      color: var(--ds-text-label);
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .ds-bar-track {
      flex: 1 1 0;
      min-width: 0;
      height: 4px;
      background: var(--bg-tertiary);
      border-radius: var(--radius-track);
      overflow: hidden;
    }
    .ds-bar-fill {
      height: 100%;
      transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      background: var(--accent);
    }
    .ds-bar-fill-amber { background: var(--severity-medium); }
    .ds-bar-fill-blue  { background: var(--accent); }
    .ds-bar-value {
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 16px;
      color: var(--ds-text-label);
      font-variant-numeric: tabular-nums;
      flex: 0 0 auto;
      min-width: 20px;
      text-align: right;
    }

    /* Fact sub-box (HOST / USER / PROCESS block inside alert cards) */
    .ds-fact-box {
      background: var(--bg-primary);
      padding: 16px;
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 8px;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 16px;
      color: var(--ds-text-label);
    }
    .ds-fact-row {
      display: flex;
      align-items: center;
      gap: 28px;
      min-width: 0;
    }
    .ds-fact-label {
      flex-shrink: 0;
      width: 59px;
      color: var(--ds-text-label);
    }
    .ds-fact-value {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--ds-text-label);
      text-decoration: underline dotted;
      text-decoration-thickness: from-font;
      text-underline-offset: 2px;
      text-decoration-skip-ink: none;
    }

    /* Severity stripe — apply to a card with position: relative */
    .ds-stripe-low      { box-shadow: inset 3px 0 0 0 var(--severity-low); }
    .ds-stripe-medium   { box-shadow: inset 3px 0 0 0 var(--severity-medium); }
    .ds-stripe-high     { box-shadow: inset 3px 0 0 0 var(--severity-high); }
    .ds-stripe-critical { box-shadow: inset 3px 0 0 0 var(--severity-critical); }

    /* Query pill — filter chip with close button */
    .ds-query-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 10px;
      border-radius: 20px;
      background: var(--accent-dim);
      border: 1px solid var(--border-focus);
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--accent);
    }
    .ds-query-pill button {
      background: transparent;
      border: none;
      color: var(--accent);
      cursor: pointer;
      font-size: 14px;
      line-height: 1;
      padding: 0;
    }

    /* Minimal scrollbar styling — applies to everything on the page */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }
  `;
  document.head.appendChild(style);

  app.onhostcontextchanged = (ctx) => {
    const hostCtx = ctx.hostContext as Record<string, unknown> | undefined;
    if (hostCtx?.theme === "light") {
      document.documentElement.setAttribute("data-theme", "light");
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  };
}

export function timeAgo(date: string | Date): string {
  const now = Date.now();
  const then = new Date(date).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(date).toLocaleDateString();
}
