/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { App } from "@modelcontextprotocol/ext-apps";

/**
 * Injects the design-system CSS variables (colors, typography, radii, motion)
 * into the page and wires up host-context theme switching.
 *
 * All real component styling lives in `src/shared/components/*.css` and the
 * per-view `styles.css` files. This function ONLY provides the variables they
 * reference, plus a `data-theme="light"` attribute toggle when the host says
 * the user prefers light mode.
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
