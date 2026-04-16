/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License;
 * you may not use this file except in compliance with the Elastic License.
 */

import type { App } from "@modelcontextprotocol/ext-apps";

export function applyTheme(app: App) {
  const style = document.createElement("style");
  style.textContent = `
    :root {
      --bg-primary: #0f1117;
      --bg-secondary: #161822;
      --bg-tertiary: #1c1f2e;
      --bg-elevated: #222639;
      --bg-hover: #262a3d;
      --bg-active: #2d3250;
      --text-primary: #e8eaf0;
      --text-secondary: #a0a4b8;
      --text-muted: #636882;
      --text-dim: #464b63;
      --border: #282d42;
      --border-subtle: #1f2336;
      --border-focus: #4c6ef5;
      --accent: #5c7cfa;
      --accent-hover: #748ffc;
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
      --font-mono: 'SF Mono', 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
      --font-sans: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', system-ui, sans-serif;
      --radius-sm: 4px;
      --radius-md: 8px;
      --radius-lg: 12px;
      --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
      --shadow-md: 0 4px 12px rgba(0,0,0,0.4);
      --shadow-lg: 0 8px 32px rgba(0,0,0,0.5);
      --transition-fast: 0.15s cubic-bezier(0.4, 0, 0.2, 1);
      --transition-normal: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }

    [data-theme="light"] {
      --bg-primary: #f5f6fa;
      --bg-secondary: #ffffff;
      --bg-tertiary: #eef0f6;
      --bg-elevated: #ffffff;
      --bg-hover: #e8eaf2;
      --bg-active: #dde0ec;
      --text-primary: #1a1d2e;
      --text-secondary: #4a4f6a;
      --text-muted: #7a7f98;
      --text-dim: #a0a4b8;
      --border: #d8dbe8;
      --border-subtle: #e8eaf2;
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
