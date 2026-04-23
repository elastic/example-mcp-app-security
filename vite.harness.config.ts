/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

/**
 * Vite config for the Storybook-like harness.
 *
 * Runs `vite` with the repo root as dev-server root (so view HTML files under
 * `src/views/<slug>/mcp-app.html` are served directly) and aliases the MCP
 * ext-apps package to a local stub that resolves `callServerTool(...)` against
 * canned fixtures instead of going over postMessage.
 *
 * Usage:
 *   npm run harness       → opens http://localhost:5370/harness/
 *
 * Edit:
 *   harness/fixtures/<view>.ts   → canned tool responses; hot-reloads
 *   harness/mock-ext-apps.ts     → the App shim
 *   harness/index.tsx / .css     → catalogue landing page
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: __dirname,
  plugins: [tailwindcss(), react()],
  resolve: {
    alias: {
      "@shared": path.resolve(__dirname, "src/shared"),
      // Swap the real MCP ext-apps package for the harness shim.
      "@modelcontextprotocol/ext-apps": path.resolve(__dirname, "harness/mock-ext-apps.ts"),
    },
  },
  server: {
    port: 5370,
    strictPort: false,
    open: "/harness/",
    fs: {
      // Allow importing types from src/shared inside fixtures.
      allow: [__dirname],
    },
  },
  // No build — the harness is dev-only. Users still run `npm run build` for
  // production, which uses the vanilla vite.config.ts.
});
