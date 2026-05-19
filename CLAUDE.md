# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

An [MCP App](https://modelcontextprotocol.io/extensions/apps/overview) for Elastic Security. The server (Node ≥ 22) talks to Elasticsearch + Kibana and exposes both model-facing tools (the LLM calls these) and app-only tools (called from the in-iframe React UI). Each model-facing tool ships an interactive React view bundled into a single self-contained HTML file.

Distributed three ways: `.mcpb` bundle (Claude Desktop), `npm` tarball (Cursor/VS Code/npx), and skill `.zip`s (Claude Desktop Skills).

## Commands

```bash
npm run dev            # Concurrently: watch-rebuild views + tsx watch on main.ts (HTTP on :3001/mcp)
npm run typecheck      # tsc --noEmit only
npm run build          # tsc --noEmit && tsc -p tsconfig.server.json && per-view Vite singlefile bundles
npm run build:views    # Build views only (drives scripts/build-views.js → vite per view)
npm run build:server   # tsc -p tsconfig.server.json only
npm run start          # node dist/main.js (HTTP)
npm run start:stdio    # node dist/main.js --stdio (use for MCP host wiring locally)
npm run standalone:dev # tsx standalone/server.ts (alternate entry)

npm run lint           # eslint . (enforces local require-license-header rule)
npm run lint:fix
npm run test           # vitest watch mode
npm run test:run       # vitest single run — use this in scripts/CI
npm run test:coverage
npm run test:permissions   # Live perms test against a real cluster (see scripts/test-permissions/README.md)

npm run mcpb:pack      # Build + esbuild bundle + mcpb pack → elastic-security-mcp-app.mcpb
npm run skills:zip     # Zip each skills/* dir → dist/skills/<name>.zip
```

Run a single test file: `npx vitest run src/tools/alert-triage.test.ts`. Run by name: `npx vitest run -t "acknowledges"`.

The version script in `package.json` keeps `manifest.json` in sync with `package.json` on `npm version`.

## Architecture

### Two-layer tool model

Driven by the MCP Apps spec. Read [docs/architecture.md](docs/architecture.md) for the canonical version.

- **Model-facing tools** (`triage-alerts`, `triage-attack-discoveries`, `manage-cases`, `manage-rules`, `threat-hunt`, `generate-sample-data`, `generate-attack-discovery`) return a **compact** JSON summary (~1–5 KB) to the LLM AND attach a `ui://…/mcp-app.html` resource via `_meta.ui.resourceUri`. The MCP host renders that HTML in a sandboxed iframe alongside the LLM response.
- **App-only tools** (`poll-alerts`, `get-alert-context`, `investigate-entity`, `get-entity-detail`, `execute-esql`, `get-case-alerts`, `get-case-comments`, …) are marked `_meta.ui.visibility: ["app"]` so the LLM never sees them. The UI calls them directly via `app.callServerTool()` for all subsequent interaction — keeps the LLM context small while the UI has full data access.

This is the central design constraint: **model-facing tool results must stay compact**. Do not dump full Elasticsearch documents into the response — slice/project first, and let the UI lazy-load full data via app-only tools.

### Layered request pipeline

```
main.ts (transport: stdio | HTTP /mcp)
  └─ src/server.ts (createServer)
      ├─ credential-client (CLUSTERS_JSON / CLUSTERS_FILE → Zod-validated config; built once at startup)
      ├─ es-client + kibana-client (per-cluster, currently pinned to the default cluster)
      ├─ src/elastic/client/* (thin per-resource HTTP wrappers: AlertsClient, RulesClient, …)
      ├─ src/elastic/service/* (business logic on top of clients: AlertsService, RulesService, …)
      └─ src/tools/*.ts (register{Tool}Tools(server, services) — defines MCP tools + UI resource)
```

- `main.ts` builds the `credentialClient` **once** at process startup so HTTP mode doesn't re-read `CLUSTERS_FILE` and re-run Zod on every `POST /mcp`. Per the MCP TS SDK stateless-HTTP guidance, each request still gets a **fresh** `McpServer` + transport.
- `createServer` is intentionally pinned to the **default** cluster for now. Multi-cluster routing is in progress: config + Zod already accept multiple clusters, but tools don't take a cluster param yet.
- The client/service split exists so tests can stub the client (thin HTTP layer) without faking ES responses to the business logic. Most logic should live in the service; the client is just request shaping.

### Views are self-contained HTML

Each view lives in `src/views/<name>/` (entry: `mcp-app.html` + `mcp-app.tsx` + `App.tsx`). `scripts/build-views.js` iterates that directory and invokes Vite once per view with `INPUT` and `VITE_OUT_DIR` env vars; `vite-plugin-singlefile` inlines every asset so the output is one HTML file at `dist/views/<name>/mcp-app.html`. The server reads that file and serves it as a `ui://…/mcp-app.html` resource. `resolveViewPath()` in [src/tools/view-path.ts](src/tools/view-path.ts) handles the various `__dirname` shapes (esbuild bundle, tsc emit, tsx dev).

UI ↔ server communication uses the `@modelcontextprotocol/ext-apps` `app.*` surface: `callServerTool`, `ontoolresult`, `ontoolinput` (verdict streaming), `updateModelContext`, `sendMessage`, `requestDisplayMode`. The `@shared` Vite alias resolves to `src/shared/` for cross-view code (types, theme, components).

### Config

`CLUSTERS_JSON` (inline JSON array) or `CLUSTERS_FILE` (path to JSON file with same shape). `CLUSTERS_FILE` wins if both are set. Cluster entries are `{ name, elasticsearchUrl, kibanaUrl, elasticsearchApiKey }`. Config is validated with Zod at startup and detects unmodified placeholder values from the install templates — startup fails loud so the first tool call doesn't silently hit a fake hostname. See [src/elastic/credential-client/create-credential-client.ts](src/elastic/credential-client/create-credential-client.ts).

The `.mcpb` manifest (`manifest.json`) only exposes the **single-cluster** fields (`elasticsearch_url`, `kibana_url`, `elasticsearch_api_key`) and assembles them into a one-entry `CLUSTERS_JSON` — the multi-cluster picker UX hasn't landed yet.

### Kibana 9.x compatibility

All Kibana API calls must include `elastic-api-version: 2023-10-31`, `x-elastic-internal-origin: Kibana` for internal APIs, and camelCase field names. Honor this when adding new Kibana calls.

## Conventions

- **Strict TypeScript.** `tsconfig.json` is the IDE/typecheck config (noEmit, includes scripts + tests); `tsconfig.server.json` emits the server bundle and excludes views/tests. Don't widen `strict`.
- **License header on every TS/TSX/JS/MJS file** under `src/`, top-level `.ts`, `scripts/**/*.js`, and `*.mjs`. The local ESLint rule `local-rules/require-license-header` (see [lint-license-rule.mjs](lint-license-rule.mjs)) enforces the Elastic-2.0 banner. Copy from any existing file; `npm run lint` will fail otherwise.
- **Tests live next to code** as `*.test.ts` / `*.test.tsx` and run under `jsdom` (so React Testing Library works for view code). Setup file: [src/test/setup.ts](src/test/setup.ts).
- **Pre-commit hook** runs `eslint --fix` on staged TS/TSX/JS/MJS via lint-staged (Husky).

## Adding a new tool

1. Add a client in `src/elastic/client/` (HTTP shaping) and a service in `src/elastic/service/` (business logic).
2. Add a `src/tools/<name>.ts` exporting `register<Name>Tools(server, deps)`. Use `registerAppTool` from `@modelcontextprotocol/ext-apps/server`. For model-facing tools, attach `_meta: { ui: { resourceUri: "ui://<name>/mcp-app.html" } }` and register the resource with `registerAppResource` pointing at `resolveViewPath("<name>")`. For app-only tools, set `_meta: { ui: { visibility: ["app"] } }`.
3. Wire it into [src/server.ts](src/server.ts).
4. If it has a UI, create `src/views/<name>/{mcp-app.html, mcp-app.tsx, App.tsx}` — `build-views.js` will pick it up automatically.
5. If model-facing, also add it to `tools` in `manifest.json` (used by the `.mcpb` package).
6. **Keep the model-facing result compact** — project fields, slice arrays, push everything else through an app-only tool.

## Permissions

The `npm run test:permissions` runner provisions the documented roles + scoped API keys against a real cluster, then exercises every read/write operation through `src/elastic/*`. When you add a new operation, update `operationChecks` in [scripts/test-permissions/roles.ts](scripts/test-permissions/roles.ts) so the matrix stays honest. Required-permissions reference: [docs/permissions.md](docs/permissions.md).
