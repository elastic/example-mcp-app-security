# Contributing

Thank you for your interest in contributing to the Elastic Security MCP App.

## Prerequisites

- **Node.js 22+**
- **npm** (included with Node.js)
- **Elasticsearch 8.x or 9.x** with Security enabled (for runtime testing)
- **Kibana 8.x or 9.x** (for cases, rules, and attack discovery)

## Getting Started

```bash
git clone https://github.com/elastic/example-mcp-app-security.git
cd example-mcp-app-security
npm install
cp .env.example .env
# Edit .env with your Elasticsearch/Kibana URLs and API keys
```

## Development

```bash
npm run dev          # Watch mode (rebuilds server + views on change)
npm run typecheck    # Type-check only (no emit)
npm run build        # Full build: typecheck → tsc → Vite views
npm run build:server # Build server only (tsc)
npm run build:views  # Build views only (Vite)
```

The dev server runs on `http://localhost:3001/mcp` in HTTP mode. Use `npm run start:stdio` to test stdio transport locally.

## Project Structure

| Path | Description |
|------|-------------|
| `main.ts` | Entry point — HTTP and stdio transport |
| `src/server.ts` | MCP server factory — registers all tool modules |
| `src/elastic/` | Elasticsearch and Kibana API clients |
| `src/tools/` | MCP tool definitions (model-facing + app-only) |
| `src/views/` | React UIs (one per capability, bundled as single HTML files) |
| `src/shared/` | Shared UI components, types, and utilities |
| `skills/` | Claude Desktop Skills (`SKILL.md` per capability) |

## Building Distribution Packages

The project supports two distribution formats. Both start from the same build pipeline.

### Full Build

```bash
npm run build
```

This runs the TypeScript compiler (type-check + emit to `dist/`) and builds each React view into a self-contained HTML file under `dist/views/`.

### MCPB Bundle (for Claude Desktop)

[MCPB](https://github.com/modelcontextprotocol/mcpb) is a packaging format for MCP servers — a `.mcpb` file that users double-click to install in Claude Desktop with zero prerequisites (Node.js ships bundled with Claude Desktop).

```bash
npm run mcpb:pack
```

This script (`scripts/build-mcpb.sh`) does three things:

1. Runs `npm run build` (TypeScript + Vite views)
2. Bundles the server into a single file with esbuild (`dist/main.bundle.mjs`) — no `node_modules` needed at runtime
3. Runs `mcpb pack .` which reads `manifest.json` and `.mcpbignore` to produce the `.mcpb` archive

The resulting file is `example-mcp-app-security.mcpb` in the repo root.

**Key files:**

- `manifest.json` — MCPB spec v0.3 manifest declaring server config, user-configurable credentials, tool metadata, and compatibility
- `.mcpbignore` — controls which files are excluded from the bundle (keeps it lean by only including the esbuild bundle + views)

### Claude Code Plugin Zip

```bash
npm run plugin:zip
```

Produces a `.zip` for Claude Code's plugin system (`scripts/build-plugin-zip.sh`). Includes the esbuild bundle, views, skills, agents, and the `.claude-plugin/plugin.json` manifest.

### npm Package (for VS Code / npx)

The `package.json` is configured for npm publishing with `bin`, `main`, and `files` fields. To publish:

```bash
npm publish --access public
```

The `prepublishOnly` script automatically runs the build before publishing. Users install via:

```
npx elastic-security-mcp-app --stdio
```

## Release Process

Releases are automated via GitHub Actions (`.github/workflows/release.yml`). To create a release:

```bash
# Update version in package.json and manifest.json
npm version patch  # or minor/major

# Push the tag
git push origin --tags
```

The workflow will:

1. Build the project and create the esbuild bundle
2. Pack the `.mcpb` bundle
3. Create a GitHub release with the `.mcpb` file attached
4. Optionally publish to npm (when the `NPM_PUBLISH` repository variable is set to `true` and an `NPM_TOKEN` secret is configured)

## Adding a New Tool

1. Create the Elastic API client functions in `src/elastic/`
2. Create the tool registration module in `src/tools/` using `registerAppTool` from `@modelcontextprotocol/ext-apps/server`
3. Register the module in `src/server.ts`
4. If the tool has a UI, create a new view directory under `src/views/` with `mcp-app.html` and `App.tsx`
5. Update `manifest.json` if the tool is model-facing (add to the `tools` array)
6. Run `npm run typecheck` to verify

## Code Style

- TypeScript strict mode is enabled
- Views use React 19 with Tailwind CSS 4
- Each view is bundled into a single self-contained HTML file (no external assets)
- Tool results should be compact summaries — the UI loads full data independently via app-only tools

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 license.
