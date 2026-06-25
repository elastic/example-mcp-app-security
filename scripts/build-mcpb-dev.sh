#!/usr/bin/env bash
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

#
# Build a parallel-installable MCPB bundle (.mcpb) for Claude Desktop.
#
# Claude Desktop keys installed extensions by the manifest's `name` field, so
# two `.mcpb` files with the same `name` overwrite each other on install. This
# script temporarily rewrites `name` and `display_name` so the bundle installs
# alongside the production build instead of replacing it. The original
# manifest.json is always restored on exit, even on failure.
#
# Usage:
#   ./scripts/build-mcpb-dev.sh             # suffix defaults to "dev"
#   ./scripts/build-mcpb-dev.sh staging     # → elastic-security-mcp-app-staging.mcpb
#
set -euo pipefail

SUFFIX="${1:-dev}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MANIFEST="$ROOT/manifest.json"
BACKUP="$ROOT/manifest.json.bak"

if [ -f "$BACKUP" ]; then
  echo "==> Refusing to start: $BACKUP already exists (previous run aborted?)."
  echo "    Inspect it, then either restore it over manifest.json or delete it."
  exit 1
fi

cp "$MANIFEST" "$BACKUP"
trap 'mv -f "$BACKUP" "$MANIFEST"' EXIT

echo "==> Patching manifest.json: suffix='-${SUFFIX}'"
SUFFIX="$SUFFIX" node -e '
  const fs = require("fs");
  const suffix = process.env.SUFFIX;
  const m = JSON.parse(fs.readFileSync("manifest.json", "utf-8"));
  m.name = `${m.name}-${suffix}`;
  const labelled = suffix.charAt(0).toUpperCase() + suffix.slice(1);
  m.display_name = `${m.display_name} (${labelled})`;
  fs.writeFileSync("manifest.json", JSON.stringify(m, null, 2) + "\n");
'

echo "==> Building project..."
npm run build

echo "==> Bundling server with esbuild..."
npx esbuild dist/main.js \
  --bundle \
  --platform=node \
  --format=esm \
  --target=node22 \
  --outfile=dist/main.bundle.mjs \
  --banner:js="import{createRequire}from'module';const require=createRequire(import.meta.url);"

echo "==> Packing MCPB bundle..."
npx @anthropic-ai/mcpb pack .

VERSION=$(node -e "console.log(require('./package.json').version)")
NAME=$(node -e "console.log(require('./manifest.json').name)")
OUTPUT="${NAME}.mcpb"

echo ""
echo "==> Done! ${OUTPUT} (v${VERSION}) is ready."
echo ""
echo "Install in Claude Desktop:"
echo "  Double-click the .mcpb file"
echo ""
echo "Note: manifest.json has been restored to the production name."
