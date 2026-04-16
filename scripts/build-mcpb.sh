#!/usr/bin/env bash
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

#
# Build an MCPB bundle (.mcpb) for Claude Desktop distribution.
# Produces elastic-security-mcp-app.mcpb in the repo root.
# Usage: ./scripts/build-mcpb.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

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
echo ""
echo "==> Done! elastic-security-mcp-app.mcpb (v${VERSION}) is ready."
echo ""
echo "Distribute via GitHub release:"
echo "  gh release create v${VERSION} elastic-security-mcp-app.mcpb"
echo ""
echo "Install in Claude Desktop:"
echo "  Double-click the .mcpb file"
