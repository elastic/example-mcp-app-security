#!/usr/bin/env bash
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

#
# Build an MCPB bundle (.mcpb) for Claude Desktop distribution.
# Produces example-mcp-app-security.mcpb in the repo root.
# Usage: ./scripts/build-mcpb.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_MCPB="example-mcp-app-security.mcpb"
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

shopt -s nullglob
mcpb_files=( *.mcpb )
if [ "${#mcpb_files[@]}" -ne 1 ]; then
  echo "Expected exactly one .mcpb file after packing, found ${#mcpb_files[@]}." >&2
  exit 1
fi

if [ "${mcpb_files[0]}" != "$TARGET_MCPB" ]; then
  mv "${mcpb_files[0]}" "$TARGET_MCPB"
fi

VERSION=$(node -e "console.log(require('./package.json').version)")
echo ""
echo "==> Done! ${TARGET_MCPB} (v${VERSION}) is ready."
echo ""
echo "Distribute via GitHub release:"
echo "  gh release create v${VERSION} ${TARGET_MCPB}"
echo ""
echo "Install in Claude Desktop:"
echo "  Double-click the .mcpb file"
