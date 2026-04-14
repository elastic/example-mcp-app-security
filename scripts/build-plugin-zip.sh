#!/usr/bin/env bash
#
# Build a distributable Claude Code plugin zip.
# Bundles the MCP server into a single JS file (no node_modules needed).
# Usage: ./scripts/build-plugin-zip.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Build TypeScript + views
echo "==> Building project..."
npm run build

# Bundle dist/main.js + all deps into a single file
echo "==> Bundling server with esbuild..."
npx esbuild dist/main.js \
  --bundle \
  --platform=node \
  --format=esm \
  --target=node22 \
  --outfile=dist/main.bundle.mjs \
  --banner:js="import{createRequire}from'module';const require=createRequire(import.meta.url);"

VERSION=$(node -e "console.log(require('./package.json').version)")
OUT="$ROOT/elastic-security-plugin-${VERSION}.zip"

rm -f "$OUT"

echo "==> Packaging plugin v${VERSION}..."
zip -r "$OUT" \
  .claude-plugin/ \
  skills/ \
  agents/ \
  bin/ \
  dist/views/ \
  dist/main.bundle.mjs \
  .env.example \
  README.md \
  LICENSE \
  -x "skills/*/Archive.zip" \
  -x "*.DS_Store"

SIZE=$(du -h "$OUT" | cut -f1)
FILES=$(unzip -l "$OUT" 2>/dev/null | tail -1 | awk '{print $2}')
echo "==> Created $OUT ($SIZE, $FILES files)"
echo ""
echo "Install in Claude Desktop:"
echo "  Settings > Plugins > Upload > drag $OUT"
echo ""
echo "Install in Claude Code:"
echo "  unzip $OUT -d elastic-security-plugin"
echo "  claude --plugin-dir ./elastic-security-plugin"
