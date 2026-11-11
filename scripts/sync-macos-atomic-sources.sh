#!/usr/bin/env bash
# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_root="${MACOS_ATOMIC_CACHE_DIR:-$project_root/.macos-atomic-cache}"
art_ref="${1:-master}"
invoke_ref="${2:-master}"

art_url="https://github.com/redcanaryco/atomic-red-team.git"
invoke_url="https://github.com/redcanaryco/invoke-atomicredteam.git"
art_dir="$cache_root/atomic-red-team"
invoke_dir="$cache_root/invoke-atomicredteam"

mkdir -p "$cache_root"

sync_repo() {
  local url="$1"
  local destination="$2"
  local ref="$3"
  local sparse="$4"

  if [[ ! -d "$destination/.git" ]]; then
    git clone --filter=blob:none --no-checkout "$url" "$destination"
  fi
  if [[ "$(git -C "$destination" remote get-url origin)" != "$url" ]]; then
    echo "Refusing cache with unexpected origin: $destination" >&2
    exit 1
  fi
  if [[ "$sparse" == "atomics" ]] &&
    [[ "$(git -C "$destination" config --bool core.sparseCheckout || true)" != "true" ]]; then
    git -C "$destination" sparse-checkout init --cone
  fi
  if [[ "$sparse" == "atomics" ]]; then
    git -C "$destination" sparse-checkout set atomics
  fi
  git -C "$destination" fetch --depth 1 origin "$ref"
  git -C "$destination" checkout --detach FETCH_HEAD
  synced_revision="$(git -C "$destination" rev-parse HEAD)"
}

synced_revision=""
sync_repo "$art_url" "$art_dir" "$art_ref" atomics
art_revision="$synced_revision"
sync_repo "$invoke_url" "$invoke_dir" "$invoke_ref" full
invoke_revision="$synced_revision"

printf '{\n'
printf '  "atomics_path": "%s",\n' "$art_dir/atomics"
printf '  "atomic_red_team_revision": "%s",\n' "$art_revision"
printf '  "invoke_atomicredteam_revision": "%s"\n' "$invoke_revision"
printf '}\n'
