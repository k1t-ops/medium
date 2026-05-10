#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache_root="${MEDIUM_CACHE_DIR:-$HOME/.cache/medium}"

print_size() {
  local path="$1"
  if [ -e "$path" ]; then
    du -sh "$path"
  fi
}

echo "==> repository caches"
print_size "$repo_root/target"
print_size "$repo_root/.medium-local"
print_size "$repo_root/apps/android/.gradle"
print_size "$repo_root/apps/android/build"
print_size "$repo_root/apps/android/app/build"

echo
echo "==> shared Medium cache"
print_size "$cache_root"
print_size "$cache_root/target"
print_size "$cache_root/cargo"
print_size "$cache_root/sccache"
print_size "$cache_root/netlab"

if command -v sccache >/dev/null 2>&1; then
  echo
  echo "==> sccache"
  sccache --show-stats || true
fi

if command -v podman >/dev/null 2>&1; then
  echo
  echo "==> podman"
  podman system df
fi
