#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"
}

toml_value() {
  local key="$1"
  local path="$2"
  sed -n "s/^$key = \"\\(.*\\)\"$/\\1/p" "$path"
}

wait_file() {
  local path="$1"
  local timeout="${2:-60}"
  for _ in $(seq 1 "$timeout"); do
    if [ -f "$path" ]; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for $path" >&2
  return 1
}

wait_nonempty_file() {
  local path="$1"
  local timeout="${2:-60}"
  for _ in $(seq 1 "$timeout"); do
    if [ -s "$path" ]; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for non-empty $path" >&2
  return 1
}

wait_https() {
  local url="$1"
  local timeout="${2:-60}"
  for _ in $(seq 1 "$timeout"); do
    if curl --fail --silent --insecure "$url" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  curl --fail --silent --insecure "$url" >/dev/null
}

wait_tcp() {
  local host="$1"
  local port="$2"
  local timeout="${3:-60}"
  for _ in $(seq 1 "$timeout"); do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  nc -z "$host" "$port" >/dev/null 2>&1
}

set_default_route() {
  local gateway="${1:-}"
  if [ -n "$gateway" ]; then
    ip route replace default via "$gateway"
  fi
}
