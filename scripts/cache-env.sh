#!/usr/bin/env bash
# Source this file before local cargo work to keep heavy build artifacts out of
# the repository and reuse the same cache across Medium helper scripts.

export MEDIUM_CACHE_DIR="${MEDIUM_CACHE_DIR:-$HOME/.cache/medium}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$MEDIUM_CACHE_DIR/target/native}"

if command -v sccache >/dev/null 2>&1; then
  export SCCACHE_DIR="${SCCACHE_DIR:-$MEDIUM_CACHE_DIR/sccache}"
  export RUSTC_WRAPPER="${RUSTC_WRAPPER:-sccache}"
fi
