#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${1:-$repo_root/dist/package}"
release_dir="${2:-$repo_root/dist}"
version="${MEDIUM_VERSION:-0.0.4}"
target="${MEDIUM_TARGET:-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)}"
cargo_target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
case "$cargo_target_dir" in
  /*) ;;
  *) cargo_target_dir="$repo_root/$cargo_target_dir" ;;
esac

cd "$repo_root"

cargo build --release -p control-plane -p home-node -p medium-cli -p relay

case "$out_dir" in
  ""|"/")
    echo "refusing to package into unsafe output path: '$out_dir'" >&2
    exit 1
    ;;
esac

rm -rf "$out_dir"

mkdir -p \
  "$out_dir/bin" \
  "$out_dir/systemd" \
  "$out_dir/docs/linux" \
  "$out_dir/homebrew"

install -m 0755 "$cargo_target_dir/release/medium" "$out_dir/bin/medium"
install -m 0755 "$cargo_target_dir/release/control-plane" "$out_dir/bin/control-plane"
install -m 0755 "$cargo_target_dir/release/home-node" "$out_dir/bin/node-agent"
install -m 0755 "$cargo_target_dir/release/relay" "$out_dir/bin/relay"

install -m 0644 packaging/systemd/medium-control-plane.service \
  "$out_dir/systemd/medium-control-plane.service"
install -m 0644 packaging/systemd/medium-node-agent.service \
  "$out_dir/systemd/medium-node-agent.service"
install -m 0644 packaging/systemd/medium-relay.service \
  "$out_dir/systemd/medium-relay.service"

install -m 0644 packaging/linux/README.md "$out_dir/docs/linux/README.md"
install -m 0644 packaging/linux/install-layout.txt \
  "$out_dir/docs/linux/install-layout.txt"
install -m 0644 packaging/homebrew/medium.rb "$out_dir/homebrew/medium.rb"

mkdir -p "$release_dir"
tar -C "$out_dir" -czf "$release_dir/medium-$version-$target.tar.gz" bin systemd docs homebrew
