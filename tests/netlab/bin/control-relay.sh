#!/usr/bin/env bash
set -euo pipefail

source /usr/local/lib/medium-netlab/lib.sh

shared_dir="${MEDIUM_NETLAB_SHARED:-/netlab/shared}"
state_root="${MEDIUM_NETLAB_STATE:-/netlab/state/control}"
control_ip="${MEDIUM_NETLAB_CONTROL_IP:-10.89.0.10}"
control_port="${MEDIUM_NETLAB_CONTROL_PORT:-7777}"
relay_port="${MEDIUM_NETLAB_RELAY_PORT:-7001}"
control_config="$state_root/etc/medium/control.toml"

mkdir -p "$shared_dir" "$state_root"

cleanup() {
  for pid in "${control_pid:-}" "${relay_pid:-}"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT TERM INT

log "initializing control-plane config"
if [ ! -f "$control_config" ]; then
  MEDIUM_ROOT="$state_root" \
  MEDIUM_CONTROL_BIND_ADDR="0.0.0.0:$control_port" \
  MEDIUM_CONTROL_PUBLIC_URL="https://$control_ip:$control_port" \
  MEDIUM_RELAY_BIND_ADDR="0.0.0.0:$relay_port" \
  MEDIUM_RELAY_PUBLIC_ADDR="$control_ip:$relay_port" \
  medium init-control >"$shared_dir/init-control.log"
fi

sed -n 's/^initialized Medium control .* generated invite //p' \
  "$shared_dir/init-control.log" >"$shared_dir/join.invite"
sed -n 's/^generated node invite //p' \
  "$shared_dir/init-control.log" >"$shared_dir/node.invite"
test -s "$shared_dir/join.invite"
test -s "$shared_dir/node.invite"

shared_secret="$(toml_value shared_secret "$control_config")"
client_secret="$(toml_value client_secret "$control_config")"
database_url="$(toml_value database_url "$control_config")"
control_pin="$(toml_value control_pin "$control_config")"
tls_cert_path="$(toml_value tls_cert_path "$control_config")"
tls_key_path="$(toml_value tls_key_path "$control_config")"
service_ca_cert_path="$(toml_value service_ca_cert_path "$control_config")"
service_ca_key_path="$(toml_value service_ca_key_path "$control_config")"
ssh_ca_key_path="$(toml_value ssh_ca_key_path "$control_config")"

log "starting TCP relay"
MEDIUM_RELAY_BIND_ADDR="0.0.0.0:$relay_port" \
MEDIUM_RELAY_SHARED_SECRET="$shared_secret" \
relay >"$shared_dir/relay.log" 2>&1 &
relay_pid=$!
wait_tcp 127.0.0.1 "$relay_port"

log "starting pinned TLS control-plane"
OVERLAY_CONTROL_BIND_ADDR="0.0.0.0:$control_port" \
OVERLAY_CONTROL_DATABASE_URL="$database_url" \
OVERLAY_SHARED_SECRET="$shared_secret" \
MEDIUM_CLIENT_SECRET="$client_secret" \
MEDIUM_CONTROL_PIN="$control_pin" \
MEDIUM_CONTROL_TLS_CERT_PATH="$tls_cert_path" \
MEDIUM_CONTROL_TLS_KEY_PATH="$tls_key_path" \
MEDIUM_SERVICE_CA_CERT_PATH="$service_ca_cert_path" \
MEDIUM_SERVICE_CA_KEY_PATH="$service_ca_key_path" \
MEDIUM_SSH_CA_KEY_PATH="$ssh_ca_key_path" \
MEDIUM_RELAY_ADDR="$control_ip:$relay_port" \
control-plane >"$shared_dir/control-plane.log" 2>&1 &
control_pid=$!
wait_https "https://127.0.0.1:$control_port/health"

touch "$shared_dir/control.ready"
log "control-relay ready"
wait -n "$control_pid" "$relay_pid"
