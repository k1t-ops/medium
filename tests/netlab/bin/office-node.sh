#!/usr/bin/env bash
set -euo pipefail

source /usr/local/lib/medium-netlab/lib.sh

shared_dir="${MEDIUM_NETLAB_SHARED:-/netlab/shared}"
state_root="${MEDIUM_NETLAB_STATE:-/netlab/state/node}"
control_ip="${MEDIUM_NETLAB_CONTROL_IP:-10.89.0.10}"
control_port="${MEDIUM_NETLAB_CONTROL_PORT:-7777}"
gateway="${MEDIUM_NETLAB_DEFAULT_GW:-}"
node_id="${MEDIUM_NETLAB_NODE_ID:-studio-smiley}"
node_public_addr="${MEDIUM_NETLAB_NODE_PUBLIC_ADDR:-10.89.1.10:17001}"
node_config="$state_root/home/.medium/node.toml"
node_services="$state_root/home/.medium/services.toml"
sshd_ca_path="$state_root/etc/medium/ssh-ca.pub"

mkdir -p "$shared_dir" "$state_root"
set_default_route "$gateway"

cleanup() {
  for pid in "${node_pid:-}" "${sshd_pid:-}" "${http_pid:-}"; do
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT TERM INT

wait_file "$shared_dir/control.ready"
wait_nonempty_file "$shared_dir/node.invite"

log "initializing node $node_id"
MEDIUM_ROOT="$state_root" \
MEDIUM_NODE_ID="$node_id" \
MEDIUM_NODE_LISTEN_ADDR="0.0.0.0:17001" \
MEDIUM_NODE_PUBLIC_ADDR="$node_public_addr" \
medium init-node "$(cat "$shared_dir/node.invite")" --reconfigure \
  >"$shared_dir/init-node.log"

log "writing SSH and HTTP service catalog"
cat >"$node_services" <<EOF
[[services]]
id = "svc_ssh"
kind = "ssh"
target = "127.0.0.1:22"
user_name = "overlay"

[[services]]
id = "hello"
kind = "http"
target = "127.0.0.1:8082"
EOF

log "configuring sshd with Medium SSH CA"
ssh-keygen -A >/dev/null
cat >/etc/ssh/sshd_config.d/99-medium-netlab.conf <<EOF
Port 22
ListenAddress 127.0.0.1
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
TrustedUserCAKeys $sshd_ca_path
LogLevel VERBOSE
EOF

/usr/sbin/sshd -D -e >"$shared_dir/sshd.log" 2>&1 &
sshd_pid=$!
wait_tcp 127.0.0.1 22

log "starting HTTP fixture"
web_root="$state_root/www"
mkdir -p "$web_root"
cat >"$web_root/index.html" <<EOF
medium-http-ok
EOF
python3 -m http.server 8082 --bind 127.0.0.1 --directory "$web_root" \
  >"$shared_dir/http-fixture.log" 2>&1 &
http_pid=$!
wait_tcp 127.0.0.1 8082

log "starting node-agent"
RUST_LOG=info \
node-agent --config "$node_config" >"$shared_dir/node-agent.log" 2>&1 &
node_pid=$!

touch "$shared_dir/node.started"
wait "$node_pid"
