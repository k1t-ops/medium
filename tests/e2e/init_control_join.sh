#!/usr/bin/env bash
set -euo pipefail

workdir="$(mktemp -d)"
server_root="$workdir/server-root"
client_home="$workdir/client-home"
bin_dir="$workdir/bin"
mkdir -p "$server_root" "$client_home" "$bin_dir"

read -r control_port home_port target_port relay_port <<EOF
$(python3 - <<'PY'
import socket

ports = []
sockets = []
for _ in range(4):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    sockets.append(sock)
print(*ports)
for sock in sockets:
    sock.close()
PY
)
EOF
control_addr="127.0.0.1:$control_port"
home_addr="127.0.0.1:$home_port"
target_addr="127.0.0.1:$target_port"
relay_addr="127.0.0.1:$relay_port"
control_config="$server_root/etc/medium/control.toml"
node_config="$server_root/etc/medium/node.toml"
control_log="$workdir/control-plane.log"
home_log="$workdir/home-node.log"
relay_log="$workdir/relay.log"
devices_log="$workdir/devices.log"
sync_log="$workdir/sync.log"
ssh_stdout="$workdir/ssh.stdout"
ssh_stderr="$workdir/ssh.stderr"
ssh_pid=""
target_log="$workdir/target.log"
target_ready="$workdir/target.ready"
control_pid=""
home_pid=""
relay_pid=""
target_pid=""

cleanup() {
  if [ -n "$target_pid" ]; then
    kill "$target_pid" 2>/dev/null || true
    wait "$target_pid" 2>/dev/null || true
  fi
  if [ -n "$ssh_pid" ]; then
    kill "$ssh_pid" 2>/dev/null || true
    wait "$ssh_pid" 2>/dev/null || true
  fi
  if [ -n "$home_pid" ]; then
    kill "$home_pid" 2>/dev/null || true
    wait "$home_pid" 2>/dev/null || true
  fi
  if [ -n "$relay_pid" ]; then
    kill "$relay_pid" 2>/dev/null || true
    wait "$relay_pid" 2>/dev/null || true
  fi
  if [ -n "$control_pid" ]; then
    kill "$control_pid" 2>/dev/null || true
    wait "$control_pid" 2>/dev/null || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

toml_value() {
  local key="$1"
  local path="$2"
  sed -n "s/^$key = \"\\(.*\\)\"$/\\1/p" "$path"
}

wait_http() {
  local url="$1"
  for _ in $(seq 1 30); do
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
  for _ in $(seq 1 30); do
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  nc -z "$host" "$port" >/dev/null 2>&1
}

init_log="$workdir/init-control.log"
MEDIUM_ROOT="$server_root" \
MEDIUM_CONTROL_BIND_ADDR="$control_addr" \
MEDIUM_CONTROL_PUBLIC_URL="https://$control_addr" \
cargo run -p medium-cli --bin medium -- init-control >"$init_log"

invite="$(sed -n 's/^initialized Medium control .* generated invite //p' "$init_log")"
node_invite="$(sed -n 's/^generated node invite //p' "$init_log")"
test -n "$invite"
test -n "$node_invite"

shared_secret="$(toml_value "shared_secret" "$control_config")"
database_url="$(toml_value "database_url" "$control_config")"
control_pin="$(toml_value "control_pin" "$control_config")"
tls_cert_path="$(toml_value "tls_cert_path" "$control_config")"
tls_key_path="$(toml_value "tls_key_path" "$control_config")"
test -n "$shared_secret"
test -n "$database_url"
test -n "$control_pin"
test -n "$tls_cert_path"
test -n "$tls_key_path"

MEDIUM_ROOT="$server_root" \
MEDIUM_NODE_LISTEN_ADDR="$home_addr" \
MEDIUM_NODE_PUBLIC_ADDR="127.0.0.1:1" \
cargo run -p medium-cli --bin medium -- init-node "$node_invite" >"$workdir/init-node.log"

# The production bootstrap owns the node config. The e2e redirects only the
# service target so it can prove the SSH path without touching the host SSHD.
sed -i.bak "s#^target = \".*\"#target = \"$target_addr\"#" "$node_config"

MEDIUM_RELAY_BIND_ADDR="$relay_addr" \
OVERLAY_SHARED_SECRET="$shared_secret" \
cargo run -p relay >"$relay_log" 2>&1 &
relay_pid=$!
wait_tcp 127.0.0.1 "$relay_port"

OVERLAY_CONTROL_BIND_ADDR="$control_addr" \
OVERLAY_CONTROL_DATABASE_URL="$database_url" \
OVERLAY_SHARED_SECRET="$shared_secret" \
MEDIUM_CONTROL_PIN="$control_pin" \
MEDIUM_CONTROL_TLS_CERT_PATH="$tls_cert_path" \
MEDIUM_CONTROL_TLS_KEY_PATH="$tls_key_path" \
MEDIUM_RELAY_ADDR="$relay_addr" \
cargo run -p control-plane >"$control_log" 2>&1 &
control_pid=$!
wait_http "https://$control_addr/health"

OVERLAY_CONTROL_URL="https://$control_addr" \
OVERLAY_SHARED_SECRET="$shared_secret" \
MEDIUM_CONTROL_PIN="$control_pin" \
MEDIUM_RELAY_ADDR="$relay_addr" \
cargo run -p home-node -- --config "$node_config" >"$home_log" 2>&1 &
home_pid=$!
wait_tcp 127.0.0.1 "$home_port"

OVERLAY_HOME="$client_home" MEDIUM_DEVICE_NAME="macbook" \
cargo run -p medium-cli --bin medium -- join "$invite" >"$workdir/join.log"

grep -q "joined macbook via https://$control_addr using invite v1" "$workdir/join.log"

OVERLAY_HOME="$client_home" cargo run -p medium-cli --bin medium -- devices >"$devices_log"
grep -q "node-1 ssh overlay@127.0.0.1:1" "$devices_log"

mkdir -p "$client_home/.ssh/config.d"
OVERLAY_HOME="$client_home" cargo run -p medium-cli --bin medium -- services >"$sync_log"
grep -q "svc_ssh ssh ssh://overlay@node-1 -> $target_addr" "$sync_log"

cat >"$bin_dir/medium" <<EOF
#!/usr/bin/env bash
cd "$(pwd)"
OVERLAY_HOME="$client_home" exec "$(pwd)/target/debug/medium" "\$@"
EOF
chmod 0755 "$bin_dir/medium"

python3 - "$target_log" "$target_addr" <<'PY' &
import socket
import sys

target_log = sys.argv[1]
ready_path = target_log.rsplit("/", 1)[0] + "/target.ready"
with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host, port = sys.argv[2].rsplit(":", 1)
    server.bind((host, int(port)))
    server.listen(1)
    with open(ready_path, "w") as ready:
        ready.write("ready\n")
    conn, _ = server.accept()
    with conn:
        with open(target_log, "wb") as out:
            out.write(b"connected\n")
        conn.sendall(b"SSH-2.0-MediumE2E\r\n")
        try:
            data = conn.recv(256)
        except ConnectionResetError:
            data = b""
        with open(target_log, "ab") as out:
            out.write(data)
PY
target_pid=$!
for _ in $(seq 1 30); do
  if [ -f "$target_ready" ]; then
    break
  fi
  sleep 1
done
test -f "$target_ready"

PATH="$bin_dir:$PATH" HOME="$client_home" ssh \
  -F "$client_home/.ssh/config" \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile="$workdir/known_hosts" \
  -o ConnectTimeout=5 \
  node-1 true >"$ssh_stdout" 2>"$ssh_stderr" &
ssh_pid=$!

wait "$target_pid"
target_pid=""
for _ in $(seq 1 10); do
  if ! kill -0 "$ssh_pid" 2>/dev/null; then
    break
  fi
  sleep 1
done
if kill -0 "$ssh_pid" 2>/dev/null; then
  kill "$ssh_pid" 2>/dev/null || true
fi
wait "$ssh_pid" 2>/dev/null || true
ssh_pid=""
grep -q "connected" "$target_log"
grep -q "SSH-2.0-" "$target_log"
