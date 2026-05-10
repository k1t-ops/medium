#!/usr/bin/env bash
set -euo pipefail

source /usr/local/lib/medium-netlab/lib.sh

shared_dir="${MEDIUM_NETLAB_SHARED:-/netlab/shared}"
home_dir="${MEDIUM_NETLAB_HOME:-/netlab/state/client/home}"
gateway="${MEDIUM_NETLAB_DEFAULT_GW:-}"
node_id="${MEDIUM_NETLAB_NODE_ID:-studio-smiley}"
client_name="${MEDIUM_NETLAB_CLIENT_NAME:-macbook}"
client_prefix="${MEDIUM_NETLAB_CLIENT_PREFIX:-client}"
scenarios="${MEDIUM_NETLAB_SCENARIOS:-all}"

mkdir -p "$shared_dir" "$home_dir/.ssh"
set_default_route "$gateway"

wait_file "$shared_dir/control.ready"
wait_nonempty_file "$shared_dir/join.invite"

cat >"$home_dir/.ssh/config" <<EOF
Host *
  StrictHostKeyChecking no
  UserKnownHostsFile $home_dir/.ssh/known_hosts
  LogLevel ERROR
EOF
chmod 700 "$home_dir/.ssh"
chmod 600 "$home_dir/.ssh/config"

log "joining Medium network as $client_name"
HOME="$home_dir" MEDIUM_HOME="$home_dir" MEDIUM_DEVICE_NAME="$client_name" \
medium join "$(cat "$shared_dir/join.invite")" >"$shared_dir/$client_prefix-join.log"

log "waiting for node service catalog"
for _ in $(seq 1 90); do
  if HOME="$home_dir" MEDIUM_HOME="$home_dir" medium services \
      >"$shared_dir/$client_prefix-services.log" 2>"$shared_dir/$client_prefix-services.err" \
      && grep -q "$node_id" "$shared_dir/$client_prefix-services.log" \
      && grep -q "svc_ssh ssh" "$shared_dir/$client_prefix-services.log" \
      && grep -q "hello http" "$shared_dir/$client_prefix-services.log"; then
    break
  fi
  sleep 1
done
grep -q "$node_id" "$shared_dir/$client_prefix-services.log"
grep -q "svc_ssh ssh" "$shared_dir/$client_prefix-services.log"
grep -q "hello http" "$shared_dir/$client_prefix-services.log"

run_ssh_case() {
  local name="$1"
  local expected_path_regex="$2"
  shift 2
  local stdout="$shared_dir/$client_prefix-$name.stdout"
  local stderr="$shared_dir/$client_prefix-$name.stderr"
  local status_path="$shared_dir/$client_prefix-$name.status"

  log "running $name"
  set +e
  printf 'echo medium-netlab-ok\nexit\n' | \
    HOME="$home_dir" MEDIUM_HOME="$home_dir" \
    timeout 90s medium ssh -v "$@" "$node_id" \
      >"$stdout" \
      2>"$stderr"
  local status="${PIPESTATUS[1]}"
  set -e
  echo "$status" >"$status_path"

  grep -q "medium-netlab-ok" "$stdout"
  grep -Eq "connected via $expected_path_regex" "$stderr"
  grep -q "Medium TLS connected as svc-ssh.medium" "$stderr"
  if [ "$status" -ne 0 ]; then
    echo "$name exited with $status" >&2
    exit "$status"
  fi
}

run_http_case() {
  local name="$1"
  local expected_path_regex="$2"
  shift 2
  local stdout="$shared_dir/$client_prefix-$name.stdout"
  local stderr="$shared_dir/$client_prefix-$name.stderr"
  local status_path="$shared_dir/$client_prefix-$name.status"

  log "running $name"
  set +e
  printf 'GET / HTTP/1.1\r\nHost: hello.medium\r\nConnection: close\r\n\r\n' | \
    HOME="$home_dir" MEDIUM_HOME="$home_dir" \
    timeout 90s medium proxy service --node "$node_id" --service hello -v "$@" \
      >"$stdout" \
      2>"$stderr"
  local status="${PIPESTATUS[1]}"
  set -e
  echo "$status" >"$status_path"

  grep -q "medium-http-ok" "$stdout"
  grep -Eq "connected via $expected_path_regex" "$stderr"
  grep -q "Medium TLS connected as hello.medium" "$stderr"
  if [ "$status" -ne 0 ]; then
    echo "$name exited with $status" >&2
    exit "$status"
  fi
}

case "$scenarios" in
  all)
    run_ssh_case "ssh-p2p" "ice_udp/"
    run_ssh_case "ssh-relay" "relay_tcp" --relay
    run_http_case "http-p2p" "ice_udp/"
    run_http_case "http-relay" "relay_tcp" --relay
    ;;
  p2p)
    run_ssh_case "ssh-p2p" "ice_udp/"
    run_http_case "http-p2p" "ice_udp/"
    ;;
  relay)
    run_ssh_case "ssh-relay" "relay_tcp" --relay
    run_http_case "http-relay" "relay_tcp" --relay
    ;;
  *)
    echo "unknown MEDIUM_NETLAB_SCENARIOS=$scenarios" >&2
    exit 2
    ;;
esac

touch "$shared_dir/$client_prefix.ok"
log "$client_prefix network scenario set passed"
