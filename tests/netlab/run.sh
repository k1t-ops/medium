#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="localhost/medium-netlab:dev"
prefix="medium-netlab"
public_net="$prefix-public"
office_net="$prefix-office"
client_net="$prefix-client"
host_arch="$(uname -m)"
case "$host_arch" in
  arm64 | aarch64)
    default_platform="linux/arm64"
    ;;
  x86_64 | amd64)
    default_platform="linux/amd64"
    ;;
  *)
    echo "unsupported host architecture for netlab: $host_arch" >&2
    exit 2
    ;;
esac
netlab_platform="${MEDIUM_NETLAB_PLATFORM:-$default_platform}"
run_root="$repo_root/.medium-local/netlab"
shared_dir="$run_root/shared"
public_cidr="10.250.10.0/24"
office_cidr="10.250.11.0/24"
client_cidr="10.250.12.0/24"
control_ip="10.250.10.10"
office_gw_public_ip="10.250.10.20"
client_gw_public_ip="10.250.10.30"
office_gw_lan_ip="10.250.11.2"
client_gw_lan_ip="10.250.12.2"
office_node_ip="10.250.11.10"
p2p_client_ip="10.250.11.20"
relay_client_ip="10.250.12.10"

containers=(
  "$prefix-control-relay"
  "$prefix-office-gw"
  "$prefix-client-gw"
  "$prefix-office-node"
  "$prefix-p2p-client"
  "$prefix-relay-client"
)

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    echo "medium netlab failed; logs and shared state are in $run_root" >&2
    for container in "${containers[@]}"; do
      if podman container exists "$container" 2>/dev/null; then
        echo "===== podman logs $container =====" >&2
        podman logs "$container" >&2 || true
      fi
    done
    if [ -d "$shared_dir" ]; then
      for path in "$shared_dir"/*.log "$shared_dir"/*.stdout "$shared_dir"/*.stderr "$shared_dir"/*.err; do
        if [ -f "$path" ]; then
          echo "===== $path =====" >&2
          cat "$path" >&2
        fi
      done
    fi
  fi
  for container in "${containers[@]}"; do
    podman rm -f "$container" >/dev/null 2>&1 || true
  done
  for network in "$client_net" "$office_net" "$public_net"; do
    podman network rm "$network" >/dev/null 2>&1 || true
  done
  exit "$status"
}
trap cleanup EXIT

require_no_args() {
  if [ "$#" -ne 0 ]; then
    echo "usage: tests/netlab/run.sh" >&2
    exit 2
  fi
}

wait_container_ready_file() {
  local container="$1"
  local path="$2"
  local timeout="${3:-60}"
  for _ in $(seq 1 "$timeout"); do
    if podman exec "$container" test -f "$path" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  podman exec "$container" test -f "$path"
}

require_no_args "$@"
cd "$repo_root"

command -v podman >/dev/null

mkdir -p "$shared_dir"
rm -rf "$run_root"
mkdir -p "$shared_dir"

echo "==> build netlab image"
podman build \
  --platform "$netlab_platform" \
  --ignorefile tests/netlab/containerignore \
  -f tests/netlab/Containerfile \
  -t "$image" \
  .

for container in "${containers[@]}"; do
  podman rm -f "$container" >/dev/null 2>&1 || true
done
for network in "$client_net" "$office_net" "$public_net"; do
  podman network rm "$network" >/dev/null 2>&1 || true
done

echo "==> create isolated networks"
podman network create --subnet "$public_cidr" "$public_net" >/dev/null
podman network create --subnet "$office_cidr" "$office_net" >/dev/null
podman network create --subnet "$client_cidr" "$client_net" >/dev/null

echo "==> start NAT gateways"
podman run -d \
  --name "$prefix-office-gw" \
  --privileged \
  --platform "$netlab_platform" \
  --network "$public_net:ip=$office_gw_public_ip" \
  "$image" \
  /usr/local/lib/medium-netlab/gateway.sh "$office_cidr" "$public_cidr" >/dev/null
podman network connect --ip "$office_gw_lan_ip" "$office_net" "$prefix-office-gw"

podman run -d \
  --name "$prefix-client-gw" \
  --privileged \
  --platform "$netlab_platform" \
  --network "$public_net:ip=$client_gw_public_ip" \
  "$image" \
  /usr/local/lib/medium-netlab/gateway.sh "$client_cidr" "$public_cidr" >/dev/null
podman network connect --ip "$client_gw_lan_ip" "$client_net" "$prefix-client-gw"

wait_container_ready_file "$prefix-office-gw" /tmp/medium-gateway-ready
wait_container_ready_file "$prefix-client-gw" /tmp/medium-gateway-ready

echo "==> start control-plane and relay"
podman run -d \
  --name "$prefix-control-relay" \
  --platform "$netlab_platform" \
  --network "$public_net:ip=$control_ip" \
  -e MEDIUM_NETLAB_CONTROL_IP="$control_ip" \
  -v "$shared_dir:/netlab/shared:rw" \
  "$image" \
  /usr/local/lib/medium-netlab/control-relay.sh >/dev/null
wait_container_ready_file "$prefix-control-relay" /netlab/shared/control.ready 120

echo "==> start office node behind NAT"
podman run -d \
  --name "$prefix-office-node" \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --platform "$netlab_platform" \
  --network "$office_net:ip=$office_node_ip" \
  -e MEDIUM_NETLAB_CONTROL_IP="$control_ip" \
  -e MEDIUM_NETLAB_DEFAULT_GW="$office_gw_lan_ip" \
  -e MEDIUM_NETLAB_NODE_PUBLIC_ADDR="$office_node_ip:17001" \
  -v "$shared_dir:/netlab/shared:rw" \
  "$image" \
  /usr/local/lib/medium-netlab/office-node.sh >/dev/null

echo "==> start p2p client on office LAN"
podman run -d \
  --name "$prefix-p2p-client" \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --platform "$netlab_platform" \
  --network "$office_net:ip=$p2p_client_ip" \
  -e MEDIUM_NETLAB_DEFAULT_GW="$office_gw_lan_ip" \
  -e MEDIUM_NETLAB_CLIENT_NAME="p2p-macbook" \
  -e MEDIUM_NETLAB_CLIENT_PREFIX="p2p-client" \
  -e MEDIUM_NETLAB_SCENARIOS="p2p" \
  -v "$shared_dir:/netlab/shared:rw" \
  "$image" \
  /usr/local/lib/medium-netlab/client.sh >/dev/null

echo "==> start relay client behind separate NAT"
podman run -d \
  --name "$prefix-relay-client" \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --platform "$netlab_platform" \
  --network "$client_net:ip=$relay_client_ip" \
  -e MEDIUM_NETLAB_DEFAULT_GW="$client_gw_lan_ip" \
  -e MEDIUM_NETLAB_CLIENT_NAME="relay-macbook" \
  -e MEDIUM_NETLAB_CLIENT_PREFIX="relay-client" \
  -e MEDIUM_NETLAB_SCENARIOS="relay" \
  -v "$shared_dir:/netlab/shared:rw" \
  "$image" \
  /usr/local/lib/medium-netlab/client.sh >/dev/null

for client_container in "$prefix-p2p-client" "$prefix-relay-client"; do
  client_status="$(podman wait "$client_container")"
  if [ "$client_status" != "0" ]; then
    echo "$client_container failed with exit status $client_status" >&2
    exit "$client_status"
  fi
done

for ok_file in "$shared_dir/p2p-client.ok" "$shared_dir/relay-client.ok"; do
  test -f "$ok_file"
done

echo "medium netlab network scenario matrix passed"
