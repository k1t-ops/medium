#!/usr/bin/env bash
set -euo pipefail

source /usr/local/lib/medium-netlab/lib.sh

lan_cidr="${1:?usage: gateway.sh <lan-cidr> <public-cidr>}"
public_cidr="${2:?usage: gateway.sh <lan-cidr> <public-cidr>}"

find_iface_for_cidr() {
  local cidr="$1"
  python3 - "$cidr" <<'PY'
import ipaddress
import subprocess
import sys

network = ipaddress.ip_network(sys.argv[1])
output = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True)
for line in output.splitlines():
    parts = line.split()
    iface = parts[1]
    addr = ipaddress.ip_interface(parts[3]).ip
    if addr in network:
        print(iface)
        sys.exit(0)
sys.exit(1)
PY
}

log "waiting for gateway interfaces lan=$lan_cidr public=$public_cidr"
for _ in $(seq 1 60); do
  lan_if="$(find_iface_for_cidr "$lan_cidr" 2>/dev/null || true)"
  public_if="$(find_iface_for_cidr "$public_cidr" 2>/dev/null || true)"
  if [ -n "$lan_if" ] && [ -n "$public_if" ] && [ "$lan_if" != "$public_if" ]; then
    break
  fi
  sleep 1
done

test -n "${lan_if:-}"
test -n "${public_if:-}"
test "$lan_if" != "$public_if"

log "configuring NAT lan_if=$lan_if public_if=$public_if"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

nft flush ruleset
nft add table ip medium_nat
nft 'add chain ip medium_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
nft add rule ip medium_nat postrouting oifname "$public_if" masquerade
nft add table ip medium_filter
nft 'add chain ip medium_filter forward { type filter hook forward priority filter; policy drop; }'
nft add rule ip medium_filter forward iifname "$lan_if" oifname "$public_if" accept
nft add rule ip medium_filter forward iifname "$public_if" oifname "$lan_if" ct state established,related accept

touch /tmp/medium-gateway-ready
log "gateway ready"
tail -f /dev/null
