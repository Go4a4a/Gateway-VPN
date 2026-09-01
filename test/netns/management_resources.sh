#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
TEST_BINARY=${1:-/tmp/gateway-vpn-gatewayfabric-test}
[[ $EUID -eq 0 ]] || { echo "management_resources.sh requires root" >&2; exit 1; }
[[ -x $TEST_BINARY ]] || { echo "Gateway Fabric test binary is required" >&2; exit 2; }
for command in ip python3 seq; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

SUFFIX=$$
GW="gvpn-res-gw-$SUFFIX"
KEENETIC="gvpn-res-kn-$SUFFIX"
WGROUTER="gvpn-res-wg-$SUFFIX"
DEDICATED="gvpn-res-ded-$SUFFIX"
SERVER_PIDS=()
cleanup() {
  for pid in "${SERVER_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  ip netns del "$DEDICATED" 2>/dev/null || true
  ip netns del "$WGROUTER" 2>/dev/null || true
  ip netns del "$KEENETIC" 2>/dev/null || true
  ip netns del "$GW" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for namespace in "$GW" "$KEENETIC" "$WGROUTER" "$DEDICATED"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done

ip link add gvkn0 type veth peer name gvkn1
ip link set gvkn0 netns "$GW"
ip link set gvkn1 netns "$KEENETIC"
ip -n "$GW" link set gvkn0 name lan0
ip -n "$KEENETIC" link set gvkn1 name eth0
ip -n "$GW" address add 192.168.200.1/24 dev lan0
ip -n "$GW" link set lan0 up
ip -n "$GW" address add 192.168.201.1/32 dev lo
ip -n "$KEENETIC" address add 192.168.200.254/24 dev eth0
ip -n "$KEENETIC" link set eth0 up
ip -n "$KEENETIC" address add 192.168.50.10/32 dev lo
ip -n "$GW" route add 192.168.50.0/24 via 192.168.200.254 dev lan0

ip link add gvw0 type veth peer name gvw1
ip link set gvw0 netns "$GW"
ip link set gvw1 netns "$WGROUTER"
ip -n "$GW" link set gvw0 name wg-ingress
ip -n "$WGROUTER" link set gvw1 name eth0
ip -n "$GW" address add 10.90.0.1/24 dev wg-ingress
ip -n "$GW" link set wg-ingress up
ip -n "$WGROUTER" address add 10.90.0.2/24 dev eth0
ip -n "$WGROUTER" address add 192.168.51.10/32 dev eth0
ip -n "$WGROUTER" link set eth0 up
ip -n "$GW" route add 192.168.51.0/24 dev wg-ingress protocol 186

ip link add gvd0 type veth peer name gvd1
ip link set gvd0 netns "$GW"
ip link set gvd1 netns "$DEDICATED"
ip -n "$GW" link set gvd0 name mgmt0
ip -n "$DEDICATED" link set gvd1 name eth0
ip -n "$GW" address add 192.168.60.1/24 dev mgmt0
ip -n "$GW" link set mgmt0 up
ip -n "$DEDICATED" address add 192.168.60.10/24 dev eth0
ip -n "$DEDICATED" link set eth0 up

start_server() {
  local namespace=$1
  local address=$2
  ip netns exec "$namespace" python3 -c 'import socket,sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],18443))
s.listen(16)
while True:
    c,_=s.accept()
    c.close()' "$address" >/dev/null 2>&1 &
  SERVER_PIDS+=("$!")
}
start_server "$GW" 192.168.201.1
start_server "$KEENETIC" 0.0.0.0
start_server "$WGROUTER" 192.168.51.10
start_server "$DEDICATED" 192.168.60.10

for _ in $(seq 1 100); do
  if ip netns exec "$GW" python3 -c 'import socket
for host in ("192.168.201.1","192.168.200.254","192.168.50.10","192.168.51.10","192.168.60.10"):
    socket.create_connection((host,18443),0.2).close()' >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
ip netns exec "$GW" python3 -c 'import socket
for host in ("192.168.201.1","192.168.200.254","192.168.50.10","192.168.51.10","192.168.60.10"):
    socket.create_connection((host,18443),1).close()'

ip netns exec "$GW" env GATEWAY_VPN_RESOURCE_PROBE_INTEGRATION=1 "$TEST_BINARY" \
  -test.v -test.count=1 -test.run '^TestResourceProbeAgainstKernelRoutes$'

echo "PASS: all five management resource profiles require their exact kernel path and transport"
