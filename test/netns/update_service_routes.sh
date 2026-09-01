#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
DATAPLANE_TEST=${1:-$ROOT/dist/gateway-vpn-dataplane-test}
UPDATENET_TEST=${2:-$ROOT/dist/gateway-vpn-updatenet-test}
[[ $EUID -eq 0 ]] || { echo "update_service_routes.sh requires root" >&2; exit 1; }
[[ -x $DATAPLANE_TEST ]] || { echo "Build the Linux dataplane test binary" >&2; exit 2; }
[[ -x $UPDATENET_TEST ]] || { echo "Build the Linux updatenet test binary" >&2; exit 2; }
for command in ip nft python3 getent useradd userdel runuser setcap grep; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

SUFFIX=$$
GW="gvpn-update-gw-$SUFFIX"
HILINK="gvpn-update-hi-$SUFFIX"
ETHERNET="gvpn-update-eth-$SUFFIX"
SERVER_PIDS=()
CREATED_USERS=()
cleanup() {
  for pid in "${SERVER_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  ip netns del "$ETHERNET" 2>/dev/null || true
  ip netns del "$HILINK" 2>/dev/null || true
  ip netns del "$GW" 2>/dev/null || true
  for user in "${CREATED_USERS[@]}"; do
    userdel "$user" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

for user in gateway-vpn gateway-vpn-mihomo; do
  if ! getent passwd "$user" >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
    CREATED_USERS+=("$user")
  fi
done

ip netns add "$GW"
ip netns add "$HILINK"
ip netns add "$ETHERNET"
ip link add wan0 type veth peer name hilink0
ip link set wan0 netns "$GW"
ip link set hilink0 netns "$HILINK"
ip link add wan1 type veth peer name ethernet0
ip link set wan1 netns "$GW"
ip link set ethernet0 netns "$ETHERNET"

ip -n "$GW" link set lo up
ip -n "$GW" address add 192.168.8.2/24 dev wan0
ip -n "$GW" address add 172.20.1.2/24 dev wan1
ip -n "$GW" link set wan0 up
ip -n "$GW" link set wan1 up

ip -n "$HILINK" link set lo up
ip -n "$HILINK" address add 192.168.8.1/24 dev hilink0
ip -n "$HILINK" address add 8.8.8.8/32 dev lo
ip -n "$HILINK" link set hilink0 up

ip -n "$ETHERNET" link set lo up
ip -n "$ETHERNET" address add 172.20.1.1/24 dev ethernet0
ip -n "$ETHERNET" address add 9.9.9.9/32 dev lo
ip -n "$ETHERNET" address add 1.0.0.1/32 dev lo
ip -n "$ETHERNET" link set ethernet0 up

start_server() {
  local namespace=$1
  local address=$2
  ip netns exec "$namespace" python3 -c 'import socket,sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],443))
s.listen(1)
c,_=s.accept()
c.recv(32)
c.sendall(b"ok")
c.close()
s.close()' "$address" &
  SERVER_PIDS+=("$!")
}

start_server "$HILINK" 8.8.8.8
start_server "$ETHERNET" 9.9.9.9
start_server "$ETHERNET" 1.0.0.1
for attempt in $(seq 1 100); do
  if ip netns exec "$HILINK" ss -H -ltn 'sport = :443' | grep -F '8.8.8.8:443' >/dev/null \
    && ip netns exec "$ETHERNET" ss -H -ltn 'sport = :443' | grep -F '9.9.9.9:443' >/dev/null \
    && ip netns exec "$ETHERNET" ss -H -ltn 'sport = :443' | grep -F '1.0.0.1:443' >/dev/null; then
    break
  fi
  sleep 0.05
done
ip netns exec "$HILINK" ss -H -ltn 'sport = :443' | grep -F '8.8.8.8:443' >/dev/null || { echo "HiLink test listener did not start" >&2; exit 1; }
ip netns exec "$ETHERNET" ss -H -ltn 'sport = :443' | grep -F '9.9.9.9:443' >/dev/null || { echo "Ethernet test listener did not start" >&2; exit 1; }
ip netns exec "$ETHERNET" ss -H -ltn 'sport = :443' | grep -F '1.0.0.1:443' >/dev/null || { echo "Unauthorized-destination listener did not start" >&2; exit 1; }

ip netns exec "$GW" sysctl -q -w net.ipv4.conf.all.src_valid_mark=1
ip netns exec "$GW" env GATEWAY_VPN_UPDATE_SERVICE_INTEGRATION=1 "$DATAPLANE_TEST" \
  -test.run '^TestUpdateServiceRoutesAgainstKernelNFTablesAndPolicyRouting$' -test.count=1

ip netns exec "$GW" ip route get 8.8.8.8 mark 0x1101 | grep -F 'dev wan0' >/dev/null
ip netns exec "$GW" ip route get 9.9.9.9 mark 0x1102 | grep -F 'dev wan1' >/dev/null
if ip netns exec "$GW" ip route get 9.9.9.9 >/dev/null 2>&1; then
  echo "Signed-update gate created an unmarked default route" >&2
  exit 1
fi

setcap cap_net_raw=ep "$UPDATENET_TEST"
run_probe() {
  local user=$1
  local interface_name=$2
  local mark=$3
  local target=$4
  local expect_failure=${5:-0}
  local prefix=()
  if [[ $user != root ]]; then
    prefix=(runuser -u "$user" --)
  fi
  if ip netns exec "$GW" "${prefix[@]}" env \
    GATEWAY_VPN_UPDATE_BOUND_DIAL_INTEGRATION=1 \
    GATEWAY_VPN_UPDATE_INTERFACE="$interface_name" \
    GATEWAY_VPN_UPDATE_MARK="$mark" \
    GATEWAY_VPN_UPDATE_TARGET="$target" \
    GATEWAY_VPN_UPDATE_EXPECT_FAILURE="$expect_failure" \
    "$UPDATENET_TEST" -test.run '^TestBoundDialerAgainstKernelUpdateServiceFirewall$' -test.count=1; then
    return 0
  fi
  echo "Update-service probe failed: user=$user interface=$interface_name mark=$mark target=$target expected_failure=$expect_failure" >&2
  ip netns exec "$GW" id "$user" >&2 || true
  getcap "$UPDATENET_TEST" >&2 || true
  ip netns exec "$GW" ip -4 rule show >&2 || true
  ip netns exec "$GW" ip -4 route show table 1101 >&2 || true
  ip netns exec "$GW" ip -4 route show table 1102 >&2 || true
  ip netns exec "$GW" nft list set inet gateway_vpn bootstrap_http_v4 >&2 || true
  ip netns exec "$GW" nft list set inet gateway_vpn hilink_interfaces >&2 || true
  ip netns exec "$GW" nft list chain inet gateway_vpn output >&2 || true
	for key in all default wan0 wan1; do
		ip netns exec "$GW" sysctl "net.ipv4.conf.$key.rp_filter" >&2 || true
	done
	ip -n "$GW" -s link show dev "$interface_name" >&2 || true
	ip -n "$HILINK" -s link show dev hilink0 >&2 || true
	ip -n "$ETHERNET" -s link show dev ethernet0 >&2 || true
  ip netns exec "$HILINK" ss -H -ltn >&2 || true
  ip netns exec "$ETHERNET" ss -H -ltn >&2 || true
  return 1
}

# The nft rule is scoped to the unprivileged Gateway service UID.
run_probe root wan1 0x1102 9.9.9.9:443 1
run_probe gateway-vpn wan0 0x1101 8.8.8.8:443
run_probe gateway-vpn wan1 0x1102 9.9.9.9:443
# Same UID/interface/mark, but no transient authorization for this destination.
run_probe gateway-vpn wan1 0x1102 1.0.0.1:443 1

echo "PASS: signed-update service packets used exact UID/interface/mark/IP/443 contexts for HiLink and Ethernet"
