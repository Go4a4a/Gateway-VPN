#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BINARY=${1:-$ROOT/dist/gateway-vpn-netns}
NETWORKAPPLY_TEST=${2:-$ROOT/dist/gateway-vpn-networkapply-test}
[[ $EUID -eq 0 ]] || { echo "topology_profiles.sh requires root" >&2; exit 1; }
[[ -x $BINARY && -x $NETWORKAPPLY_TEST ]] || { echo "Gateway and networkapply test binaries are required" >&2; exit 2; }
for command in ip nft sed grep mktemp getent useradd userdel ping seq; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

# First prove the durable transaction contract: the old management address and
# member policies survive Apply, Commit retires them, rollback restores LKG,
# partial rollback remains PATH_BLOCKED, and malformed snapshots mutate nothing.
"$NETWORKAPPLY_TEST" -test.v -test.count=1 -test.run \
  '^(TestUbuntuBackendTopologyApplyCommitIsRecoverableAndRollbackRestoresLKG|TestUbuntuBackendTopologyRollbackRetainsBlockedFirewallAfterPartialFailure|TestUbuntuBackendRejectsTamperedTopologySnapshotMembers|TestRecoverRollsBackUnconfirmedApplyEvenBeforeDeadline)$'

SUFFIX=$$
GW="gvpn-topology-$SUFFIX"
PEER="gvpn-peer-$SUFFIX"
UPSTREAM="gvpn-upstream-$SUFFIX"
WORK=$(mktemp -d)
CREATED_USERS=()
cleanup() {
  ip netns del "$PEER" 2>/dev/null || true
  ip netns del "$UPSTREAM" 2>/dev/null || true
  ip netns del "$GW" 2>/dev/null || true
  for user in "${CREATED_USERS[@]}"; do
    userdel "$user" 2>/dev/null || true
  done
  rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

for user in gateway-vpn gateway-vpn-mihomo; do
  if ! getent passwd "$user" >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
    CREATED_USERS+=("$user")
  fi
done

ip netns add "$GW"
ip netns add "$PEER"
ip netns add "$UPSTREAM"
ip link add peer0 type veth peer name wg-ingress
ip link set peer0 netns "$PEER"
ip link set wg-ingress netns "$GW"
ip link add upstream0 type veth peer name wan0
ip link set upstream0 netns "$UPSTREAM"
ip link set wan0 netns "$GW"

for namespace in "$GW" "$PEER" "$UPSTREAM"; do
  ip -n "$namespace" link set lo up
done
ip -n "$GW" link set wg-ingress up
ip -n "$GW" address add 10.90.0.1/24 dev wg-ingress
ip -n "$GW" link set wan0 up
ip -n "$GW" address add 192.168.8.2/24 dev wan0
ip netns exec "$GW" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$GW" sysctl -q -w net.ipv4.conf.all.src_valid_mark=1
ip -n "$GW" route add default via 192.168.8.1 dev wan0 table 1101 protocol 186
ip -n "$GW" rule add priority 1101 fwmark 0x1101/0xffffffff table 1101 protocol 186

ip -n "$PEER" link set peer0 up
ip -n "$PEER" address add 10.90.0.2/24 dev peer0
ip -n "$PEER" route add default via 10.90.0.1
ip -n "$UPSTREAM" link set upstream0 up
ip -n "$UPSTREAM" address add 192.168.8.1/24 dev upstream0

sed -e 's/lan_interface: enp2s0/lan_interface: wg-ingress/' \
    -e 's/lan_address: 192.168.200.1\/24/lan_address: 10.90.0.1\/24/' \
    -e 's/management_interfaces: \[\]/management_interfaces: [wg-ingress]/' \
    -e 's/lan_service_mode: dhcp_dns/lan_service_mode: disabled/' \
    -e 's/192\.168\.200\.1/10.90.0.1/g' \
    "$ROOT/config.example.yaml" >"$WORK/config.yaml"

ip netns exec "$GW" "$BINARY" firewall-boot --config "$WORK/config.yaml" --apply
rules=$(ip netns exec "$GW" nft list chain inet gateway_vpn forward)
grep -F 'iifname "wg-ingress" ip saddr @wireguard_ingress_allowed_v4 oifname . meta mark @active_direct_context' <<<"$rules" >/dev/null
if grep -F 'iifname "wg-ingress" oifname . meta mark @active_direct_context' <<<"$rules" >/dev/null; then
  echo "ONE_ARM firewall contains unrestricted WireGuard transit" >&2
  exit 1
fi

ip netns exec "$GW" nft --file "$ROOT/test/fixtures/nftables/path-direct-modem-a.nft"
if ip netns exec "$PEER" ping -c 1 -W 1 192.168.8.1 >/dev/null 2>&1; then
  echo "Unqualified ONE_ARM source escaped before peer authorization" >&2
  exit 1
fi
ip netns exec "$GW" nft add element inet gateway_vpn wireguard_ingress_allowed_v4 '{ 10.90.0.2 }'
ip netns exec "$PEER" ping -c 1 -W 2 192.168.8.1 >/dev/null

ip -n "$PEER" address add 10.90.0.3/24 dev peer0
if ip netns exec "$PEER" ping -I 10.90.0.3 -c 1 -W 1 192.168.8.1 >/dev/null 2>&1; then
  echo "Spoofed ONE_ARM source escaped the exact peer allowlist" >&2
  exit 1
fi

mark_count=$(ip netns exec "$GW" nft --json list map inet gateway_vpn active_direct_marks | grep -o '"wg-ingress"' | wc -l)
[[ $mark_count == 1 ]] || { echo "wg-ingress direct mark element count is $mark_count, expected 1" >&2; exit 1; }

echo "PASS: topology rollback contract and peer-scoped ONE_ARM kernel firewall are fail-closed"
