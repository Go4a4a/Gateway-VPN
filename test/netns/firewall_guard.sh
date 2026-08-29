#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BINARY=${1:-$ROOT/dist/gateway-vpn-netns}
DATAPLANE_TEST=${2:-$ROOT/dist/gateway-vpn-dataplane-test}
[[ $EUID -eq 0 ]] || { echo "firewall_guard.sh requires root" >&2; exit 1; }
[[ -x $BINARY ]] || { echo "Build a Linux gateway-vpn binary and pass its absolute path" >&2; exit 2; }
[[ -x $DATAPLANE_TEST ]] || { echo "Build the Linux dataplane test binary and pass its absolute path" >&2; exit 2; }
for command in ip nft sed grep mktemp getent useradd userdel ping; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

SUFFIX=$$
GW="gvpn-gw-$SUFFIX"
CLIENT="gvpn-client-$SUFFIX"
MODEM="gvpn-modem-$SUFFIX"
WORK=$(mktemp -d)
GUARD_PID=
CREATED_USERS=()
cleanup() {
  if [[ -n ${GUARD_PID:-} ]]; then
    kill "$GUARD_PID" 2>/dev/null || true
    wait "$GUARD_PID" 2>/dev/null || true
  fi
  ip netns del "$CLIENT" 2>/dev/null || true
  ip netns del "$MODEM" 2>/dev/null || true
  ip netns del "$GW" 2>/dev/null || true
	for user in "${CREATED_USERS[@]}"; do
		userdel "$user" 2>/dev/null || true
	done
  rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

# nft resolves symbolic skuid values while loading the ruleset. The real
# installer creates these two fixed service accounts before firewall-boot;
# the standalone netns gate reproduces that prerequisite and removes only
# accounts it created itself.
for user in gateway-vpn gateway-vpn-mihomo; do
	if ! getent passwd "$user" >/dev/null; then
		useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
		CREATED_USERS+=("$user")
	fi
done

ip netns add "$GW"
ip netns add "$CLIENT"
ip netns add "$MODEM"

ip link add client0 type veth peer name lan0
ip link set client0 netns "$CLIENT"
ip link set lan0 netns "$GW"
ip link add wan0 type veth peer name modem0
ip link set wan0 netns "$GW"
ip link set modem0 netns "$MODEM"

ip -n "$CLIENT" link set lo up
ip -n "$CLIENT" address add 192.168.200.2/24 dev client0
ip -n "$CLIENT" link set client0 up
ip -n "$CLIENT" route add default via 192.168.200.1

ip -n "$GW" link set lo up
ip -n "$GW" address add 192.168.200.1/24 dev lan0
ip -n "$GW" link set lan0 up
ip -n "$GW" address add 192.168.8.2/24 dev wan0
ip -n "$GW" link set wan0 up
ip -n "$GW" link add gateway-vpn-tun type dummy
ip -n "$GW" link set gateway-vpn-tun up
ip netns exec "$GW" sysctl -q -w net.ipv4.ip_forward=1
ip -n "$GW" route add default via 192.168.8.1 dev wan0 table 1101 protocol 186
ip -n "$GW" rule add priority 1101 fwmark 0x1101/0xffffffff table 1101 protocol 186

ip -n "$MODEM" link set lo up
ip -n "$MODEM" address add 192.168.8.1/24 dev modem0
ip -n "$MODEM" link set modem0 up

sed 's/lan_interface: enp2s0/lan_interface: lan0/' "$ROOT/config.example.yaml" >"$WORK/config.yaml"

# Production routing invariant: marked service traffic has a modem table,
# while an unmarked forwarded LAN packet has no global/default route.
ip netns exec "$GW" ip route get 1.1.1.1 mark 0x1101 | grep 'dev wan0' >/dev/null
if ip netns exec "$GW" ip route get 1.1.1.1 >/dev/null 2>&1; then
  echo "Unmarked direct route exists before firewall test" >&2
  exit 1
fi

# Exercise the production renderer, atomic transactions and nft JSON decoder
# against the Ubuntu kernel/userspace combination used by CI.
ip netns exec "$GW" env GATEWAY_VPN_NFT_PATH_INTEGRATION=1 "$DATAPLANE_TEST" \
  -test.run '^TestFirewallBackendAgainstKernelNFTables$' -test.count=1

ip netns exec "$GW" "$BINARY" firewall-boot --config "$WORK/config.yaml" --apply
ip netns exec "$GW" nft list table inet gateway_vpn | grep 'policy drop' >/dev/null

# PATH_BLOCKED must prevent LAN traffic even to the modem's connected subnet.
if ip netns exec "$CLIENT" ping -c 1 -W 1 192.168.8.1 >/dev/null 2>&1; then
  echo "PATH_BLOCKED leaked LAN traffic to the modem" >&2
  exit 1
fi

# Open exactly wan0+fwmark 0x1101. The selected direct path must pass, then a
# TUN activation must atomically remove every direct gate again.
sed 's/"enp2s0"/"lan0"/' "$ROOT/test/fixtures/nftables/path-direct-modem-a.nft" >"$WORK/path-direct.nft"
ip netns exec "$GW" nft --check --file "$WORK/path-direct.nft"
ip netns exec "$GW" nft --file "$WORK/path-direct.nft"
ip netns exec "$CLIENT" ping -c 1 -W 2 192.168.8.1 >/dev/null
ip netns exec "$GW" nft --file "$ROOT/test/fixtures/nftables/path-active-modem-a.nft"
if ip netns exec "$CLIENT" ping -c 1 -W 1 192.168.8.1 >/dev/null 2>&1; then
  echo "TUN activation left the previous direct path open" >&2
  exit 1
fi

# Leave the guard test itself at the boot-safe baseline.
ip netns exec "$GW" "$BINARY" firewall-boot --config "$WORK/config.yaml" --apply

ip netns exec "$GW" "$BINARY" firewall-guard --config "$WORK/config.yaml" --marker-path "$WORK/quarantine" --apply >"$WORK/guard.log" 2>&1 &
GUARD_PID=$!

wait_recovery() {
  local expected_count=$1
  local attempt
  for attempt in $(seq 1 100); do
    if ip netns exec "$GW" nft list table inet gateway_vpn >/dev/null 2>&1 \
      && ip netns exec "$GW" nft --json list set inet gateway_vpn firewall_schema_generation | grep -E '"elem"[[:space:]]*:[[:space:]]*\[[[:space:]]*4[[:space:]]*\]' >/dev/null \
      && ip -n "$GW" -json link show dev lan0 | grep '"UP"' >/dev/null \
      && [[ $(grep -c 'recovered=true' "$WORK/guard.log" || true) -ge $expected_count ]]; then
      return 0
    fi
    sleep 0.05
  done
  echo "Firewall guard recovery timeout" >&2
	ip netns exec "$GW" nft --json list set inet gateway_vpn firewall_schema_generation >&2 || true
	ip -n "$GW" -json link show dev lan0 >&2 || true
  cat "$WORK/guard.log" >&2
  return 1
}

# Simulate loss of only the owned table after an active generation existed.
ip netns exec "$GW" nft add element inet gateway_vpn active_tun_interfaces '{ "gateway-vpn-tun" }'
ip netns exec "$GW" nft add element inet gateway_vpn active_path_generation '{ 77 }'
ip netns exec "$GW" nft delete table inet gateway_vpn
wait_recovery 1
if ip netns exec "$GW" nft list set inet gateway_vpn active_tun_interfaces | grep 'elements' >/dev/null; then
  echo "Guard reopened the previous TUN generation without re-verification" >&2
  exit 1
fi

# Simulate the documented administrative accident. The guard must recreate
# only Gateway VPN's table and again leave PATH_BLOCKED.
ip netns exec "$GW" nft flush ruleset
wait_recovery 2
ip netns exec "$GW" nft list chain inet gateway_vpn forward | grep 'gateway-vpn PATH_BLOCKED' >/dev/null
if ip netns exec "$GW" ip route get 1.1.1.1 >/dev/null 2>&1; then
  echo "Unmarked direct route appeared after firewall recovery" >&2
  exit 1
fi

echo "PASS: firewall guard quarantined LAN, restored owned PATH_BLOCKED table, and did not create a direct route"
