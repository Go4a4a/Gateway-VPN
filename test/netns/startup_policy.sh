#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BINARY=${1:-$ROOT/dist/gateway-vpn-netns}
APP_TEST=${2:-$ROOT/dist/gateway-vpn-app-test}
[[ $EUID -eq 0 ]] || { echo "startup_policy.sh requires root" >&2; exit 1; }
[[ -x $BINARY ]] || { echo "Build a Linux gateway-vpn binary and pass its absolute path" >&2; exit 2; }
[[ -x $APP_TEST ]] || { echo "Build the Linux internal/app test binary and pass its absolute path" >&2; exit 2; }
for command in ip nft sed grep mktemp getent useradd userdel ping; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

SUFFIX=$$
GW="gvpn-start-gw-$SUFFIX"
CLIENT="gvpn-start-client-$SUFFIX"
MODEM="gvpn-start-modem-$SUFFIX"
WORK=$(mktemp -d)
CREATED_USERS=()
cleanup() {
  ip netns del "$CLIENT" 2>/dev/null || true
  ip netns del "$MODEM" 2>/dev/null || true
  ip netns del "$GW" 2>/dev/null || true
  for user in "${CREATED_USERS[@]}"; do
    userdel "$user" 2>/dev/null || true
  done
  rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

# The production boot ruleset resolves these fixed service users while nft
# parses skuid expressions. Create only missing accounts and remove only those
# owned by this isolated harness.
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

ip -n "$MODEM" link set lo up
ip -n "$MODEM" address add 192.168.8.1/24 dev modem0
ip -n "$MODEM" link set modem0 up

sed 's/lan_interface: enp2s0/lan_interface: lan0/' "$ROOT/config.example.yaml" >"$WORK/config.yaml"
ip netns exec "$GW" "$BINARY" firewall-boot --config "$WORK/config.yaml" --apply

run_phase() {
  local phase=$1
  local database=$2
  ip netns exec "$GW" env \
    GATEWAY_VPN_STARTUP_POLICY_INTEGRATION=1 \
    GATEWAY_VPN_STARTUP_POLICY_PHASE="$phase" \
    GATEWAY_VPN_STARTUP_POLICY_DB="$database" \
    "$APP_TEST" -test.run '^TestStartupPolicyAgainstKernelFirewall$' -test.count=1
}

assert_blocked() {
  if ip netns exec "$CLIENT" ping -c 1 -W 1 192.168.8.1 >/dev/null 2>&1; then
    echo "Startup quarantine leaked LAN traffic to the modem" >&2
    exit 1
  fi
}

assert_direct() {
  ip netns exec "$CLIENT" ping -c 1 -W 2 192.168.8.1 >/dev/null
  ip netns exec "$GW" ip route get 1.1.1.1 mark 0x1101 | grep 'dev wan0' >/dev/null
  if ip netns exec "$GW" ip route get 1.1.1.1 >/dev/null 2>&1; then
    echo "Ungated startup recovery created an unmarked direct route" >&2
    exit 1
  fi
}

# Startup block ON: a new boot invalidates previous qualification, clears the
# boot-scoped override and leaves both the database and kernel PATH_BLOCKED.
run_phase gated-boot "$WORK/gated.db"
assert_blocked

# Startup block OFF: only the exact prior LKG direct tuple may enter VERIFYING.
# Production policy routing and nft activation then open wan0+fwmark atomically.
run_phase ungated-activate "$WORK/ungated.db"
assert_direct

# A process restart during the same host boot preserves the exact tuple and
# temporary direct-only flag; it must neither manufacture a boot nor re-route.
run_phase same-boot-restart "$WORK/ungated.db"
assert_direct

# Model the next host boot: firewall-boot closes the kernel before control-plane
# recovery. The changed boot ID then resets direct-only and invalidates evidence.
ip netns exec "$GW" "$BINARY" firewall-boot --config "$WORK/config.yaml" --apply
assert_blocked
run_phase next-gated-boot "$WORK/ungated.db"
assert_blocked

if ip netns exec "$GW" ip route get 1.1.1.1 >/dev/null 2>&1; then
  echo "A new gated boot left an unmarked direct route" >&2
  exit 1
fi
ip netns exec "$GW" nft list chain inet gateway_vpn forward | grep 'gateway-vpn PATH_BLOCKED' >/dev/null

echo "PASS: startup gate, exact LKG recovery, same-boot restart, direct-only reset, and kernel quarantine"
