#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BINARY=${1:-$ROOT/dist/gateway-vpn-netns}
[[ $EUID -eq 0 ]] || { echo "lan_bridge_ssh.sh requires root" >&2; exit 1; }
[[ -x $BINARY ]] || { echo "Build a Linux gateway-vpn binary and pass its absolute path" >&2; exit 2; }
for command in ip bridge nft sed grep mktemp getent useradd userdel python3 timeout bash ss seq sleep; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

SUFFIX=$$
GW="gvpn-bridge-$SUFFIX"
CLIENT_A="gvpn-lan-a-$SUFFIX"
CLIENT_B="gvpn-lan-b-$SUFFIX"
UPLINK="gvpn-uplink-$SUFFIX"
WORK=$(mktemp -d)
SERVER_PID=
CREATED_USERS=()
cleanup() {
  if [[ -n ${SERVER_PID:-} ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  ip netns del "$CLIENT_A" 2>/dev/null || true
  ip netns del "$CLIENT_B" 2>/dev/null || true
  ip netns del "$UPLINK" 2>/dev/null || true
  ip netns del "$GW" 2>/dev/null || true
  for user in "${CREATED_USERS[@]}"; do
    userdel "$user" 2>/dev/null || true
  done
  rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

# The production nftables renderer resolves these fixed service accounts while
# loading its output rules, even though this gate exercises only LAN input.
for user in gateway-vpn gateway-vpn-mihomo; do
  if ! getent passwd "$user" >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
    CREATED_USERS+=("$user")
  fi
done

ip netns add "$GW"
ip netns add "$CLIENT_A"
ip netns add "$CLIENT_B"
ip netns add "$UPLINK"

make_veth() {
  local namespace=$1
  local peer_name=$2
  local root_left="v${SUFFIX: -4}${peer_name: -1}a"
  local root_right="v${SUFFIX: -4}${peer_name: -1}b"
  ip link add "$root_left" type veth peer name "$root_right"
  ip link set "$root_left" netns "$namespace"
  ip link set "$root_right" netns "$GW"
  ip -n "$namespace" link set "$root_left" name eth0
  ip -n "$GW" link set "$root_right" name "$peer_name"
}

make_veth "$CLIENT_A" lanp1
make_veth "$CLIENT_B" lanp2
make_veth "$UPLINK" uplink0

for namespace in "$GW" "$CLIENT_A" "$CLIENT_B" "$UPLINK"; do
  ip -n "$namespace" link set lo up
done

ip -n "$GW" link add name gateway-vpn-lan type bridge stp_state 1 forward_delay 4
ip -n "$GW" link set lanp1 master gateway-vpn-lan
ip -n "$GW" link set lanp2 master gateway-vpn-lan
ip -n "$GW" link set lanp1 up
ip -n "$GW" link set lanp2 up
ip -n "$GW" link set gateway-vpn-lan up
ip -n "$GW" address add 192.168.200.1/24 dev gateway-vpn-lan
ip -n "$GW" link set uplink0 up
ip -n "$GW" address add 192.168.8.2/24 dev uplink0

ip -n "$CLIENT_A" link set eth0 up
ip -n "$CLIENT_A" address add 192.168.200.2/24 dev eth0
ip -n "$CLIENT_B" link set eth0 up
ip -n "$CLIENT_B" address add 192.168.200.3/24 dev eth0
ip -n "$UPLINK" link set eth0 up
ip -n "$UPLINK" address add 192.168.8.1/24 dev eth0

ip -n "$GW" -o link show dev lanp1 | grep -F 'master gateway-vpn-lan' >/dev/null
ip -n "$GW" -o link show dev lanp2 | grep -F 'master gateway-vpn-lan' >/dev/null
ip -n "$GW" -d link show dev gateway-vpn-lan | grep -F 'stp_state 1' >/dev/null
[[ -z $(ip -n "$GW" -o -4 address show dev lanp1) ]]
[[ -z $(ip -n "$GW" -o -4 address show dev lanp2) ]]
[[ $(ip -n "$GW" -o -4 address show dev gateway-vpn-lan | grep -c '192.168.200.1/24') == 1 ]]

for _ in $(seq 1 240); do
  if ip netns exec "$GW" bridge -j link show dev lanp1 | grep -Eq '"state"[[:space:]]*:[[:space:]]*"forwarding"' \
    && ip netns exec "$GW" bridge -j link show dev lanp2 | grep -Eq '"state"[[:space:]]*:[[:space:]]*"forwarding"'; then
    break
  fi
  sleep 0.05
done
ip netns exec "$GW" bridge -j link show dev lanp1 | grep -Eq '"state"[[:space:]]*:[[:space:]]*"forwarding"' || { echo "First LAN member did not reach STP forwarding" >&2; exit 1; }
ip netns exec "$GW" bridge -j link show dev lanp2 | grep -Eq '"state"[[:space:]]*:[[:space:]]*"forwarding"' || { echo "Second LAN member did not reach STP forwarding" >&2; exit 1; }

sed 's/lan_interface: enp2s0/lan_interface: gateway-vpn-lan/' "$ROOT/config.example.yaml" >"$WORK/config.yaml"
ip netns exec "$GW" "$BINARY" firewall-boot --config "$WORK/config.yaml" --apply
ip netns exec "$GW" nft list chain inet gateway_vpn input | grep -F 'iifname "gateway-vpn-lan" tcp dport 22 accept' >/dev/null

ip netns exec "$GW" python3 -c 'import socket
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 22))
s.listen(2)
for _ in range(2):
    c, _ = s.accept()
    c.recv(16)
    c.sendall(b"pong\n")
    c.close()
s.close()' >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
  ip netns exec "$GW" ss -H -ltn 'sport = :22' | grep -q . && break
  sleep 0.05
done
ip netns exec "$GW" ss -H -ltn 'sport = :22' | grep -q . || { echo "Test SSH listener did not start" >&2; exit 1; }

# A physically separate uplink reaches the host address but must not reach the
# management listener because the production input rule names only the bridge.
if timeout 1 ip netns exec "$UPLINK" bash -c 'exec 3<>/dev/tcp/192.168.8.2/22'; then
  echo "TCP/22 was exposed through the non-LAN uplink" >&2
  exit 1
fi

probe_lan_port() {
  local namespace=$1
  timeout 5 ip netns exec "$namespace" bash -c '
    exec 3<>/dev/tcp/192.168.200.1/22
    printf "ping\n" >&3
    IFS= read -r -t 2 reply <&3
    [[ $reply == pong ]]
  '
}

probe_lan_port "$CLIENT_A"
probe_lan_port "$CLIENT_B"
wait "$SERVER_PID"
SERVER_PID=

echo "PASS: one bridge IPv4 and the production firewall allowed TCP/22 through both LAN members while blocking the uplink"
