#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BINARY=${1:-$ROOT/dist/gateway-vpn-netns}
DATAPLANE_TEST=${2:-$ROOT/dist/gateway-vpn-dataplane-test}
[[ $EUID -eq 0 ]] || { echo "firewall_guard.sh requires root" >&2; exit 1; }
[[ -x $BINARY ]] || { echo "Build a Linux gateway-vpn binary and pass its absolute path" >&2; exit 2; }
[[ -x $DATAPLANE_TEST ]] || { echo "Build the Linux dataplane test binary and pass its absolute path" >&2; exit 2; }
for command in ip nft sed grep mktemp getent useradd userdel ping python3 tcpdump ss timeout; do
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
ip link add gvtun0 type veth peer name tunpeer0
ip link set gvtun0 netns "$GW"
ip -n "$GW" link set gvtun0 name gateway-vpn-tun
ip link set tunpeer0 netns "$MODEM"

ip -n "$CLIENT" link set lo up
ip -n "$CLIENT" address add 192.168.200.2/24 dev client0
ip -n "$CLIENT" link set client0 up
ip -n "$CLIENT" route add default via 192.168.200.1

ip -n "$GW" link set lo up
ip -n "$GW" address add 192.168.200.1/24 dev lan0
ip -n "$GW" link set lan0 up
ip -n "$GW" address add 192.168.8.2/24 dev wan0
ip -n "$GW" link set wan0 up
ip -n "$GW" address add 10.250.0.1/24 dev gateway-vpn-tun
ip -n "$GW" link set gateway-vpn-tun mtu 1300
ip -n "$GW" link set gateway-vpn-tun up
ip netns exec "$GW" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$GW" sysctl -q -w net.ipv4.conf.all.src_valid_mark=1
ip -n "$GW" route add default via 192.168.8.1 dev wan0 table 1101 protocol 186
ip -n "$GW" rule add priority 1101 fwmark 0x1101/0xffffffff table 1101 protocol 186

ip -n "$MODEM" link set lo up
ip -n "$MODEM" address add 192.168.8.1/24 dev modem0
ip -n "$MODEM" link set modem0 up
ip -n "$MODEM" address add 10.250.0.2/24 dev tunpeer0
ip -n "$MODEM" link set tunpeer0 mtu 1300
ip -n "$MODEM" link set tunpeer0 up
ip -n "$MODEM" route add 192.168.200.0/24 via 10.250.0.1 dev tunpeer0

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

# A reduced active-route MTU must rewrite only the forwarded client TCP SYN.
# Without the owned forward_mss chain this packet advertises the LAN MSS 1460;
# after route-aware clamping the modem observes 1280-40 = 1240. This proves
# actual packet mutation, not just nft syntax acceptance.
ip -n "$GW" link set dev wan0 mtu 1280
ip -n "$MODEM" link set dev modem0 mtu 1280
ip netns exec "$MODEM" python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("192.168.8.1",18080)); s.listen(1); c,_=s.accept(); c.close(); s.close()' >"$WORK/mss-server.log" 2>&1 &
MSS_SERVER_PID=$!
for _ in $(seq 1 50); do
  ip netns exec "$MODEM" ss -H -ltn 'sport = :18080' | grep -F . >/dev/null && break
  sleep 0.02
done
ip netns exec "$MODEM" ss -H -ltn 'sport = :18080' | grep -F . >/dev/null || { echo "MSS test server did not start" >&2; exit 1; }
ip netns exec "$MODEM" timeout 5 tcpdump -i modem0 -nn -s 128 -c 1 'tcp[tcpflags] & tcp-syn != 0 and dst port 18080' -w "$WORK/mss.pcap" >"$WORK/mss-tcpdump.log" 2>&1 &
MSS_CAPTURE_PID=$!
sleep 0.1
ip netns exec "$CLIENT" python3 -c 'import socket; s=socket.create_connection(("192.168.8.1",18080),2); s.close()'
wait "$MSS_SERVER_PID"
wait "$MSS_CAPTURE_PID"
tcpdump -nn -vv -r "$WORK/mss.pcap" 2>/dev/null | grep -F 'mss 1240,' >/dev/null || {
  echo "Forwarded TCP SYN was not clamped to the active route MTU" >&2
  tcpdump -nn -vv -r "$WORK/mss.pcap" >&2 || true
  exit 1
}

ip netns exec "$GW" nft --file "$ROOT/test/fixtures/nftables/path-active-modem-a.nft"
if ip netns exec "$CLIENT" ping -c 1 -W 1 192.168.8.1 >/dev/null 2>&1; then
  echo "TUN activation left the previous direct path open" >&2
  exit 1
fi

# The same route-aware rule must work when no modem/direct gate is involved.
# A veth named like the production TUN gives this firewall test a real packet
# egress while the separate Mihomo suite remains responsible for TUN userspace.
ip netns exec "$MODEM" python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("10.250.0.2",18081)); s.listen(1); c,_=s.accept(); c.close(); s.close()' >"$WORK/mss-tun-server.log" 2>&1 &
MSS_TUN_SERVER_PID=$!
for _ in $(seq 1 50); do
  ip netns exec "$MODEM" ss -H -ltn 'sport = :18081' | grep -F . >/dev/null && break
  sleep 0.02
done
ip netns exec "$MODEM" ss -H -ltn 'sport = :18081' | grep -F . >/dev/null || { echo "MSS TUN test server did not start" >&2; exit 1; }
ip netns exec "$MODEM" timeout 5 tcpdump -i tunpeer0 -nn -s 128 -c 1 'tcp[tcpflags] & tcp-syn != 0 and dst port 18081' -w "$WORK/mss-tun.pcap" >"$WORK/mss-tun-tcpdump.log" 2>&1 &
MSS_TUN_CAPTURE_PID=$!
sleep 0.1
ip netns exec "$CLIENT" python3 -c 'import socket; s=socket.create_connection(("10.250.0.2",18081),2); s.close()'
wait "$MSS_TUN_SERVER_PID"
wait "$MSS_TUN_CAPTURE_PID"
tcpdump -nn -vv -r "$WORK/mss-tun.pcap" 2>/dev/null | grep -F 'mss 1260,' >/dev/null || {
  echo "Forwarded TCP SYN was not clamped to the active TUN route MTU" >&2
  tcpdump -nn -vv -r "$WORK/mss-tun.pcap" >&2 || true
  exit 1
}

# Leave the guard test itself at the boot-safe baseline.
ip netns exec "$GW" "$BINARY" firewall-boot --config "$WORK/config.yaml" --apply

ip netns exec "$GW" "$BINARY" firewall-guard --config "$WORK/config.yaml" --marker-path "$WORK/quarantine" --apply >"$WORK/guard.log" 2>&1 &
GUARD_PID=$!

wait_recovery() {
  local expected_count=$1
  local attempt
  for attempt in $(seq 1 100); do
    if ip netns exec "$GW" nft list table inet gateway_vpn >/dev/null 2>&1 \
      && ip netns exec "$GW" nft --json list set inet gateway_vpn firewall_schema_generation | grep -E '"elem"[[:space:]]*:[[:space:]]*\[[[:space:]]*8[[:space:]]*\]' >/dev/null \
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
