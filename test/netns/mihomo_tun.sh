#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

MIHOMO=${1:-}
PEER=${2:-}
EXPECTED_VERSION=${3:-}
EXPECTED_SHA256=${4:-}
EVIDENCE_DIRECTORY=${5:-}
[[ $EUID -eq 0 ]] || { echo "mihomo_tun.sh requires root" >&2; exit 1; }
[[ $MIHOMO == /* && -x $MIHOMO && ! -L $MIHOMO ]] || { echo "Pass an absolute regular executable Mihomo path" >&2; exit 2; }
[[ $PEER == /* && -x $PEER && ! -L $PEER ]] || { echo "Pass an absolute regular executable mihomo-peer path" >&2; exit 2; }
[[ $EXPECTED_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Pass an exact Mihomo version such as v1.19.30" >&2; exit 2; }
[[ $EXPECTED_SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo "Pass the lowercase expected Mihomo SHA-256" >&2; exit 2; }
for command in ip nft curl grep awk mktemp sha256sum timeout readlink seq sleep sysctl; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

MIHOMO=$(readlink -f -- "$MIHOMO")
PEER=$(readlink -f -- "$PEER")
[[ $(sha256sum -- "$MIHOMO" | awk '{print $1}') == "$EXPECTED_SHA256" ]] || { echo "Mihomo SHA-256 mismatch" >&2; exit 1; }
"$MIHOMO" -v | grep -F "Mihomo Meta $EXPECTED_VERSION linux amd64" >/dev/null || { echo "Mihomo version mismatch" >&2; exit 1; }

SUFFIX=$$
GW="gvpn-mihomo-gw-$SUFFIX"
CLIENT="gvpn-mihomo-client-$SUFFIX"
UPSTREAM="gvpn-mihomo-up-$SUFFIX"
if [[ -n $EVIDENCE_DIRECTORY ]]; then
  [[ $EVIDENCE_DIRECTORY == /* && ! -e $EVIDENCE_DIRECTORY ]] || { echo "Evidence directory must be a new absolute path" >&2; exit 2; }
  mkdir -m 0700 -- "$EVIDENCE_DIRECTORY"
  WORK=$EVIDENCE_DIRECTORY
else
  WORK=$(mktemp -d)
fi
GW_PID=
GW_RUN=0
GW_LOG=
UPSTREAM_PID=
PEER_PID=
cleanup() {
  set +e
  [[ -z $GW_PID ]] || kill "$GW_PID" 2>/dev/null
  [[ -z $UPSTREAM_PID ]] || kill "$UPSTREAM_PID" 2>/dev/null
  [[ -z $PEER_PID ]] || kill "$PEER_PID" 2>/dev/null
  wait "$GW_PID" "$UPSTREAM_PID" "$PEER_PID" 2>/dev/null
  ip netns del "$CLIENT" 2>/dev/null
  ip netns del "$UPSTREAM" 2>/dev/null
  ip netns del "$GW" 2>/dev/null
  [[ -n $EVIDENCE_DIRECTORY ]] || rm -rf -- "$WORK"
}
trap cleanup EXIT INT TERM

mkdir -m 0700 "$WORK/gateway" "$WORK/upstream"
cat >"$WORK/upstream/config.yaml" <<'YAML'
allow-lan: false
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:19091
secret: fixture-upstream-secret
listeners:
  - name: gate-socks
    type: socks
    listen: 203.0.113.2
    port: 1080
    udp: true
rules:
  - MATCH,DIRECT
YAML
cat >"$WORK/gateway/config.yaml" <<'YAML'
allow-lan: false
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:19090
secret: fixture-gateway-secret
dns:
  enable: true
  ipv6: false
  enhanced-mode: redir-host
  respect-rules: true
  nameserver:
    - udp://203.0.114.10:53
  proxy-server-nameserver:
    - udp://203.0.114.10:53
tun:
  enable: true
  device: gateway-vpn-tun
  stack: mixed
  auto-route: true
  auto-redirect: true
  strict-route: true
  auto-detect-interface: false
  include-interface:
    - lan0
  dns-hijack:
    - any:53
    - tcp://any:53
proxies:
  - name: gate-outbound
    type: socks5
    server: 203.0.113.2
    port: 1080
    udp: true
    interface-name: wan0
    routing-mark: 101
proxy-groups:
  - name: gateway-vpn-active
    type: select
    proxies:
      - gate-outbound
      - REJECT
rules:
  - MATCH,gateway-vpn-active
YAML

ip netns add "$GW"
ip netns add "$CLIENT"
ip netns add "$UPSTREAM"
ip link add client0 type veth peer name lan0
ip link set client0 netns "$CLIENT"
ip link set lan0 netns "$GW"
ip link add wan0 type veth peer name upstream0
ip link set wan0 netns "$GW"
ip link set upstream0 netns "$UPSTREAM"

ip -n "$CLIENT" link set lo up
ip -n "$CLIENT" address add 192.168.200.2/24 dev client0
ip -n "$CLIENT" link set client0 up
ip -n "$CLIENT" route add default via 192.168.200.1

ip -n "$GW" link set lo up
ip -n "$GW" address add 192.168.200.1/24 dev lan0
ip -n "$GW" link set lan0 up
ip -n "$GW" address add 10.250.0.2/30 dev wan0
ip -n "$GW" link set wan0 up
ip netns exec "$GW" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$GW" sysctl -q -w net.ipv4.conf.all.src_valid_mark=1
ip -n "$GW" route add table 101 203.0.113.2/32 via 10.250.0.1 dev wan0
ip -n "$GW" rule add priority 100 fwmark 101 lookup 101

ip -n "$UPSTREAM" link set lo up
ip -n "$UPSTREAM" address add 10.250.0.1/30 dev upstream0
ip -n "$UPSTREAM" link set upstream0 up
ip -n "$UPSTREAM" address add 203.0.113.2/32 dev lo
ip -n "$UPSTREAM" address add 203.0.114.10/32 dev lo
ip -n "$UPSTREAM" route add 192.168.200.0/24 via 10.250.0.2 dev upstream0

ip netns exec "$GW" nft -f - <<'NFT'
table inet gateway_vpn_mihomo_gate {
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "lan0" oifname "wan0" counter drop comment "gateway-vpn no direct LAN to uplink"
  }
}
NFT

ip netns exec "$UPSTREAM" "$PEER" serve \
  --http 203.0.114.10:18080 --udp 203.0.114.10:19080 \
  --dns 203.0.114.10:53 --answer 203.0.114.10 >"$WORK/peer.log" 2>&1 &
PEER_PID=$!
for _ in $(seq 1 50); do
  grep -F MIHOMO_PEER_READY "$WORK/peer.log" >/dev/null 2>&1 && break
  kill -0 "$PEER_PID" 2>/dev/null || { cat "$WORK/peer.log" >&2; exit 1; }
  sleep 0.1
done
grep -F MIHOMO_PEER_READY "$WORK/peer.log" >/dev/null || { echo "Local peer did not become ready" >&2; exit 1; }

ip netns exec "$UPSTREAM" "$MIHOMO" -t -d "$WORK/upstream" >/dev/null
ip netns exec "$GW" "$MIHOMO" -t -d "$WORK/gateway" >/dev/null
ip netns exec "$UPSTREAM" "$MIHOMO" -d "$WORK/upstream" >"$WORK/upstream.log" 2>&1 &
UPSTREAM_PID=$!
for _ in $(seq 1 100); do
  if ip netns exec "$UPSTREAM" curl --noproxy '*' --fail --silent \
      -H 'Authorization: Bearer fixture-upstream-secret' http://127.0.0.1:19091/version >/dev/null 2>&1; then
    break
  fi
  kill -0 "$UPSTREAM_PID" 2>/dev/null || { cat "$WORK/upstream.log" >&2; exit 1; }
  sleep 0.1
done
ip netns exec "$UPSTREAM" curl --noproxy '*' --fail --silent \
  -H 'Authorization: Bearer fixture-upstream-secret' http://127.0.0.1:19091/version >/dev/null

if ip netns exec "$GW" ip route get 203.0.113.2 >/dev/null 2>&1; then
  echo "Unmarked proxy endpoint route unexpectedly exists" >&2
  exit 1
fi
ip netns exec "$GW" ip route get 203.0.113.2 mark 101 | grep -F 'dev wan0' >/dev/null

start_gateway() {
  GW_RUN=$((GW_RUN + 1))
  GW_LOG="$WORK/gateway-$GW_RUN.log"
  ip netns exec "$GW" "$MIHOMO" -d "$WORK/gateway" >"$GW_LOG" 2>&1 &
  GW_PID=$!
  for _ in $(seq 1 150); do
    if ip netns exec "$GW" curl --noproxy '*' --fail --silent \
        -H 'Authorization: Bearer fixture-gateway-secret' http://127.0.0.1:19090/version >"$WORK/version.json" 2>/dev/null &&
       ip -n "$GW" link show dev gateway-vpn-tun >/dev/null 2>&1; then
      return 0
    fi
    kill -0 "$GW_PID" 2>/dev/null || { cat "$GW_LOG" >&2; return 1; }
    sleep 0.1
  done
  cat "$GW_LOG" >&2
  return 1
}

probe_all() {
  ip netns exec "$CLIENT" "$PEER" probe --kind http --address 203.0.114.10:18080
  ip netns exec "$CLIENT" "$PEER" probe --kind udp --address 203.0.114.10:19080
  ip netns exec "$CLIENT" "$PEER" probe --kind dns --address 8.8.8.8:53 \
    --name gateway-vpn.test. --answer 203.0.114.10
}

start_gateway
grep -F "$EXPECTED_VERSION" "$WORK/version.json" >/dev/null
ip netns exec "$GW" curl --noproxy '*' --fail --silent \
  -H 'Authorization: Bearer fixture-gateway-secret' http://127.0.0.1:19090/proxies | grep -F 'gate-outbound' >/dev/null
probe_all
ip netns exec "$GW" ip rule show >"$WORK/ip-rules-active.txt"
ip netns exec "$GW" ip route show table main >"$WORK/ip-route-main-active.txt"
ip netns exec "$GW" ip route show table 101 >"$WORK/ip-route-table-101.txt"
ip netns exec "$GW" nft list ruleset >"$WORK/nft-active.txt"
ip netns exec "$GW" nft list chain inet gateway_vpn_mihomo_gate forward | \
  grep -E 'counter packets 0 bytes 0 drop' >/dev/null || {
    echo "Successful TUN probes touched the forbidden direct-forward rule" >&2
    ip netns exec "$GW" nft list chain inet gateway_vpn_mihomo_gate forward >&2
    exit 1
  }

kill -KILL "$GW_PID"
wait "$GW_PID" 2>/dev/null || true
GW_PID=
for _ in $(seq 1 50); do
  ip -n "$GW" link show dev gateway-vpn-tun >/dev/null 2>&1 || break
  sleep 0.1
done
if ip -n "$GW" link show dev gateway-vpn-tun >/dev/null 2>&1; then
  echo "TUN interface remained after Mihomo SIGKILL" >&2
  exit 1
fi
if ip netns exec "$GW" curl --noproxy '*' --fail --silent --max-time 1 \
    -H 'Authorization: Bearer fixture-gateway-secret' http://127.0.0.1:19090/version >/dev/null 2>&1; then
  echo "Mihomo API remained reachable after SIGKILL" >&2
  exit 1
fi
# Production deliberately has no unmarked Internet route in main. Add a
# temporary target-only route after the crash solely to prove that the
# independent forwarding firewall still blocks a route that could otherwise
# leak, then remove it before the restart check.
ip -n "$GW" route add 203.0.114.0/24 via 10.250.0.1 dev wan0
if ip netns exec "$CLIENT" "$PEER" probe --kind http --address 203.0.114.10:18080 --timeout 1s >/dev/null 2>&1; then
  echo "HTTP leaked directly after Mihomo SIGKILL" >&2
  exit 1
fi
if ip netns exec "$CLIENT" "$PEER" probe --kind udp --address 203.0.114.10:19080 --timeout 1s >/dev/null 2>&1; then
  echo "UDP leaked directly after Mihomo SIGKILL" >&2
  exit 1
fi
ip netns exec "$GW" nft list chain inet gateway_vpn_mihomo_gate forward | \
  grep -E 'counter packets [1-9][0-9]* bytes [1-9][0-9]* drop' >/dev/null || {
    echo "Fail-closed proof did not hit the direct-forward drop rule" >&2
    exit 1
  }
ip netns exec "$GW" nft list chain inet gateway_vpn_mihomo_gate forward >"$WORK/nft-forward-after-kill.txt"
ip -n "$GW" route del 203.0.114.0/24 via 10.250.0.1 dev wan0

# A SIGKILL skips userspace cleanup. The same exact config must nevertheless
# reclaim its TUN/nft state and restore the proxy path without opening direct.
start_gateway
probe_all
ip netns exec "$GW" nft list ruleset >"$WORK/nft-restarted.txt"
ip netns exec "$GW" curl --noproxy '*' --fail --silent \
  -H 'Authorization: Bearer fixture-gateway-secret' http://127.0.0.1:19090/connections | grep -F 'connections' >/dev/null

echo "PASS: exact Mihomo $EXPECTED_VERSION/$EXPECTED_SHA256, mixed TUN, marked SOCKS path, TCP/UDP/DNS hijack, API, SIGKILL fail-closed and restart"
