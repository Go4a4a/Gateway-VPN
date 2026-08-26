#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

ROOT=${1:-/work}
FIXTURE="$ROOT/test/fixtures/nftables/boot-blocked.nft"
TEMPLATE="$ROOT/packaging/nftables/boot.nft.in"

[[ -f "$FIXTURE" && -f "$TEMPLATE" ]] || {
  echo "Gateway VPN nftables fixtures are unavailable" >&2
  exit 1
}
command -v nft >/dev/null
command -v getent >/dev/null
command -v useradd >/dev/null

getent passwd gateway-vpn >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin gateway-vpn
getent passwd gateway-vpn-mihomo >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin gateway-vpn-mihomo

rendered=$(mktemp)
trap 'rm -f "$rendered"; nft delete table inet gateway_vpn >/dev/null 2>&1 || true' EXIT
sed 's|__LAN_INTERFACE__|enp2s0|g' "$TEMPLATE" >"$rendered"

nft --check --file "$FIXTURE"
nft --check --file "$rendered"
nft --file "$FIXTURE"

counters=$(nft --json list counters table inet gateway_vpn)
for name in user_upload user_download service_upload service_download; do
  grep -Fq "\"name\": \"$name\"" <<<"$counters"
done

ruleset=$(nft list table inet gateway_vpn)
grep -Fq 'gateway-vpn PATH_BLOCKED' <<<"$ruleset"
grep -Fq 'counter name "service_upload"' <<<"$ruleset"
grep -Fq 'counter name "service_download"' <<<"$ruleset"
if grep -Fq 'flush ruleset' <<<"$ruleset"; then
  echo "Gateway VPN fixture contains a global ruleset flush" >&2
  exit 1
fi

echo "NFT_KERNEL_FIXTURE_GATE_PASS"
