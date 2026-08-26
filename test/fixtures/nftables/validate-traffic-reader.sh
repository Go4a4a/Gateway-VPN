#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

ROOT=${1:-/work}
[[ -f "$ROOT/go.mod" ]] || {
  echo "Gateway VPN source tree is unavailable" >&2
  exit 1
}
command -v nft >/dev/null
TEST_BINARY=${GATEWAY_VPN_TRAFFIC_TEST_BINARY:-}
if [[ -n "$TEST_BINARY" ]]; then
  [[ -x "$TEST_BINARY" ]]
else
  command -v go >/dev/null
fi

trap 'nft delete table inet gateway_vpn >/dev/null 2>&1 || true' EXIT
nft add table inet gateway_vpn
nft add counter inet gateway_vpn user_upload '{ packets 1 bytes 12345 }'
nft add counter inet gateway_vpn user_download '{ packets 2 bytes 67890 }'
nft add counter inet gateway_vpn service_upload '{ packets 3 bytes 111 }'
nft add counter inet gateway_vpn service_download '{ packets 4 bytes 222 }'

cd "$ROOT"
if [[ -n "$TEST_BINARY" ]]; then
  GATEWAY_VPN_NFT_TRAFFIC_INTEGRATION=1 "$TEST_BINARY" -test.run '^TestNFTReaderAgainstKernelNFTables$' -test.count=1
else
  GATEWAY_VPN_NFT_TRAFFIC_INTEGRATION=1 go test ./internal/traffic -run '^TestNFTReaderAgainstKernelNFTables$' -count=1
fi
echo "NFT_TRAFFIC_READER_GATE_PASS"
