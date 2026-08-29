#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
TEST_BINARY=${1:-/tmp/gateway-vpn-wgingress-test}

[[ $(id -u) -eq 0 ]] || { echo "WireGuard ingress netns gate requires root" >&2; exit 1; }
[[ -x "$TEST_BINARY" ]] || { echo "WireGuard ingress test binary is unavailable" >&2; exit 1; }
for executable in /usr/sbin/ip /usr/sbin/nft /usr/bin/wg /usr/sbin/useradd; do
  [[ -x "$executable" ]] || { echo "Required executable is unavailable: $executable" >&2; exit 1; }
done

for account in gateway-vpn gateway-vpn-mihomo; do
  if ! getent passwd "$account" >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$account"
  fi
done

cd -- "$ROOT"
GATEWAY_VPN_WG_INGRESS_INTEGRATION=1 "$TEST_BINARY" \
  -test.v -test.run '^TestBackendAgainstKernelWireGuardNamespace$'

echo "WireGuard ingress kernel namespace gate passed"
