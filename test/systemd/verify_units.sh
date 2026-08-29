#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
[[ $EUID -eq 0 ]] || { echo "verify_units.sh requires root inside the disposable builder" >&2; exit 1; }
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || { echo "systemd gate requires Ubuntu 24.04" >&2; exit 1; }

for command in apt-get install mkdir basename; do
  command -v "$command" >/dev/null || { echo "Missing systemd gate command: $command" >&2; exit 1; }
done

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -qq --yes --no-install-recommends \
  systemd nftables dnsmasq-base wireguard-tools grub-common grub2-common >/dev/null
command -v systemd-analyze >/dev/null || { echo "systemd-analyze is unavailable after installing systemd" >&2; exit 1; }

mkdir -p \
  /etc/systemd/system/wg-quick@wg-mgmt.service.d \
	/etc/systemd/system/systemd-networkd-wait-online.service.d \
  /opt/gateway-vpn/current/bin \
  /opt/gateway-vpn/current/libexec \
  /opt/gateway-vpn/recovery/bin \
  /usr/libexec

for unit in \
  "$ROOT"/packaging/systemd/*.service \
  "$ROOT"/packaging/systemd/*.socket \
  "$ROOT"/packaging/systemd/*.timer \
  "$ROOT"/packaging/vps/systemd/*.service; do
  install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"
done
install -m 0644 \
  "$ROOT/packaging/vps/systemd/wg-quick@wg-mgmt.service.d/gateway-vpn.conf" \
  /etc/systemd/system/wg-quick@wg-mgmt.service.d/gateway-vpn.conf
install -m 0644 \
  "$ROOT/packaging/systemd-wait-online/gateway-vpn.conf" \
  /etc/systemd/system/systemd-networkd-wait-online.service.d/gateway-vpn.conf

# systemd-analyze verifies command existence in addition to unit syntax and
# dependency structure. These inert placeholders occupy the exact signed
# release paths without executing application code during this static gate.
for executable in \
  /opt/gateway-vpn/current/bin/gateway-vpn \
  /opt/gateway-vpn/current/libexec/mihomo \
  /opt/gateway-vpn/recovery/bin/gateway-vpn \
  /usr/libexec/gateway-vpn-install-recovery \
  /usr/libexec/gateway-vpn-host-upgrade-recovery \
  /usr/libexec/gateway-vpn-uninstall-job \
  /usr/libexec/gateway-vpn-vps-install-recovery; do
  install -m 0755 /usr/bin/true "$executable"
done

systemd-analyze verify \
  /etc/systemd/system/gateway-vpn*.service \
  /etc/systemd/system/gateway-vpn*.socket \
  /etc/systemd/system/gateway-vpn*.timer \
	/lib/systemd/system/systemd-networkd-wait-online.service \
  /lib/systemd/system/wg-quick@.service

bash "$ROOT/test/systemd/verify_grub_policy.sh"

echo "PASS: Ubuntu 24.04 systemd verified Gateway/VPS units, no-wait boot policy, timers, sockets and WireGuard drop-in"
