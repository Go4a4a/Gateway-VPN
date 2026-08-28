#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
[[ $EUID -eq 0 ]] || { echo "verify_grub_policy.sh requires root inside a disposable Ubuntu container" >&2; exit 1; }
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || { echo "GRUB policy gate requires Ubuntu 24.04" >&2; exit 1; }
for command in update-grub grub-script-check install grep; do
  command -v "$command" >/dev/null || { echo "Missing GRUB gate command: $command" >&2; exit 1; }
done

install -d -m 0755 /boot/grub /etc/default/grub.d
[[ -f /etc/default/grub ]] || : >/etc/default/grub
install -m 0755 "$ROOT/test/systemd/fake_grub_probe.sh" /usr/sbin/grub-probe

install -m 0644 "$ROOT/packaging/grub/90-gateway-vpn-automatic.cfg" /etc/default/grub.d/90-gateway-vpn.cfg
update-grub >/dev/null
grub-script-check /boot/grub/grub.cfg
grep -Fq 'set timeout_style=hidden' /boot/grub/grub.cfg
grep -Fq 'set timeout=1' /boot/grub/grub.cfg

install -m 0644 "$ROOT/packaging/grub/90-gateway-vpn-menu.cfg" /etc/default/grub.d/90-gateway-vpn.cfg
update-grub >/dev/null
grub-script-check /boot/grub/grub.cfg
grep -Fq 'set timeout_style=menu' /boot/grub/grub.cfg
grep -Fq 'set timeout=5' /boot/grub/grub.cfg

rm -f /etc/default/grub.d/90-gateway-vpn.cfg
update-grub >/dev/null
grub-script-check /boot/grub/grub.cfg
[[ ! -e /etc/default/grub.d/90-gateway-vpn.cfg ]]

echo "PASS: Ubuntu 24.04 generated and validated automatic/menu GRUB policies and owned-drop-in rollback"
