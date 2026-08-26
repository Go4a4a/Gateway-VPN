#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

MARKER=/var/lib/gateway-vpn-privileged/install-transactions/active
if [[ ! -e "$MARKER" && ! -L "$MARKER" ]]; then
  exit 0
fi
[[ -f "$MARKER" && ! -L "$MARKER" ]] || { echo "Gateway recovery marker path is unsafe" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "Gateway install recovery requires root" >&2; exit 1; }
[[ -d /run/lock && ! -L /run/lock && $(stat -c '%u' /run/lock) == 0 ]] || { echo "Gateway runtime lock directory is unavailable" >&2; exit 1; }
LOCK_FILE=/run/lock/gateway-vpn-install.lock
if [[ ! -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
  (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create Gateway transaction lock safely" >&2; exit 1; }
fi
[[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" && $(stat -c '%u:%g:%a' "$LOCK_FILE") == "0:0:600" ]] || { echo "Gateway transaction lock ownership or mode is invalid" >&2; exit 1; }
exec 9<>"$LOCK_FILE"
flock -n 9 || { echo "Another Gateway VPN install/recovery/uninstall transaction is active" >&2; exit 1; }
[[ -f "$MARKER" && ! -L "$MARKER" && $(stat -c '%u:%g:%a' "$MARKER") == "0:0:600" ]] || { echo "Gateway recovery marker ownership or mode is invalid" >&2; exit 1; }
MARKER_BYTES=$(stat -c '%s' "$MARKER")
[[ "$MARKER_BYTES" =~ ^[0-9]+$ && "$MARKER_BYTES" -gt 0 && "$MARKER_BYTES" -le 1024 ]] || { echo "Gateway recovery marker size is invalid" >&2; exit 1; }
[[ $(wc -l <"$MARKER") == 10 ]] || { echo "Gateway recovery marker field count is invalid" >&2; exit 1; }
[[ $(grep -Ec '^(version|old_ipv4_forward|old_ipv6_all_disable|old_ipv6_default_disable|old_ipv6_all_forwarding|preserve_state_root|lan_interface|lan_address|preserve_lan_address|lan_was_up)=' "$MARKER") == 10 ]] || { echo "Gateway recovery marker schema is invalid" >&2; exit 1; }
for marker_key in version old_ipv4_forward old_ipv6_all_disable old_ipv6_default_disable old_ipv6_all_forwarding preserve_state_root lan_interface lan_address preserve_lan_address lan_was_up; do
  [[ $(grep -c "^${marker_key}=" "$MARKER") == 1 ]] || { echo "Gateway recovery marker contains duplicate or missing field: $marker_key" >&2; exit 1; }
done
VERSION=$(sed -n 's/^version=//p' "$MARKER")
OLD_IPV4_FORWARD=$(sed -n 's/^old_ipv4_forward=//p' "$MARKER")
OLD_IPV6_ALL_DISABLE=$(sed -n 's/^old_ipv6_all_disable=//p' "$MARKER")
OLD_IPV6_DEFAULT_DISABLE=$(sed -n 's/^old_ipv6_default_disable=//p' "$MARKER")
OLD_IPV6_ALL_FORWARDING=$(sed -n 's/^old_ipv6_all_forwarding=//p' "$MARKER")
PRESERVE_STATE_ROOT=$(sed -n 's/^preserve_state_root=//p' "$MARKER")
LAN_INTERFACE=$(sed -n 's/^lan_interface=//p' "$MARKER")
LAN_ADDRESS=$(sed -n 's/^lan_address=//p' "$MARKER")
PRESERVE_LAN_ADDRESS=$(sed -n 's/^preserve_lan_address=//p' "$MARKER")
LAN_WAS_UP=$(sed -n 's/^lan_was_up=//p' "$MARKER")
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ && "$OLD_IPV4_FORWARD" =~ ^[01]$ && "$OLD_IPV6_ALL_DISABLE" =~ ^[01]$ && "$OLD_IPV6_DEFAULT_DISABLE" =~ ^[01]$ && "$OLD_IPV6_ALL_FORWARDING" =~ ^[01]$ && "$PRESERVE_STATE_ROOT" =~ ^[01]$ && "$LAN_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ && "$LAN_ADDRESS" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[12][0-9]|30)$ && "$PRESERVE_LAN_ADDRESS" =~ ^[01]$ && "$LAN_WAS_UP" =~ ^[01]$ ]] || { echo "Gateway recovery marker values are invalid" >&2; exit 1; }

FAILED=0
record_failure() {
  echo "Gateway install recovery step failed: $1" >&2
  FAILED=1
}

UNITS=(
  gateway-vpn.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service
  gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn-update-finalize.timer
  gateway-vpn-update-finalize.service gateway-vpn-update-resume.service gateway-vpn-update.service
  gateway-vpn-update-recovery.service gateway-vpn-database-restore-boot.service gateway-vpn-network-recovery.service gateway-vpn-database-restore-dispatch.service gateway-vpn-database-restore.service
  gateway-vpn-database-restore-resume.service gateway-vpn-firewall-guard.service gateway-vpn-firewall.service
)
systemctl disable --now "${UNITS[@]}" >/dev/null 2>&1 || true
systemctl stop 'gateway-vpn-network-rollback@*.timer' 'gateway-vpn-network-rollback@*.service' >/dev/null 2>&1 || true
for unit in "${UNITS[@]}"; do
  systemctl is-active --quiet "$unit" && record_failure "$unit remained active"
done
if /usr/sbin/nft list table inet gateway_vpn >/dev/null 2>&1; then
  /usr/sbin/nft delete table inet gateway_vpn || record_failure "delete owned nftables table"
fi
/usr/sbin/nft list table inet gateway_vpn >/dev/null 2>&1 && record_failure "owned nftables table still exists"
if ip link show dev wg-mgmt >/dev/null 2>&1; then
  ip link delete dev wg-mgmt || record_failure "delete owned WireGuard interface"
fi
ip link show dev wg-mgmt >/dev/null 2>&1 && record_failure "owned WireGuard interface still exists"
if ip link show dev "$LAN_INTERFACE" >/dev/null 2>&1; then
  if ((PRESERVE_LAN_ADDRESS == 0)) && ip -o -4 address show dev "$LAN_INTERFACE" scope global | awk '{print $4}' | grep -Fxq "$LAN_ADDRESS"; then
    ip -4 address del "$LAN_ADDRESS" dev "$LAN_INTERFACE" || record_failure "remove installed LAN address"
  fi
  if ((LAN_WAS_UP == 0)); then
    ip link set dev "$LAN_INTERFACE" down || record_failure "restore LAN administrative state"
  fi
fi
sysctl -q -w "net.ipv6.conf.all.disable_ipv6=$OLD_IPV6_ALL_DISABLE" || record_failure "restore IPv6 all disable state"
sysctl -q -w "net.ipv6.conf.default.disable_ipv6=$OLD_IPV6_DEFAULT_DISABLE" || record_failure "restore IPv6 default disable state"
sysctl -q -w "net.ipv6.conf.all.forwarding=$OLD_IPV6_ALL_FORWARDING" || record_failure "restore IPv6 forwarding state"
sysctl -q -w "net.ipv4.ip_forward=$OLD_IPV4_FORWARD" || record_failure "restore IPv4 forwarding state"
[[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) == "$OLD_IPV6_ALL_DISABLE" ]] || record_failure "verify IPv6 all disable state"
[[ $(cat /proc/sys/net/ipv6/conf/default/disable_ipv6) == "$OLD_IPV6_DEFAULT_DISABLE" ]] || record_failure "verify IPv6 default disable state"
[[ $(cat /proc/sys/net/ipv6/conf/all/forwarding) == "$OLD_IPV6_ALL_FORWARDING" ]] || record_failure "verify IPv6 forwarding state"
[[ $(cat /proc/sys/net/ipv4/ip_forward) == "$OLD_IPV4_FORWARD" ]] || record_failure "verify IPv4 forwarding state"

rm -f /etc/systemd/network/70-gateway-vpn-lan.network /etc/systemd/network/80-gateway-vpn-hilink.network || record_failure "remove owned networkd policy"
rm -f /etc/systemd/journald@gateway-vpn.conf.d/retention.conf || record_failure "remove owned journald policy"
rm -f /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf /etc/sysctl.d/90-gateway-vpn-ipv6.conf /usr/lib/sysusers.d/gateway-vpn.conf /usr/lib/tmpfiles.d/gateway-vpn.conf || record_failure "remove owned host policy"
rm -rf /etc/gateway-vpn || record_failure "remove owned Gateway config"
rm -f /opt/gateway-vpn/current /opt/gateway-vpn/recovery /opt/gateway-vpn/.current.new /opt/gateway-vpn/.recovery.new || record_failure "remove release pointers"
rm -rf "/opt/gateway-vpn/releases/v$VERSION" || record_failure "remove failed release"
for unit_file in \
  gateway-vpn.service gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service \
  gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn-network-recovery.service \
  gateway-vpn-network-rollback@.timer gateway-vpn-network-rollback@.service gateway-vpn-database-restore-boot.service gateway-vpn-database-restore-dispatch.service gateway-vpn-database-restore.service \
  gateway-vpn-database-restore-resume.service gateway-vpn-update.service gateway-vpn-update-recovery.service \
  gateway-vpn-update-resume.service gateway-vpn-update-finalize.service gateway-vpn-update-finalize.timer; do
  rm -f "/etc/systemd/system/$unit_file" || record_failure "remove owned unit $unit_file"
done
rm -f /var/lib/gateway-vpn/install-report.json || record_failure "remove incomplete install report"
rm -f /run/gateway-vpn-install-authorized || record_failure "remove ephemeral service-start authorization"
if ((PRESERVE_STATE_ROOT == 0)); then
  rm -rf /var/lib/gateway-vpn || record_failure "remove newly created Gateway state root"
fi
networkctl reload || record_failure "reload networkd after policy cleanup"
systemctl daemon-reload || record_failure "reload systemd after owned-state cleanup"
for unit in "${UNITS[@]}"; do
  systemctl is-enabled --quiet "$unit" && record_failure "$unit remained enabled"
done
if ((FAILED)); then
  echo "Gateway install recovery is incomplete; active marker retained for retry" >&2
  exit 1
fi
sync || exit 1
timestamp=$(date -u +%Y%m%dT%H%M%S%NZ)
ROLLED_BACK_MARKER="/var/lib/gateway-vpn-privileged/install-transactions/rolled-back-$timestamp"
mv -f "$MARKER" "$ROLLED_BACK_MARKER" || exit 1
if ! sync -f /var/lib/gateway-vpn-privileged/install-transactions; then
  mv -f "$ROLLED_BACK_MARKER" "$MARKER" || true
  sync -f /var/lib/gateway-vpn-privileged/install-transactions || true
  exit 1
fi
systemctl disable gateway-vpn-install-recovery.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/gateway-vpn-install-recovery.service /usr/libexec/gateway-vpn-install-recovery || echo "Warning: recovered Gateway state but could not remove recovery helper" >&2
systemctl daemon-reload || echo "Warning: recovered Gateway state but final systemd reload failed" >&2
exit 0
