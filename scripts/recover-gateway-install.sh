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
if [[ ${GATEWAY_VPN_HOST_UPGRADE_INNER:-} == 1 ]]; then
  [[ -e /proc/$$/fd/9 && $(readlink -f /proc/$$/fd/9) == "$LOCK_FILE" && -f /var/lib/gateway-vpn-host-upgrade/active ]] || { echo "Inherited host-upgrade recovery lock is invalid" >&2; exit 1; }
else
  exec 9<>"$LOCK_FILE"
  flock -n 9 || { echo "Another Gateway VPN install/recovery/uninstall transaction is active" >&2; exit 1; }
fi
[[ -f "$MARKER" && ! -L "$MARKER" && $(stat -c '%u:%g:%a' "$MARKER") == "0:0:600" ]] || { echo "Gateway recovery marker ownership or mode is invalid" >&2; exit 1; }
MARKER_BYTES=$(stat -c '%s' "$MARKER")
[[ "$MARKER_BYTES" =~ ^[0-9]+$ && "$MARKER_BYTES" -gt 0 && "$MARKER_BYTES" -le 2048 ]] || { echo "Gateway recovery marker size is invalid" >&2; exit 1; }
MARKER_FIELD_COUNT=$(wc -l <"$MARKER")
[[ "$MARKER_FIELD_COUNT" == 14 || "$MARKER_FIELD_COUNT" == 16 || "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 ]] || { echo "Gateway recovery marker field count is invalid" >&2; exit 1; }
[[ $(grep -Ec '^(version|old_ipv4_forward|old_ipv6_all_disable|old_ipv6_default_disable|old_ipv6_all_forwarding|preserve_state_root|lan_interface|lan_members|lan_member_was_up|lan_address|preserve_lan_address|lan_was_up|ssh_was_enabled|ssh_was_active|ssh_socket_was_enabled|ssh_socket_was_active|log_reader_user|log_reader_was_member|boot_network_policy|grub_policy)=' "$MARKER") == "$MARKER_FIELD_COUNT" ]] || { echo "Gateway recovery marker schema is invalid" >&2; exit 1; }
MARKER_KEYS=(version old_ipv4_forward old_ipv6_all_disable old_ipv6_default_disable old_ipv6_all_forwarding preserve_state_root lan_interface lan_members lan_member_was_up lan_address preserve_lan_address lan_was_up ssh_was_enabled ssh_was_active)
if [[ "$MARKER_FIELD_COUNT" == 16 || "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 ]]; then
  MARKER_KEYS+=(boot_network_policy grub_policy)
fi
if [[ "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 ]]; then
  MARKER_KEYS+=(log_reader_user log_reader_was_member)
fi
if [[ "$MARKER_FIELD_COUNT" == 20 ]]; then
  MARKER_KEYS+=(ssh_socket_was_enabled ssh_socket_was_active)
fi
for marker_key in "${MARKER_KEYS[@]}"; do
  [[ $(grep -c "^${marker_key}=" "$MARKER") == 1 ]] || { echo "Gateway recovery marker contains duplicate or missing field: $marker_key" >&2; exit 1; }
done
VERSION=$(sed -n 's/^version=//p' "$MARKER")
OLD_IPV4_FORWARD=$(sed -n 's/^old_ipv4_forward=//p' "$MARKER")
OLD_IPV6_ALL_DISABLE=$(sed -n 's/^old_ipv6_all_disable=//p' "$MARKER")
OLD_IPV6_DEFAULT_DISABLE=$(sed -n 's/^old_ipv6_default_disable=//p' "$MARKER")
OLD_IPV6_ALL_FORWARDING=$(sed -n 's/^old_ipv6_all_forwarding=//p' "$MARKER")
PRESERVE_STATE_ROOT=$(sed -n 's/^preserve_state_root=//p' "$MARKER")
LAN_INTERFACE=$(sed -n 's/^lan_interface=//p' "$MARKER")
LAN_MEMBERS=$(sed -n 's/^lan_members=//p' "$MARKER")
LAN_MEMBER_WAS_UP=$(sed -n 's/^lan_member_was_up=//p' "$MARKER")
LAN_ADDRESS=$(sed -n 's/^lan_address=//p' "$MARKER")
PRESERVE_LAN_ADDRESS=$(sed -n 's/^preserve_lan_address=//p' "$MARKER")
LAN_WAS_UP=$(sed -n 's/^lan_was_up=//p' "$MARKER")
SSH_WAS_ENABLED=$(sed -n 's/^ssh_was_enabled=//p' "$MARKER")
SSH_WAS_ACTIVE=$(sed -n 's/^ssh_was_active=//p' "$MARKER")
BOOT_NETWORK_POLICY=keep
GRUB_POLICY=keep
LOG_READER_USER=""
LOG_READER_WAS_MEMBER=1
SSH_SOCKET_STATE_KNOWN=0
SSH_SOCKET_WAS_ENABLED=0
SSH_SOCKET_WAS_ACTIVE=0
if [[ "$MARKER_FIELD_COUNT" == 16 || "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 ]]; then
  BOOT_NETWORK_POLICY=$(sed -n 's/^boot_network_policy=//p' "$MARKER")
  GRUB_POLICY=$(sed -n 's/^grub_policy=//p' "$MARKER")
fi
if [[ "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 ]]; then
  LOG_READER_USER=$(sed -n 's/^log_reader_user=//p' "$MARKER")
  LOG_READER_WAS_MEMBER=$(sed -n 's/^log_reader_was_member=//p' "$MARKER")
fi
if [[ "$MARKER_FIELD_COUNT" == 20 ]]; then
  SSH_SOCKET_STATE_KNOWN=1
  SSH_SOCKET_WAS_ENABLED=$(sed -n 's/^ssh_socket_was_enabled=//p' "$MARKER")
  SSH_SOCKET_WAS_ACTIVE=$(sed -n 's/^ssh_socket_was_active=//p' "$MARKER")
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ && "$OLD_IPV4_FORWARD" =~ ^[01]$ && "$OLD_IPV6_ALL_DISABLE" =~ ^[01]$ && "$OLD_IPV6_DEFAULT_DISABLE" =~ ^[01]$ && "$OLD_IPV6_ALL_FORWARDING" =~ ^[01]$ && "$PRESERVE_STATE_ROOT" =~ ^[01]$ && "$LAN_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ && "$LAN_ADDRESS" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[12][0-9]|30)$ && "$PRESERVE_LAN_ADDRESS" =~ ^[01]$ && "$LAN_WAS_UP" =~ ^[01]$ && "$SSH_WAS_ENABLED" =~ ^[01]$ && "$SSH_WAS_ACTIVE" =~ ^[01]$ ]] || { echo "Gateway recovery marker values are invalid" >&2; exit 1; }
[[ "$BOOT_NETWORK_POLICY" == gateway-nonblocking || "$BOOT_NETWORK_POLICY" == keep ]] || { echo "Gateway recovery boot-network policy is invalid" >&2; exit 1; }
[[ "$GRUB_POLICY" == automatic-hidden || "$GRUB_POLICY" == menu-5s || "$GRUB_POLICY" == keep ]] || { echo "Gateway recovery GRUB policy is invalid" >&2; exit 1; }
[[ -z "$LOG_READER_USER" || "$LOG_READER_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$LOG_READER_USER" != root && "$LOG_READER_WAS_MEMBER" =~ ^[01]$ ]] || { echo "Gateway recovery log-reader values are invalid" >&2; exit 1; }
((SSH_SOCKET_STATE_KNOWN == 0)) || [[ "$SSH_SOCKET_WAS_ENABLED" =~ ^[01]$ && "$SSH_SOCKET_WAS_ACTIVE" =~ ^[01]$ ]] || { echo "Gateway recovery OpenSSH socket values are invalid" >&2; exit 1; }
if [[ -n "$LAN_MEMBERS" ]]; then
  [[ "$LAN_INTERFACE" == gateway-vpn-lan && "$LAN_MEMBERS" =~ ^[A-Za-z0-9_.:-]{1,15}(,[A-Za-z0-9_.:-]{1,15}){0,15}$ && "$LAN_MEMBER_WAS_UP" =~ ^[01](,[01]){0,15}$ ]] || { echo "Gateway recovery LAN bridge marker values are invalid" >&2; exit 1; }
  IFS=, read -r -a LAN_MEMBER_NAMES <<<"$LAN_MEMBERS"
  IFS=, read -r -a LAN_MEMBER_WAS_UP_VALUES <<<"$LAN_MEMBER_WAS_UP"
  ((${#LAN_MEMBER_NAMES[@]} == ${#LAN_MEMBER_WAS_UP_VALUES[@]})) || { echo "Gateway recovery LAN bridge marker lengths differ" >&2; exit 1; }
else
  [[ -z "$LAN_MEMBER_WAS_UP" ]] || { echo "Gateway recovery has member state without members" >&2; exit 1; }
  LAN_MEMBER_NAMES=()
  LAN_MEMBER_WAS_UP_VALUES=()
fi

FAILED=0
record_failure() {
  echo "Gateway install recovery step failed: $1" >&2
  FAILED=1
}

restore_systemd_unit_state() {
  local unit=$1 desired_enabled=$2 desired_active=$3 label=$4 load_state
  load_state=$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)
  if [[ "$load_state" == not-found ]]; then
    ((desired_enabled == 0 && desired_active == 0)) && return 0
    record_failure "$label unit is unavailable"
    return 0
  fi
  if ((desired_enabled)); then
    systemctl enable "$unit" >/dev/null 2>&1 || record_failure "enable $label"
    systemctl is-enabled --quiet "$unit" || record_failure "verify enabled $label"
  else
    systemctl disable "$unit" >/dev/null 2>&1 || record_failure "disable $label"
    systemctl is-enabled --quiet "$unit" && record_failure "$label remained enabled"
  fi
  if ((desired_active)); then
    systemctl start "$unit" >/dev/null 2>&1 || record_failure "start $label"
    systemctl is-active --quiet "$unit" || record_failure "verify active $label"
  else
    systemctl stop "$unit" >/dev/null 2>&1 || record_failure "stop $label"
    systemctl is-active --quiet "$unit" && record_failure "$label remained active"
  fi
  # A successfully restored disabled/inactive unit makes the negative probes
  # above return 1.  Do not leak that expected probe result through the
  # function under `set -e`; only record_failure controls recovery failure.
  return 0
}

# Recovery removes only Gateway-owned .network files. Do not implicitly start
# a stopped or unavailable network manager while restoring the pre-install
# host. When networkd is already active, failure to reload its live policy is a
# real recovery error and is retained in the durable transaction marker.
reload_networkd_policy_if_active() {
  if systemctl is-active --quiet systemd-networkd.service; then
    networkctl reload || record_failure "reload active networkd after policy cleanup"
  else
    echo "systemd-networkd is not active; skipped live policy reload after Gateway install recovery"
  fi
}

UNITS=(
  gateway-vpn.service gateway-vpn-watchdog.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service
  gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn-update-finalize.timer
  gateway-vpn-update-finalize.service gateway-vpn-update-resume.service gateway-vpn-update.service
  gateway-vpn-update-recovery.service gateway-vpn-database-restore-boot.service gateway-vpn-network-recovery.service gateway-vpn-database-restore-dispatch.service gateway-vpn-database-restore.service
  gateway-vpn-database-restore-resume.service gateway-vpn-firewall-guard.service gateway-vpn-firewall.service
  gateway-vpn-uninstall.service
)
if [[ ${GATEWAY_VPN_HOST_UPGRADE_INNER:-} != 1 ]]; then
  UNITS+=(gateway-vpn-host-upgrade-recovery.service)
fi
systemctl disable --now "${UNITS[@]}" >/dev/null 2>&1 || true
systemctl stop 'gateway-vpn-network-rollback@*.timer' 'gateway-vpn-network-rollback@*.service' >/dev/null 2>&1 || true
systemctl stop 'gateway-vpn-power-cycle@*.service' >/dev/null 2>&1 || true
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
if ip link show dev wg-ingress >/dev/null 2>&1; then
  ip link delete dev wg-ingress || record_failure "delete owned WireGuard ingress interface"
fi
ip link show dev wg-ingress >/dev/null 2>&1 && record_failure "owned WireGuard ingress interface still exists"
if ip link show dev "$LAN_INTERFACE" >/dev/null 2>&1; then
  if ((PRESERVE_LAN_ADDRESS == 0)) && ip -o -4 address show dev "$LAN_INTERFACE" scope global | awk '{print $4}' | grep -Fxq "$LAN_ADDRESS"; then
    ip -4 address del "$LAN_ADDRESS" dev "$LAN_INTERFACE" || record_failure "remove installed LAN address"
  fi
  if ((LAN_WAS_UP == 0)); then
    ip link set dev "$LAN_INTERFACE" down || record_failure "restore LAN administrative state"
  fi
fi
for index in "${!LAN_MEMBER_NAMES[@]}"; do
  member=${LAN_MEMBER_NAMES[$index]}
  if ip link show dev "$member" >/dev/null 2>&1; then
    ip link set dev "$member" nomaster || record_failure "detach LAN bridge member $member"
    if ((${LAN_MEMBER_WAS_UP_VALUES[$index]} == 0)); then
      ip link set dev "$member" down || record_failure "restore LAN bridge member state $member"
    fi
  fi
done
if ((${#LAN_MEMBER_NAMES[@]})) && ip link show dev "$LAN_INTERFACE" >/dev/null 2>&1; then
  ip link delete dev "$LAN_INTERFACE" type bridge || record_failure "delete owned LAN bridge"
fi
if ((SSH_SOCKET_STATE_KNOWN)); then
  restore_systemd_unit_state ssh.socket "$SSH_SOCKET_WAS_ENABLED" "$SSH_SOCKET_WAS_ACTIVE" "OpenSSH socket"
fi
restore_systemd_unit_state ssh.service "$SSH_WAS_ENABLED" "$SSH_WAS_ACTIVE" "OpenSSH service"
if [[ -n "$LOG_READER_USER" && "$LOG_READER_WAS_MEMBER" == 0 ]] &&
   getent group gateway-vpn-log-readers >/dev/null 2>&1 &&
   id -nG "$LOG_READER_USER" 2>/dev/null | tr ' ' '\n' | grep -Fxq gateway-vpn-log-readers; then
  gpasswd -d "$LOG_READER_USER" gateway-vpn-log-readers >/dev/null 2>&1 || record_failure "restore Gateway log-reader group membership"
fi
sysctl -q -w "net.ipv6.conf.all.disable_ipv6=$OLD_IPV6_ALL_DISABLE" || record_failure "restore IPv6 all disable state"
sysctl -q -w "net.ipv6.conf.default.disable_ipv6=$OLD_IPV6_DEFAULT_DISABLE" || record_failure "restore IPv6 default disable state"
sysctl -q -w "net.ipv6.conf.all.forwarding=$OLD_IPV6_ALL_FORWARDING" || record_failure "restore IPv6 forwarding state"
sysctl -q -w "net.ipv4.ip_forward=$OLD_IPV4_FORWARD" || record_failure "restore IPv4 forwarding state"
[[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) == "$OLD_IPV6_ALL_DISABLE" ]] || record_failure "verify IPv6 all disable state"
[[ $(cat /proc/sys/net/ipv6/conf/default/disable_ipv6) == "$OLD_IPV6_DEFAULT_DISABLE" ]] || record_failure "verify IPv6 default disable state"
[[ $(cat /proc/sys/net/ipv6/conf/all/forwarding) == "$OLD_IPV6_ALL_FORWARDING" ]] || record_failure "verify IPv6 forwarding state"
[[ $(cat /proc/sys/net/ipv4/ip_forward) == "$OLD_IPV4_FORWARD" ]] || record_failure "verify IPv4 forwarding state"

rm -f /etc/systemd/network/05-gateway-vpn-lan.network /etc/systemd/network/05-gateway-vpn-lan.netdev /etc/systemd/network/06-gateway-vpn-lan-*.network /etc/systemd/network/80-gateway-vpn-hilink.network || record_failure "remove owned networkd policy"
rm -f /etc/systemd/system/systemd-networkd-wait-online.service.d/gateway-vpn.conf || record_failure "remove owned boot-network policy"
if [[ "$GRUB_POLICY" != keep ]]; then
  rm -f /etc/default/grub.d/90-gateway-vpn.cfg || record_failure "remove owned GRUB policy"
  if command -v update-grub >/dev/null && command -v grub-script-check >/dev/null && [[ -f /boot/grub/grub.cfg && ! -L /boot/grub/grub.cfg ]]; then
    update-grub >/dev/null || record_failure "regenerate GRUB after policy rollback"
    grub-script-check /boot/grub/grub.cfg >/dev/null || record_failure "validate GRUB after policy rollback"
  else
    record_failure "GRUB recovery commands or configuration are unavailable"
  fi
fi
rm -f /etc/systemd/journald@gateway-vpn.conf.d/retention.conf || record_failure "remove owned journald policy"
rm -f /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf /etc/sysctl.d/90-gateway-vpn-ipv6.conf /usr/lib/sysusers.d/gateway-vpn.conf /usr/lib/tmpfiles.d/gateway-vpn.conf || record_failure "remove owned host policy"
rm -rf /etc/gateway-vpn || record_failure "remove owned Gateway config"
rm -f /opt/gateway-vpn/current /opt/gateway-vpn/recovery /opt/gateway-vpn/.current.new /opt/gateway-vpn/.recovery.new || record_failure "remove release pointers"
rm -rf "/opt/gateway-vpn/releases/v$VERSION" || record_failure "remove failed release"
UNIT_FILES=( \
  gateway-vpn.service gateway-vpn-watchdog.service gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service \
  gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn-network-recovery.service \
  gateway-vpn-network-rollback@.timer gateway-vpn-network-rollback@.service gateway-vpn-database-restore-boot.service gateway-vpn-database-restore-dispatch.service gateway-vpn-database-restore.service \
  gateway-vpn-power-cycle@.service \
  gateway-vpn-uninstall.service \
  gateway-vpn-database-restore-resume.service gateway-vpn-update.service gateway-vpn-update-recovery.service \
  gateway-vpn-update-resume.service gateway-vpn-update-finalize.service gateway-vpn-update-finalize.timer
)
if [[ ${GATEWAY_VPN_HOST_UPGRADE_INNER:-} != 1 ]]; then
  UNIT_FILES+=(gateway-vpn-host-upgrade-recovery.service)
fi
for unit_file in "${UNIT_FILES[@]}"; do
  rm -f "/etc/systemd/system/$unit_file" || record_failure "remove owned unit $unit_file"
done
rm -f /usr/libexec/gateway-vpn-uninstall-job || record_failure "remove owned uninstall guardian helper"
if [[ ${GATEWAY_VPN_HOST_UPGRADE_INNER:-} != 1 ]]; then
  rm -f /usr/libexec/gateway-vpn-host-upgrade-recovery || record_failure "remove owned host-upgrade recovery helper"
fi
rm -f /var/lib/gateway-vpn/install-report.json || record_failure "remove incomplete install report"
rm -f /run/gateway-vpn-install-authorized || record_failure "remove ephemeral service-start authorization"
rm -rf /var/lib/gateway-vpn-dnsmasq || record_failure "remove newly created dnsmasq state root"
if ((PRESERVE_STATE_ROOT == 0)); then
  rm -rf /var/lib/gateway-vpn || record_failure "remove newly created Gateway state root"
  rm -rf /var/log/gateway-vpn || record_failure "remove newly created Gateway log export root"
fi
if [[ ! -e /var/lib/gateway-vpn-host-upgrade/active && ! -L /var/lib/gateway-vpn-host-upgrade/active ]]; then
  rm -rf /var/lib/gateway-vpn-host-upgrade || record_failure "remove unused host-upgrade transaction root"
fi
reload_networkd_policy_if_active
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
