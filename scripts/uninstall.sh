#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077
APPLY=0
PURGE_DATA=0
while (($#)); do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --purge-data) PURGE_DATA=1; shift ;;
    -h|--help) echo "Usage: uninstall.sh [--purge-data] --apply"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if ((APPLY == 0)); then
  echo "Would stop/disable Gateway VPN units and remove program/config files. Runtime data is preserved unless --purge-data is supplied."
  exit 0
fi
[[ $EUID -eq 0 ]] || { echo "--apply requires root" >&2; exit 1; }
[[ -d /run/lock && ! -L /run/lock && $(stat -c '%u' /run/lock) == 0 ]] || { echo "Gateway runtime lock directory is unavailable" >&2; exit 1; }
LOCK_FILE=/run/lock/gateway-vpn-install.lock
if [[ ${GATEWAY_VPN_UNINSTALL_GUARDIAN:-} == 1 ]]; then
  [[ -e /proc/$$/fd/9 && $(readlink -f /proc/$$/fd/9) == "$LOCK_FILE" ]] || { echo "Inherited Gateway uninstall transaction lock is invalid" >&2; exit 1; }
else
  if [[ ! -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
    (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create Gateway transaction lock safely" >&2; exit 1; }
  fi
  [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" && $(stat -c '%u:%g:%a' "$LOCK_FILE") == "0:0:600" ]] || { echo "Gateway transaction lock ownership or mode is invalid" >&2; exit 1; }
  exec 9<>"$LOCK_FILE"
  flock -n 9 || { echo "Another Gateway VPN install/recovery/uninstall transaction is active" >&2; exit 1; }
fi

if [[ ${GATEWAY_VPN_UNINSTALL_GUARDIAN:-} == 1 ]]; then
  UPDATE_LIFECYCLE_CHECKER=/var/lib/gateway-vpn-uninstall/tooling/gateway-vpn
else
  UPDATE_LIFECYCLE_CHECKER=/opt/gateway-vpn/current/bin/gateway-vpn
fi

assert_no_update_restore_transaction() {
  local pending checker_mode
  [[ -f $UPDATE_LIFECYCLE_CHECKER && ! -L $UPDATE_LIFECYCLE_CHECKER ]] || { echo "Gateway update lifecycle checker is unavailable or unsafe" >&2; return 1; }
  checker_mode=$(stat -c '%u:%g:%a' "$UPDATE_LIFECYCLE_CHECKER")
  [[ $checker_mode == 0:0:700 || $checker_mode == 0:0:755 ]] || { echo "Gateway update lifecycle checker ownership or mode is unsafe" >&2; return 1; }
  for pending in /var/lib/gateway-vpn/update-staging/pending-update.json /var/lib/gateway-vpn-privileged/update-rollback/pending.json /var/lib/gateway-vpn/recovery/pending-restore.json; do
    [[ ! -e $pending && ! -L $pending ]] || { echo "Finish or discard the existing Gateway update/restore transaction before uninstall" >&2; return 1; }
  done
  "$UPDATE_LIFECYCLE_CHECKER" update-lifecycle-check >/dev/null || { echo "Finish or recover the active Gateway update before uninstall" >&2; return 1; }
}

[[ ! -e /var/lib/gateway-vpn-privileged/install-transactions/active && ! -L /var/lib/gateway-vpn-privileged/install-transactions/active ]] || { echo "Recover the interrupted Gateway install before uninstall" >&2; exit 1; }
[[ ! -e /var/lib/gateway-vpn-host-upgrade/active && ! -L /var/lib/gateway-vpn-host-upgrade/active ]] || { echo "Recover the interrupted Gateway host upgrade before uninstall" >&2; exit 1; }
assert_no_update_restore_transaction
if [[ -e /var/lib/gateway-vpn-uninstall/active || -L /var/lib/gateway-vpn-uninstall/active ]]; then
  [[ ${GATEWAY_VPN_UNINSTALL_GUARDIAN:-} == 1 ]] || { echo "A durable WebUI uninstall is active; let its guardian finish" >&2; exit 1; }
  [[ -f /var/lib/gateway-vpn-uninstall/active && ! -L /var/lib/gateway-vpn-uninstall/active && $(stat -c '%u:%g:%a' /var/lib/gateway-vpn-uninstall/active) == 0:0:600 ]] || { echo "Durable uninstall marker is unsafe" >&2; exit 1; }
elif [[ ${GATEWAY_VPN_UNINSTALL_GUARDIAN:-} == 1 ]]; then
  echo "Durable uninstall guardian has no active marker" >&2
  exit 1
fi

# Quarantine forwarding before the first service is stopped. This is the
# signed, installed boot ruleset and preserves only scoped management access.
if [[ -f /etc/gateway-vpn/nftables/boot.nft && ! -L /etc/gateway-vpn/nftables/boot.nft ]]; then
  [[ $(stat -c '%u:%a' /etc/gateway-vpn/nftables/boot.nft) == 0:640 ]] || { echo "Gateway boot firewall ownership or mode is unsafe" >&2; exit 1; }
  /usr/sbin/nft --check --file /etc/gateway-vpn/nftables/boot.nft
  /usr/sbin/nft --file /etc/gateway-vpn/nftables/boot.nft
  /usr/sbin/nft list chain inet gateway_vpn forward | grep -Fq 'gateway-vpn PATH_BLOCKED' || { echo "Gateway did not enter PATH_BLOCKED before uninstall" >&2; exit 1; }
fi

validate_marker_lan() {
  local cidr=$1 ip prefix a b c d octet ip_value host_mask network_value broadcast_value wg_start wg_end
  [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/(1[6-9]|2[0-9]|30)$ ]] || return 1
  ip=${cidr%/*}
  prefix=${cidr#*/}
  IFS=. read -r a b c d <<<"$ip"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
  a=$((10#$a)); b=$((10#$b)); c=$((10#$c)); d=$((10#$d))
  ((a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168))) || return 1
  ip_value=$(((a << 24) | (b << 16) | (c << 8) | d))
  host_mask=$(((1 << (32 - prefix)) - 1))
  network_value=$((ip_value & (0xFFFFFFFF ^ host_mask)))
  broadcast_value=$((network_value | host_mask))
  ((ip_value != network_value && ip_value != broadcast_value)) || return 1
  wg_start=$(((10 << 24) | (80 << 16)))
  wg_end=$((wg_start | 255))
  ! ((network_value <= wg_end && wg_start <= broadcast_value))
}

HAVE_COMPLETED_TRANSACTION=0
TRANSACTIONS_DIR=/var/lib/gateway-vpn-privileged/install-transactions
if [[ -e "$TRANSACTIONS_DIR" || -L "$TRANSACTIONS_DIR" ]]; then
  [[ -d "$TRANSACTIONS_DIR" && ! -L "$TRANSACTIONS_DIR" && $(stat -c '%u:%g:%a' "$TRANSACTIONS_DIR") == "0:0:700" ]] || { echo "Gateway install transaction directory is unsafe" >&2; exit 1; }
  LATEST_TRANSACTION=$(find "$TRANSACTIONS_DIR" -maxdepth 1 -type f -name 'completed-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1 {sub(/^[^ ]+ /, ""); print}')
  if [[ -n "$LATEST_TRANSACTION" ]]; then
    [[ -f "$LATEST_TRANSACTION" && ! -L "$LATEST_TRANSACTION" && $(stat -c '%u:%g:%a' "$LATEST_TRANSACTION") == "0:0:600" ]] || { echo "Completed Gateway install marker ownership or mode is unsafe" >&2; exit 1; }
    MARKER_BYTES=$(stat -c '%s' "$LATEST_TRANSACTION")
    [[ "$MARKER_BYTES" =~ ^[0-9]+$ && "$MARKER_BYTES" -gt 0 && "$MARKER_BYTES" -le 2048 ]] || { echo "Completed Gateway install marker size is unsafe" >&2; exit 1; }
    MARKER_FIELD_COUNT=$(wc -l <"$LATEST_TRANSACTION")
    [[ "$MARKER_FIELD_COUNT" == 14 || "$MARKER_FIELD_COUNT" == 16 || "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 ]] || { echo "Completed Gateway install marker field count is invalid" >&2; exit 1; }
    [[ $(grep -Ec '^(version|old_ipv4_forward|old_ipv6_all_disable|old_ipv6_default_disable|old_ipv6_all_forwarding|preserve_state_root|lan_interface|lan_members|lan_member_was_up|lan_address|preserve_lan_address|lan_was_up|ssh_was_enabled|ssh_was_active|ssh_socket_was_enabled|ssh_socket_was_active|log_reader_user|log_reader_was_member|boot_network_policy|grub_policy)=' "$LATEST_TRANSACTION") == "$MARKER_FIELD_COUNT" ]] || { echo "Completed Gateway install marker schema is invalid" >&2; exit 1; }
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
      [[ $(grep -c "^${marker_key}=" "$LATEST_TRANSACTION") == 1 ]] || { echo "Completed Gateway install marker contains duplicate or missing field: $marker_key" >&2; exit 1; }
    done
    VERSION=$(sed -n 's/^version=//p' "$LATEST_TRANSACTION")
    OLD_IPV4_FORWARD=$(sed -n 's/^old_ipv4_forward=//p' "$LATEST_TRANSACTION")
    OLD_IPV6_ALL_DISABLE=$(sed -n 's/^old_ipv6_all_disable=//p' "$LATEST_TRANSACTION")
    OLD_IPV6_DEFAULT_DISABLE=$(sed -n 's/^old_ipv6_default_disable=//p' "$LATEST_TRANSACTION")
    OLD_IPV6_ALL_FORWARDING=$(sed -n 's/^old_ipv6_all_forwarding=//p' "$LATEST_TRANSACTION")
    PRESERVE_STATE_ROOT=$(sed -n 's/^preserve_state_root=//p' "$LATEST_TRANSACTION")
    LAN_INTERFACE=$(sed -n 's/^lan_interface=//p' "$LATEST_TRANSACTION")
    LAN_MEMBERS=$(sed -n 's/^lan_members=//p' "$LATEST_TRANSACTION")
    LAN_MEMBER_WAS_UP=$(sed -n 's/^lan_member_was_up=//p' "$LATEST_TRANSACTION")
    LAN_ADDRESS=$(sed -n 's/^lan_address=//p' "$LATEST_TRANSACTION")
    PRESERVE_LAN_ADDRESS=$(sed -n 's/^preserve_lan_address=//p' "$LATEST_TRANSACTION")
    LAN_WAS_UP=$(sed -n 's/^lan_was_up=//p' "$LATEST_TRANSACTION")
    SSH_WAS_ENABLED=$(sed -n 's/^ssh_was_enabled=//p' "$LATEST_TRANSACTION")
    SSH_WAS_ACTIVE=$(sed -n 's/^ssh_was_active=//p' "$LATEST_TRANSACTION")
    BOOT_NETWORK_POLICY=keep
    GRUB_POLICY=keep
    LOG_READER_USER=""
    LOG_READER_WAS_MEMBER=1
    SSH_SOCKET_STATE_KNOWN=0
    SSH_SOCKET_WAS_ENABLED=0
    SSH_SOCKET_WAS_ACTIVE=0
    if [[ "$MARKER_FIELD_COUNT" == 16 || "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 ]]; then
      BOOT_NETWORK_POLICY=$(sed -n 's/^boot_network_policy=//p' "$LATEST_TRANSACTION")
      GRUB_POLICY=$(sed -n 's/^grub_policy=//p' "$LATEST_TRANSACTION")
    fi
    if [[ "$MARKER_FIELD_COUNT" == 18 || "$MARKER_FIELD_COUNT" == 20 ]]; then
      LOG_READER_USER=$(sed -n 's/^log_reader_user=//p' "$LATEST_TRANSACTION")
      LOG_READER_WAS_MEMBER=$(sed -n 's/^log_reader_was_member=//p' "$LATEST_TRANSACTION")
    fi
    if [[ "$MARKER_FIELD_COUNT" == 20 ]]; then
      SSH_SOCKET_STATE_KNOWN=1
      SSH_SOCKET_WAS_ENABLED=$(sed -n 's/^ssh_socket_was_enabled=//p' "$LATEST_TRANSACTION")
      SSH_SOCKET_WAS_ACTIVE=$(sed -n 's/^ssh_socket_was_active=//p' "$LATEST_TRANSACTION")
    fi
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ && "$OLD_IPV4_FORWARD" =~ ^[01]$ && "$OLD_IPV6_ALL_DISABLE" =~ ^[01]$ && "$OLD_IPV6_DEFAULT_DISABLE" =~ ^[01]$ && "$OLD_IPV6_ALL_FORWARDING" =~ ^[01]$ && "$PRESERVE_STATE_ROOT" =~ ^[01]$ && "$LAN_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ && "$PRESERVE_LAN_ADDRESS" =~ ^[01]$ && "$LAN_WAS_UP" =~ ^[01]$ && "$SSH_WAS_ENABLED" =~ ^[01]$ && "$SSH_WAS_ACTIVE" =~ ^[01]$ ]] && validate_marker_lan "$LAN_ADDRESS" || { echo "Completed Gateway install marker values are invalid" >&2; exit 1; }
    [[ "$BOOT_NETWORK_POLICY" == gateway-nonblocking || "$BOOT_NETWORK_POLICY" == keep ]] || { echo "Completed Gateway boot-network policy is invalid" >&2; exit 1; }
    [[ "$GRUB_POLICY" == automatic-hidden || "$GRUB_POLICY" == menu-5s || "$GRUB_POLICY" == keep ]] || { echo "Completed Gateway GRUB policy is invalid" >&2; exit 1; }
    [[ -z "$LOG_READER_USER" || "$LOG_READER_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$LOG_READER_USER" != root && "$LOG_READER_WAS_MEMBER" =~ ^[01]$ ]] || { echo "Completed Gateway log-reader values are invalid" >&2; exit 1; }
    ((SSH_SOCKET_STATE_KNOWN == 0)) || [[ "$SSH_SOCKET_WAS_ENABLED" =~ ^[01]$ && "$SSH_SOCKET_WAS_ACTIVE" =~ ^[01]$ ]] || { echo "Completed Gateway OpenSSH socket values are invalid" >&2; exit 1; }
    if [[ -n "$LAN_MEMBERS" ]]; then
      [[ "$LAN_INTERFACE" == gateway-vpn-lan && "$LAN_MEMBERS" =~ ^[A-Za-z0-9_.:-]{1,15}(,[A-Za-z0-9_.:-]{1,15}){0,15}$ && "$LAN_MEMBER_WAS_UP" =~ ^[01](,[01]){0,15}$ ]] || { echo "Completed Gateway LAN bridge marker values are invalid" >&2; exit 1; }
      IFS=, read -r -a LAN_MEMBER_NAMES <<<"$LAN_MEMBERS"
      IFS=, read -r -a LAN_MEMBER_WAS_UP_VALUES <<<"$LAN_MEMBER_WAS_UP"
      ((${#LAN_MEMBER_NAMES[@]} == ${#LAN_MEMBER_WAS_UP_VALUES[@]})) || { echo "Completed Gateway LAN bridge marker lengths differ" >&2; exit 1; }
    else
      [[ -z "$LAN_MEMBER_WAS_UP" ]] || { echo "Completed Gateway has member state without members" >&2; exit 1; }
      LAN_MEMBER_NAMES=()
      LAN_MEMBER_WAS_UP_VALUES=()
    fi
    HAVE_COMPLETED_TRANSACTION=1
  fi
fi

restore_systemd_unit_state() {
  local unit=$1 desired_enabled=$2 desired_active=$3 label=$4 load_state
  load_state=$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)
  if [[ "$load_state" == not-found ]]; then
    ((desired_enabled == 0 && desired_active == 0)) && return 0
    echo "$label unit is unavailable during uninstall" >&2
    return 1
  fi
  if ((desired_enabled)); then
    systemctl enable "$unit" >/dev/null
    systemctl is-enabled --quiet "$unit"
  else
    systemctl disable "$unit" >/dev/null
    ! systemctl is-enabled --quiet "$unit"
  fi
  if ((desired_active)); then
    systemctl start "$unit" >/dev/null
    systemctl is-active --quiet "$unit"
  else
    systemctl stop "$unit" >/dev/null
    ! systemctl is-active --quiet "$unit"
  fi
}

# Removing Gateway-owned .network files does not require starting a network
# manager that is currently stopped (or not installed). Starting it here could
# take ownership of unrelated interfaces while an uninstall is restoring the
# pre-install host. If networkd is already active, however, the live policy must
# be reloaded and any failure remains fatal under set -e.
reload_networkd_policy_if_active() {
  if systemctl is-active --quiet systemd-networkd.service; then
    networkctl reload
  else
    echo "systemd-networkd is not active; skipped live policy reload after removing Gateway-owned files"
  fi
}

# Close the only unprivileged API that can create a new staged update, then
# repeat the lifecycle check while the common root lock is still held. A
# conflicting request detected in this narrow window aborts before unit files
# or persistent host state are removed.
CONTROL_PLANE_WAS_ACTIVE=0
systemctl is-active --quiet gateway-vpn.service && CONTROL_PLANE_WAS_ACTIVE=1
systemctl stop gateway-vpn.service 2>/dev/null || true
if ! assert_no_update_restore_transaction; then
  if ((CONTROL_PLANE_WAS_ACTIVE)); then
    systemctl start gateway-vpn.service >/dev/null 2>&1 || true
  fi
  exit 1
fi
systemctl disable --now gateway-vpn.service gateway-vpn-watchdog.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn-update-finalize.timer gateway-vpn-update-finalize.service gateway-vpn-update-rollback.service gateway-vpn-update-resume.service gateway-vpn-update.service gateway-vpn-update-recovery.service gateway-vpn-database-restore-boot.service gateway-vpn-network-recovery.service gateway-vpn-database-restore-dispatch.service gateway-vpn-database-restore.service gateway-vpn-database-restore-resume.service gateway-vpn-firewall-guard.service gateway-vpn-firewall.service gateway-vpn-install-recovery.service gateway-vpn-host-upgrade-recovery.service 2>/dev/null || true
systemctl stop 'gateway-vpn-power-cycle@*.service' 2>/dev/null || true
systemctl stop 'gateway-vpn-network-rollback@*.timer' 'gateway-vpn-network-rollback@*.service' 2>/dev/null || true
if [[ ${GATEWAY_VPN_UNINSTALL_GUARDIAN:-} != 1 ]]; then
  systemctl disable --now gateway-vpn-uninstall.service 2>/dev/null || true
fi
rm -f /etc/systemd/system/gateway-vpn.service /etc/systemd/system/gateway-vpn-watchdog.service /etc/systemd/system/gateway-vpn-mihomo.service /etc/systemd/system/gateway-vpn-dnsmasq.service /etc/systemd/system/gateway-vpn-firewall.service
rm -f /etc/systemd/system/gateway-vpn-network-broker.socket /etc/systemd/system/gateway-vpn-network-broker.service /etc/systemd/system/gateway-vpn-network-recovery.service /etc/systemd/system/gateway-vpn-network-rollback@.timer /etc/systemd/system/gateway-vpn-network-rollback@.service /etc/systemd/system/gateway-vpn-database-restore-boot.service /etc/systemd/system/gateway-vpn-database-restore-dispatch.service /etc/systemd/system/gateway-vpn-database-restore.service /etc/systemd/system/gateway-vpn-database-restore-resume.service /etc/systemd/system/gateway-vpn-firewall-guard.service
rm -f /etc/systemd/system/gateway-vpn-update.service /etc/systemd/system/gateway-vpn-update-rollback.service /etc/systemd/system/gateway-vpn-update-recovery.service /etc/systemd/system/gateway-vpn-update-resume.service /etc/systemd/system/gateway-vpn-update-finalize.service /etc/systemd/system/gateway-vpn-update-finalize.timer
rm -f /etc/systemd/system/gateway-vpn-power-cycle@.service
rm -f /etc/systemd/system/gateway-vpn-host-upgrade-recovery.service
if [[ ${GATEWAY_VPN_UNINSTALL_GUARDIAN:-} != 1 ]]; then
  rm -f /etc/systemd/system/gateway-vpn-uninstall.service /usr/libexec/gateway-vpn-uninstall-job
fi
rm -f /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf /etc/sysctl.d/90-gateway-vpn-ipv6.conf /usr/lib/sysusers.d/gateway-vpn.conf /usr/lib/tmpfiles.d/gateway-vpn.conf
rm -f /etc/systemd/journald@gateway-vpn.conf.d/retention.conf
rm -f /etc/systemd/network/05-gateway-vpn-lan.network /etc/systemd/network/05-gateway-vpn-lan.netdev /etc/systemd/network/06-gateway-vpn-lan-*.network /etc/systemd/network/80-gateway-vpn-hilink.network
rm -f /etc/systemd/system/systemd-networkd-wait-online.service.d/gateway-vpn.conf
GRUB_POLICY_REMOVED=0
if [[ -f /etc/default/grub.d/90-gateway-vpn.cfg && ! -L /etc/default/grub.d/90-gateway-vpn.cfg ]]; then
  rm -f /etc/default/grub.d/90-gateway-vpn.cfg
  GRUB_POLICY_REMOVED=1
elif [[ -e /etc/default/grub.d/90-gateway-vpn.cfg || -L /etc/default/grub.d/90-gateway-vpn.cfg ]]; then
  echo "Unsafe Gateway GRUB policy path requires manual inspection" >&2
  exit 1
fi
# A guardian retry may begin after the owned drop-in was removed but before
# update-grub completed. The durable install marker, not current file presence,
# is the authoritative reason to regenerate the boot projection.
if ((HAVE_COMPLETED_TRANSACTION)) && [[ "$GRUB_POLICY" != keep ]]; then
  GRUB_POLICY_REMOVED=1
fi
if /usr/sbin/nft list table inet gateway_vpn >/dev/null 2>&1; then
  /usr/sbin/nft delete table inet gateway_vpn
fi
if ip link show dev wg-mgmt >/dev/null 2>&1; then
  ip link delete dev wg-mgmt
fi
if ip link show dev wg-ingress >/dev/null 2>&1; then
  ip link delete dev wg-ingress
fi

if ((HAVE_COMPLETED_TRANSACTION)); then
  sysctl -q -w "net.ipv4.ip_forward=$OLD_IPV4_FORWARD"
  sysctl -q -w "net.ipv6.conf.all.disable_ipv6=$OLD_IPV6_ALL_DISABLE"
  sysctl -q -w "net.ipv6.conf.default.disable_ipv6=$OLD_IPV6_DEFAULT_DISABLE"
  sysctl -q -w "net.ipv6.conf.all.forwarding=$OLD_IPV6_ALL_FORWARDING"
  if ip link show dev "$LAN_INTERFACE" >/dev/null 2>&1; then
    if ((PRESERVE_LAN_ADDRESS == 0)) && ip -o -4 address show dev "$LAN_INTERFACE" scope global | awk '{print $4}' | grep -Fxq "$LAN_ADDRESS"; then
      ip -4 address del "$LAN_ADDRESS" dev "$LAN_INTERFACE"
    fi
    ((LAN_WAS_UP)) || ip link set dev "$LAN_INTERFACE" down
  fi
  for index in "${!LAN_MEMBER_NAMES[@]}"; do
    member=${LAN_MEMBER_NAMES[$index]}
    if ip link show dev "$member" >/dev/null 2>&1; then
      ip link set dev "$member" nomaster
      ((${LAN_MEMBER_WAS_UP_VALUES[$index]})) || ip link set dev "$member" down
    fi
  done
  if ((${#LAN_MEMBER_NAMES[@]})) && ip link show dev "$LAN_INTERFACE" >/dev/null 2>&1; then
    ip link delete dev "$LAN_INTERFACE" type bridge
  fi
  if ((SSH_SOCKET_STATE_KNOWN)); then
    restore_systemd_unit_state ssh.socket "$SSH_SOCKET_WAS_ENABLED" "$SSH_SOCKET_WAS_ACTIVE" "OpenSSH socket"
  fi
  restore_systemd_unit_state ssh.service "$SSH_WAS_ENABLED" "$SSH_WAS_ACTIVE" "OpenSSH service"
  if [[ -n "$LOG_READER_USER" && "$LOG_READER_WAS_MEMBER" == 0 ]] &&
     getent group gateway-vpn-log-readers >/dev/null 2>&1 &&
     id -nG "$LOG_READER_USER" 2>/dev/null | tr ' ' '\n' | grep -Fxq gateway-vpn-log-readers; then
    gpasswd -d "$LOG_READER_USER" gateway-vpn-log-readers >/dev/null
  fi
fi
rm -rf /etc/gateway-vpn /opt/gateway-vpn
rm -f /var/lib/gateway-vpn/install-report.json
rm -rf /var/lib/gateway-vpn-dnsmasq
rm -f /run/gateway-vpn-install-authorized
rm -f /etc/systemd/system/gateway-vpn-install-recovery.service /usr/libexec/gateway-vpn-install-recovery /usr/libexec/gateway-vpn-host-upgrade-recovery
if ((PURGE_DATA)); then
  rm -rf /var/lib/gateway-vpn
  rm -rf /var/lib/gateway-vpn-privileged
  rm -rf /var/lib/gateway-vpn-host-upgrade
  rm -rf /var/log/gateway-vpn
fi
reload_networkd_policy_if_active
systemctl daemon-reload
if ((GRUB_POLICY_REMOVED)); then
  command -v update-grub >/dev/null && command -v grub-script-check >/dev/null || { echo "Cannot regenerate GRUB after uninstall" >&2; exit 1; }
  update-grub
  grub-script-check /boot/grub/grub.cfg >/dev/null
fi
echo "Gateway VPN uninstalled. Reboot or apply the desired host firewall/network configuration explicitly."
