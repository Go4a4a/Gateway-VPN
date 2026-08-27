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
if [[ ! -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
  (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create Gateway transaction lock safely" >&2; exit 1; }
fi
[[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" && $(stat -c '%u:%g:%a' "$LOCK_FILE") == "0:0:600" ]] || { echo "Gateway transaction lock ownership or mode is invalid" >&2; exit 1; }
exec 9<>"$LOCK_FILE"
flock -n 9 || { echo "Another Gateway VPN install/recovery/uninstall transaction is active" >&2; exit 1; }
[[ ! -e /var/lib/gateway-vpn-privileged/install-transactions/active && ! -L /var/lib/gateway-vpn-privileged/install-transactions/active ]] || { echo "Recover the interrupted Gateway install before uninstall" >&2; exit 1; }

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
    [[ "$MARKER_BYTES" =~ ^[0-9]+$ && "$MARKER_BYTES" -gt 0 && "$MARKER_BYTES" -le 1024 ]] || { echo "Completed Gateway install marker size is unsafe" >&2; exit 1; }
    [[ $(wc -l <"$LATEST_TRANSACTION") == 14 ]] || { echo "Completed Gateway install marker field count is invalid" >&2; exit 1; }
    [[ $(grep -Ec '^(version|old_ipv4_forward|old_ipv6_all_disable|old_ipv6_default_disable|old_ipv6_all_forwarding|preserve_state_root|lan_interface|lan_members|lan_member_was_up|lan_address|preserve_lan_address|lan_was_up|ssh_was_enabled|ssh_was_active)=' "$LATEST_TRANSACTION") == 14 ]] || { echo "Completed Gateway install marker schema is invalid" >&2; exit 1; }
    for marker_key in version old_ipv4_forward old_ipv6_all_disable old_ipv6_default_disable old_ipv6_all_forwarding preserve_state_root lan_interface lan_members lan_member_was_up lan_address preserve_lan_address lan_was_up ssh_was_enabled ssh_was_active; do
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
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ && "$OLD_IPV4_FORWARD" =~ ^[01]$ && "$OLD_IPV6_ALL_DISABLE" =~ ^[01]$ && "$OLD_IPV6_DEFAULT_DISABLE" =~ ^[01]$ && "$OLD_IPV6_ALL_FORWARDING" =~ ^[01]$ && "$PRESERVE_STATE_ROOT" =~ ^[01]$ && "$LAN_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ && "$PRESERVE_LAN_ADDRESS" =~ ^[01]$ && "$LAN_WAS_UP" =~ ^[01]$ && "$SSH_WAS_ENABLED" =~ ^[01]$ && "$SSH_WAS_ACTIVE" =~ ^[01]$ ]] && validate_marker_lan "$LAN_ADDRESS" || { echo "Completed Gateway install marker values are invalid" >&2; exit 1; }
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
systemctl disable --now gateway-vpn.service gateway-vpn-watchdog.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn-update-finalize.timer gateway-vpn-update-finalize.service gateway-vpn-update-resume.service gateway-vpn-update.service gateway-vpn-update-recovery.service gateway-vpn-database-restore-boot.service gateway-vpn-network-recovery.service gateway-vpn-database-restore-dispatch.service gateway-vpn-database-restore.service gateway-vpn-database-restore-resume.service gateway-vpn-firewall-guard.service gateway-vpn-firewall.service gateway-vpn-install-recovery.service 2>/dev/null || true
systemctl stop 'gateway-vpn-network-rollback@*.timer' 'gateway-vpn-network-rollback@*.service' 2>/dev/null || true
rm -f /etc/systemd/system/gateway-vpn.service /etc/systemd/system/gateway-vpn-watchdog.service /etc/systemd/system/gateway-vpn-mihomo.service /etc/systemd/system/gateway-vpn-dnsmasq.service /etc/systemd/system/gateway-vpn-firewall.service
rm -f /etc/systemd/system/gateway-vpn-network-broker.socket /etc/systemd/system/gateway-vpn-network-broker.service /etc/systemd/system/gateway-vpn-network-recovery.service /etc/systemd/system/gateway-vpn-network-rollback@.timer /etc/systemd/system/gateway-vpn-network-rollback@.service /etc/systemd/system/gateway-vpn-database-restore-boot.service /etc/systemd/system/gateway-vpn-database-restore-dispatch.service /etc/systemd/system/gateway-vpn-database-restore.service /etc/systemd/system/gateway-vpn-database-restore-resume.service /etc/systemd/system/gateway-vpn-firewall-guard.service
rm -f /etc/systemd/system/gateway-vpn-update.service /etc/systemd/system/gateway-vpn-update-recovery.service /etc/systemd/system/gateway-vpn-update-resume.service /etc/systemd/system/gateway-vpn-update-finalize.service /etc/systemd/system/gateway-vpn-update-finalize.timer
rm -f /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf /etc/sysctl.d/90-gateway-vpn-ipv6.conf /usr/lib/sysusers.d/gateway-vpn.conf /usr/lib/tmpfiles.d/gateway-vpn.conf
rm -f /etc/systemd/journald@gateway-vpn.conf.d/retention.conf
rm -f /etc/systemd/network/05-gateway-vpn-lan.network /etc/systemd/network/05-gateway-vpn-lan.netdev /etc/systemd/network/06-gateway-vpn-lan-*.network /etc/systemd/network/80-gateway-vpn-hilink.network
if /usr/sbin/nft list table inet gateway_vpn >/dev/null 2>&1; then
  /usr/sbin/nft delete table inet gateway_vpn
fi
if ip link show dev wg-mgmt >/dev/null 2>&1; then
  ip link delete dev wg-mgmt
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
  ((SSH_WAS_ACTIVE)) || systemctl stop ssh.service >/dev/null 2>&1 || true
  ((SSH_WAS_ENABLED)) || systemctl disable ssh.service >/dev/null 2>&1 || true
fi
rm -rf /etc/gateway-vpn /opt/gateway-vpn
rm -f /var/lib/gateway-vpn/install-report.json
rm -rf /var/lib/gateway-vpn-dnsmasq
rm -f /run/gateway-vpn-install-authorized
rm -f /etc/systemd/system/gateway-vpn-install-recovery.service /usr/libexec/gateway-vpn-install-recovery
if ((PURGE_DATA)); then
  [[ -f /var/lib/gateway-vpn/state.db ]] && cp --reflink=auto --sparse=always /var/lib/gateway-vpn/state.db "/root/gateway-vpn-state-$(date -u +%Y%m%dT%H%M%SZ).db"
  rm -rf /var/lib/gateway-vpn
  rm -rf /var/lib/gateway-vpn-privileged
fi
networkctl reload
systemctl daemon-reload
echo "Gateway VPN uninstalled. Reboot or apply the desired host firewall/network configuration explicitly."
