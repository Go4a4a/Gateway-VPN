#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

APPLY=0
PURGE_KEYS=0
while (($#)); do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --purge-keys) PURGE_KEYS=1; shift ;;
    -h|--help) echo "Usage: uninstall-vps.sh [--purge-keys] --apply"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
if ((APPLY == 0)); then
  echo "Would stop Gateway VPN VPS services and remove only owned nftables/program/sysctl/unit files. VPS Hub settings, backups, administrator, TLS identity, and WireGuard keys are preserved unless --purge-keys is supplied."
  exit 0
fi
[[ $EUID -eq 0 ]] || { echo "VPS uninstall requires root" >&2; exit 1; }
[[ -d /run/lock && ! -L /run/lock && $(stat -c '%u' /run/lock) == 0 ]] || { echo "VPS runtime lock directory is unavailable" >&2; exit 1; }
LOCK_FILE=/run/lock/gateway-vpn-vps-install.lock
if [[ ! -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
  (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create VPS transaction lock safely" >&2; exit 1; }
fi
[[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" && $(stat -c '%u:%g:%a' "$LOCK_FILE") == "0:0:600" ]] || { echo "VPS transaction lock ownership or mode is invalid" >&2; exit 1; }
exec 9<>"$LOCK_FILE"
flock -n 9 || { echo "Another Gateway VPN VPS install/recovery/uninstall transaction is active" >&2; exit 1; }
[[ ! -e /var/lib/gateway-vpn-vps/install-transactions/active && ! -L /var/lib/gateway-vpn-vps/install-transactions/active ]] || { echo "Recover the interrupted VPS install before uninstall" >&2; exit 1; }
[[ ! -e /var/lib/gateway-vpn-vps/agent/restore.trigger && ! -L /var/lib/gateway-vpn-vps/agent/restore.trigger ]] || { echo "Finish or discard the pending VPS restore before uninstall" >&2; exit 1; }
[[ ! -e /var/lib/gateway-vpn-vps/agent/fabric.trigger && ! -L /var/lib/gateway-vpn-vps/agent/fabric.trigger ]] || { echo "Finish the pending VPS Management Fabric apply before uninstall" >&2; exit 1; }
[[ ! -e /var/lib/gateway-vpn-vps/agent/update.trigger && ! -L /var/lib/gateway-vpn-vps/agent/update.trigger ]] || { echo "Finish the pending VPS update before uninstall" >&2; exit 1; }
if [[ -d /var/lib/gateway-vpn-vps-privileged/restore-transactions ]] && find /var/lib/gateway-vpn-vps-privileged/restore-transactions -maxdepth 1 -type f -name '*.json' -print -quit | grep -q .; then
  echo "Recover the interrupted VPS restore before uninstall" >&2
  exit 1
fi
if [[ -d /var/lib/gateway-vpn-vps-privileged/fabric ]] && find /var/lib/gateway-vpn-vps-privileged/fabric -maxdepth 1 -type f \( -name 'transaction.json' -o -name 'restore-reconcile.json' \) -print -quit | grep -q .; then
  echo "Recover the pending VPS Management Fabric transaction before uninstall" >&2
  exit 1
fi
if [[ -e /var/lib/gateway-vpn-vps-privileged/update-transactions/active.json || -L /var/lib/gateway-vpn-vps-privileged/update-transactions/active.json ]]; then
  echo "Recover or finalize the active VPS update before uninstall" >&2
  exit 1
fi

systemctl disable --now gateway-vpn-vps-update.path gateway-vpn-vps-update-finalize.timer gateway-vpn-vps-update.service gateway-vpn-vps-update-finalize.service gateway-vpn-vps-update-recovery.service gateway-vpn-vps-restore.path gateway-vpn-vps-fabric.path gateway-vpn-vps-fabric-watchdog.timer gateway-vpn-vps-fabric-watchdog.service gateway-vpn-vps-operations.timer gateway-vpn-vps-operations.service gateway-vpn-vps-agent.service gateway-vpn-vps-restore.service gateway-vpn-vps-fabric.service gateway-vpn-vps-restore-recovery.service gateway-vpn-vps-fabric-recovery.service wg-quick@wg-mgmt.service gateway-vpn-vps-firewall.service gateway-vpn-vps-install-recovery.service >/dev/null 2>&1 || true
if /usr/sbin/nft list table inet gateway_vpn_vps >/dev/null 2>&1; then
  /usr/sbin/nft delete table inet gateway_vpn_vps
fi

LATEST_TRANSACTION=$(find /var/lib/gateway-vpn-vps/install-transactions -maxdepth 1 -type f -name 'completed-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1 {sub(/^[^ ]+ /, ""); print}')
if [[ -n "$LATEST_TRANSACTION" && -f "$LATEST_TRANSACTION" && ! -L "$LATEST_TRANSACTION" ]]; then
  OLD_FORWARD=$(sed -n 's/^old_ipv4_forward=//p' "$LATEST_TRANSACTION")
  OLD_IPV6_ALL=$(sed -n 's/^old_ipv6_all_forwarding=//p' "$LATEST_TRANSACTION")
  OLD_IPV6_DEFAULT=$(sed -n 's/^old_ipv6_default_forwarding=//p' "$LATEST_TRANSACTION")
  if [[ "$OLD_FORWARD" =~ ^[01]$ && "$OLD_IPV6_ALL" =~ ^[01]$ && "$OLD_IPV6_DEFAULT" =~ ^[01]$ ]]; then
    sysctl -q -w "net.ipv4.ip_forward=$OLD_FORWARD"
    sysctl -q -w "net.ipv6.conf.all.forwarding=$OLD_IPV6_ALL"
    sysctl -q -w "net.ipv6.conf.default.forwarding=$OLD_IPV6_DEFAULT"
  fi
fi

rm -f /etc/sysctl.d/90-gateway-vpn-vps.conf
rm -f /etc/systemd/system/gateway-vpn-vps-firewall.service
rm -f /etc/systemd/system/gateway-vpn-vps-agent.service
rm -f /etc/systemd/system/gateway-vpn-vps-restore.service
rm -f /etc/systemd/system/gateway-vpn-vps-restore.path
rm -f /etc/systemd/system/gateway-vpn-vps-restore-recovery.service
rm -f /etc/systemd/system/gateway-vpn-vps-fabric.service
rm -f /etc/systemd/system/gateway-vpn-vps-fabric.path
rm -f /etc/systemd/system/gateway-vpn-vps-fabric-recovery.service
rm -f /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.service
rm -f /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.timer
rm -f /etc/systemd/system/gateway-vpn-vps-operations.service
rm -f /etc/systemd/system/gateway-vpn-vps-operations.timer
rm -f /etc/systemd/system/gateway-vpn-vps-update.service
rm -f /etc/systemd/system/gateway-vpn-vps-update.path
rm -f /etc/systemd/system/gateway-vpn-vps-update-recovery.service
rm -f /etc/systemd/system/gateway-vpn-vps-update-finalize.service
rm -f /etc/systemd/system/gateway-vpn-vps-update-finalize.timer
rm -f /etc/systemd/system/gateway-vpn-vps-install-recovery.service
rm -rf /etc/systemd/system/wg-quick@wg-mgmt.service.d
rm -rf /etc/gateway-vpn-vps
rm -rf /opt/gateway-vpn-vps
rm -f /usr/libexec/gateway-vpn-vps-install-recovery
rm -f /run/gateway-vpn-vps-install-authorized
rm -f /run/gateway-vpn-vps-update-live
rm -rf /var/lib/gateway-vpn-vps-privileged
rm -f /var/lib/gateway-vpn-vps/agent/update.trigger /var/lib/gateway-vpn-vps/agent/update-status.json
rm -rf /var/lib/gateway-vpn-vps/agent/update-staging
if ((PURGE_KEYS)); then
  rm -f /etc/wireguard/wg-mgmt.conf
  rm -rf /var/lib/gateway-vpn-vps
  if getent passwd gateway-vpn-vps >/dev/null; then
    userdel gateway-vpn-vps
  fi
  if getent group gateway-vpn-vps >/dev/null; then
    groupdel gateway-vpn-vps
  fi
  echo "Gateway VPN VPS uninstalled; VPS Hub settings, backups, administrator, TLS identity, and WireGuard keys were purged."
else
  echo "Gateway VPN VPS uninstalled; VPS Hub settings/backups/account and /etc/wireguard/wg-mgmt.conf are preserved for reinstall."
fi
systemctl daemon-reload
