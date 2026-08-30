#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

MARKER=/var/lib/gateway-vpn-vps/install-transactions/active
if [[ ! -e "$MARKER" && ! -L "$MARKER" ]]; then
  exit 0
fi
[[ -f "$MARKER" && ! -L "$MARKER" ]] || { echo "Gateway VPN VPS recovery marker path is unsafe" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "VPS install recovery requires root" >&2; exit 1; }
[[ -d /run/lock && ! -L /run/lock && $(stat -c '%u' /run/lock) == 0 ]] || { echo "VPS runtime lock directory is unavailable" >&2; exit 1; }
LOCK_FILE=/run/lock/gateway-vpn-vps-install.lock
if [[ ! -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
  (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create VPS transaction lock safely" >&2; exit 1; }
fi
[[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" && $(stat -c '%u:%g:%a' "$LOCK_FILE") == "0:0:600" ]] || { echo "VPS transaction lock ownership or mode is invalid" >&2; exit 1; }
exec 9<>"$LOCK_FILE"
flock -n 9 || { echo "Another Gateway VPN VPS install/recovery/uninstall transaction is active" >&2; exit 1; }
[[ -f "$MARKER" && ! -L "$MARKER" ]] || { echo "Gateway VPN VPS recovery marker path changed while acquiring the lock" >&2; exit 1; }
[[ $(stat -c '%u:%g:%a' "$MARKER") == "0:0:600" ]] || { echo "Gateway VPN VPS recovery marker ownership or mode is invalid" >&2; exit 1; }
MARKER_BYTES=$(stat -c '%s' "$MARKER")
[[ "$MARKER_BYTES" =~ ^[0-9]+$ && "$MARKER_BYTES" -gt 0 && "$MARKER_BYTES" -le 1024 ]] || { echo "Gateway VPN VPS recovery marker size is invalid" >&2; exit 1; }
[[ $(wc -l <"$MARKER") == 6 ]] || { echo "Gateway VPN VPS recovery marker field count is invalid" >&2; exit 1; }
[[ $(grep -Ec '^(version|old_ipv4_forward|old_ipv6_all_forwarding|old_ipv6_default_forwarding|preserve_wg_config|preserve_agent_user)=' "$MARKER") == 6 ]] || { echo "Gateway VPN VPS recovery marker schema is invalid" >&2; exit 1; }
for marker_key in version old_ipv4_forward old_ipv6_all_forwarding old_ipv6_default_forwarding preserve_wg_config preserve_agent_user; do
  [[ $(grep -c "^${marker_key}=" "$MARKER") == 1 ]] || { echo "Gateway VPN VPS recovery marker contains duplicate or missing field: $marker_key" >&2; exit 1; }
done
VERSION=$(sed -n 's/^version=//p' "$MARKER")
OLD_FORWARD=$(sed -n 's/^old_ipv4_forward=//p' "$MARKER")
OLD_IPV6_ALL=$(sed -n 's/^old_ipv6_all_forwarding=//p' "$MARKER")
OLD_IPV6_DEFAULT=$(sed -n 's/^old_ipv6_default_forwarding=//p' "$MARKER")
PRESERVE_WG_CONFIG=$(sed -n 's/^preserve_wg_config=//p' "$MARKER")
PRESERVE_AGENT_USER=$(sed -n 's/^preserve_agent_user=//p' "$MARKER")
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ && "$OLD_FORWARD" =~ ^[01]$ && "$OLD_IPV6_ALL" =~ ^[01]$ && "$OLD_IPV6_DEFAULT" =~ ^[01]$ && "$PRESERVE_WG_CONFIG" =~ ^[01]$ && "$PRESERVE_AGENT_USER" =~ ^[01]$ ]] || {
  echo "Gateway VPN VPS recovery marker is invalid; refusing path-derived cleanup" >&2
  exit 1
}

FAILED=0
record_failure() {
  echo "VPS install recovery step failed: $1" >&2
  FAILED=1
}

systemctl disable --now gateway-vpn-vps-restore.path gateway-vpn-vps-fabric.path gateway-vpn-vps-fabric-watchdog.timer gateway-vpn-vps-fabric-watchdog.service gateway-vpn-vps-agent.service gateway-vpn-vps-restore.service gateway-vpn-vps-fabric.service gateway-vpn-vps-restore-recovery.service gateway-vpn-vps-fabric-recovery.service wg-quick@wg-mgmt.service gateway-vpn-vps-firewall.service >/dev/null 2>&1 || true
systemctl is-active --quiet gateway-vpn-vps-agent.service && record_failure "VPS Agent remained active"
systemctl is-active --quiet gateway-vpn-vps-restore.path && record_failure "VPS restore watcher remained active"
systemctl is-active --quiet gateway-vpn-vps-fabric.path && record_failure "VPS fabric watcher remained active"
systemctl is-active --quiet wg-quick@wg-mgmt.service && record_failure "wg-mgmt remained active"
systemctl is-active --quiet gateway-vpn-vps-firewall.service && record_failure "owned firewall remained active"
if /usr/sbin/nft list table inet gateway_vpn_vps >/dev/null 2>&1; then
  /usr/sbin/nft delete table inet gateway_vpn_vps || record_failure "delete owned nftables table"
fi
/usr/sbin/nft list table inet gateway_vpn_vps >/dev/null 2>&1 && record_failure "owned nftables table still exists"
sysctl -q -w "net.ipv4.ip_forward=$OLD_FORWARD" || record_failure "restore IPv4 forwarding"
sysctl -q -w "net.ipv6.conf.all.forwarding=$OLD_IPV6_ALL" || record_failure "restore IPv6 all forwarding"
sysctl -q -w "net.ipv6.conf.default.forwarding=$OLD_IPV6_DEFAULT" || record_failure "restore IPv6 default forwarding"
[[ $(cat /proc/sys/net/ipv4/ip_forward) == "$OLD_FORWARD" ]] || record_failure "verify IPv4 forwarding"
[[ $(cat /proc/sys/net/ipv6/conf/all/forwarding) == "$OLD_IPV6_ALL" ]] || record_failure "verify IPv6 all forwarding"
[[ $(cat /proc/sys/net/ipv6/conf/default/forwarding) == "$OLD_IPV6_DEFAULT" ]] || record_failure "verify IPv6 default forwarding"
if ((PRESERVE_WG_CONFIG == 0)); then
  rm -f /etc/wireguard/wg-mgmt.conf || record_failure "remove generated WireGuard config"
  [[ ! -e /etc/wireguard/wg-mgmt.conf && ! -L /etc/wireguard/wg-mgmt.conf ]] || record_failure "verify generated WireGuard config removal"
else
  [[ -f /etc/wireguard/wg-mgmt.conf && ! -L /etc/wireguard/wg-mgmt.conf ]] || record_failure "preserved WireGuard config is missing"
fi
rm -f /etc/wireguard/.gateway-vpn-wg-mgmt.conf.tmp || record_failure "remove WireGuard temp file"
rm -f /etc/sysctl.d/90-gateway-vpn-vps.conf || record_failure "remove owned sysctl file"
rm -f /etc/systemd/system/gateway-vpn-vps-firewall.service || record_failure "remove owned firewall unit"
rm -f /etc/systemd/system/gateway-vpn-vps-agent.service || record_failure "remove owned Agent unit"
rm -f /etc/systemd/system/gateway-vpn-vps-restore.service || record_failure "remove owned restore unit"
rm -f /etc/systemd/system/gateway-vpn-vps-restore.path || record_failure "remove owned restore watcher"
rm -f /etc/systemd/system/gateway-vpn-vps-restore-recovery.service || record_failure "remove owned restore recovery unit"
rm -f /etc/systemd/system/gateway-vpn-vps-fabric.service || record_failure "remove owned fabric apply unit"
rm -f /etc/systemd/system/gateway-vpn-vps-fabric.path || record_failure "remove owned fabric watcher"
rm -f /etc/systemd/system/gateway-vpn-vps-fabric-recovery.service || record_failure "remove owned fabric recovery unit"
rm -f /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.service || record_failure "remove owned fabric watchdog unit"
rm -f /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.timer || record_failure "remove owned fabric watchdog timer"
rm -rf /etc/systemd/system/wg-quick@wg-mgmt.service.d || record_failure "remove owned WireGuard drop-in"
rm -rf /etc/gateway-vpn-vps || record_failure "remove owned VPS config"
rm -f /opt/gateway-vpn-vps/current /opt/gateway-vpn-vps/.current.new || record_failure "remove release pointers"
rm -rf "/opt/gateway-vpn-vps/releases/v$VERSION" || record_failure "remove failed release"
rm -f /var/lib/gateway-vpn-vps/install-report.json || record_failure "remove incomplete install report"
rm -f /run/gateway-vpn-vps-install-authorized || record_failure "remove ephemeral service-start authorization"
rm -rf /var/lib/gateway-vpn-vps-privileged || record_failure "remove privileged VPS restore state"
if ((PRESERVE_AGENT_USER == 0)); then
  rm -rf /var/lib/gateway-vpn-vps/agent || record_failure "remove newly created VPS Agent state"
  if getent passwd gateway-vpn-vps >/dev/null; then
    userdel gateway-vpn-vps || record_failure "remove newly created VPS Agent user"
  fi
  if getent group gateway-vpn-vps >/dev/null; then
    groupdel gateway-vpn-vps || record_failure "remove newly created VPS Agent group"
  fi
else
  [[ -d /var/lib/gateway-vpn-vps/agent && ! -L /var/lib/gateway-vpn-vps/agent ]] || record_failure "preserved VPS Agent state is missing"
fi
if ((PRESERVE_AGENT_USER)); then
  chown root:gateway-vpn-vps /var/lib/gateway-vpn-vps || record_failure "restore preserved VPS state-root ownership"
  chmod 0710 /var/lib/gateway-vpn-vps || record_failure "restore preserved VPS state-root mode"
else
  chown root:root /var/lib/gateway-vpn-vps || record_failure "restore VPS state-root ownership"
  chmod 0700 /var/lib/gateway-vpn-vps || record_failure "restore VPS state-root mode"
fi
systemctl daemon-reload || record_failure "reload systemd after owned-state cleanup"
systemctl is-enabled --quiet wg-quick@wg-mgmt.service && record_failure "wg-mgmt remained enabled"
systemctl is-enabled --quiet gateway-vpn-vps-firewall.service && record_failure "owned firewall remained enabled"
systemctl is-enabled --quiet gateway-vpn-vps-agent.service && record_failure "VPS Agent remained enabled"
systemctl is-enabled --quiet gateway-vpn-vps-restore.path && record_failure "VPS restore watcher remained enabled"
systemctl is-enabled --quiet gateway-vpn-vps-fabric.path && record_failure "VPS fabric watcher remained enabled"
systemctl is-enabled --quiet gateway-vpn-vps-fabric-watchdog.timer && record_failure "VPS fabric watchdog remained enabled"
if ((FAILED)); then
  echo "Gateway VPN VPS recovery is incomplete; active marker retained for retry" >&2
  exit 1
fi
sync || exit 1
timestamp=$(date -u +%Y%m%dT%H%M%S%NZ)
ROLLED_BACK_MARKER="/var/lib/gateway-vpn-vps/install-transactions/rolled-back-$timestamp"
mv -f "$MARKER" "$ROLLED_BACK_MARKER" || exit 1
if ! sync -f /var/lib/gateway-vpn-vps/install-transactions; then
  mv -f "$ROLLED_BACK_MARKER" "$MARKER" || true
  sync -f /var/lib/gateway-vpn-vps/install-transactions || true
  exit 1
fi
systemctl disable gateway-vpn-vps-install-recovery.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/gateway-vpn-vps-install-recovery.service /usr/libexec/gateway-vpn-vps-install-recovery || echo "Warning: recovered VPS state but could not remove recovery helper" >&2
systemctl daemon-reload || echo "Warning: recovered VPS state but final systemd reload failed" >&2
exit 0
