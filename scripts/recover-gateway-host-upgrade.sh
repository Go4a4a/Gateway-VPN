#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

ROOT=/var/lib/gateway-vpn-host-upgrade
ACTIVE=$ROOT/active
LOCK_FILE=/run/lock/gateway-vpn-install.lock

[[ ${1:-} == --apply && $# == 1 ]] || { echo "Usage: gateway-vpn-host-upgrade-recovery --apply" >&2; exit 2; }
[[ $EUID -eq 0 && ${GATEWAY_VPN_HOST_UPGRADE_RECOVERY_UNIT:-} == 1 ]] || { echo "Host-upgrade recovery may run only as root inside its fixed recovery transaction" >&2; exit 1; }
[[ -d /run/lock && ! -L /run/lock && $(stat -c '%u' /run/lock) == 0 ]] || { echo "Gateway runtime lock directory is unavailable" >&2; exit 1; }
if [[ ! -e $LOCK_FILE && ! -L $LOCK_FILE ]]; then
  (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create Gateway transaction lock safely" >&2; exit 1; }
fi
[[ -f $LOCK_FILE && ! -L $LOCK_FILE && $(stat -c '%u:%g:%a' "$LOCK_FILE") == 0:0:600 ]] || { echo "Gateway transaction lock ownership or mode is invalid" >&2; exit 1; }
exec 9<>"$LOCK_FILE"
flock -n 9 || { echo "Another Gateway VPN install/recovery/uninstall transaction is active" >&2; exit 1; }

RECOVERY_HELPER=/usr/libexec/gateway-vpn-host-upgrade-recovery
RECOVERY_UNIT=/etc/systemd/system/gateway-vpn-host-upgrade-recovery.service
RECOVERY_WANTS=/etc/systemd/system/multi-user.target.wants/gateway-vpn-host-upgrade-recovery.service
[[ $(realpath -e -- "$0") == "$RECOVERY_HELPER" && -f $RECOVERY_HELPER && ! -L $RECOVERY_HELPER && $(stat -c '%u:%g:%a' "$RECOVERY_HELPER") == 0:0:700 ]] || { echo "Host-upgrade recovery helper is unsafe" >&2; exit 1; }
[[ -f $RECOVERY_UNIT && ! -L $RECOVERY_UNIT && $(stat -c '%u:%g:%a' "$RECOVERY_UNIT") == 0:0:644 ]] || { echo "Host-upgrade recovery unit is unsafe" >&2; exit 1; }
[[ -L $RECOVERY_WANTS && $(readlink "$RECOVERY_WANTS") == "$RECOVERY_UNIT" ]] || { echo "Host-upgrade boot recovery is not enabled" >&2; exit 1; }

[[ -d $ROOT && ! -L $ROOT && $(stat -c '%u:%g:%a' "$ROOT") == 0:0:700 ]] || { echo "Host-upgrade transaction root is unsafe" >&2; exit 1; }
[[ -f $ACTIVE && ! -L $ACTIVE && $(stat -c '%u:%g:%a' "$ACTIVE") == 0:0:600 ]] || { echo "Host-upgrade active marker is unsafe" >&2; exit 1; }
MARKER_BYTES=$(stat -c '%s' "$ACTIVE")
[[ $MARKER_BYTES =~ ^[0-9]+$ && $MARKER_BYTES -gt 0 && $MARKER_BYTES -le 2048 ]] || { echo "Host-upgrade active marker size is invalid" >&2; exit 1; }
[[ $(wc -l <"$ACTIVE") == 8 ]] || { echo "Host-upgrade active marker field count is invalid" >&2; exit 1; }
for key in format transaction_id state old_version new_version log_reader_user log_reader_group_existed log_reader_was_member; do
  [[ $(grep -c "^${key}=" "$ACTIVE") == 1 ]] || { echo "Host-upgrade active marker field is invalid" >&2; exit 1; }
done
[[ $(grep -Ec '^(format|transaction_id|state|old_version|new_version|log_reader_user|log_reader_group_existed|log_reader_was_member)=' "$ACTIVE") == 8 ]] || { echo "Host-upgrade active marker contains unknown fields" >&2; exit 1; }

marker_value() { sed -n "s/^$1=//p" "$ACTIVE"; }
FORMAT=$(marker_value format)
TRANSACTION_ID=$(marker_value transaction_id)
STATE=$(marker_value state)
OLD_VERSION=$(marker_value old_version)
NEW_VERSION=$(marker_value new_version)
LOG_READER_USER=$(marker_value log_reader_user)
LOG_READER_GROUP_EXISTED=$(marker_value log_reader_group_existed)
LOG_READER_WAS_MEMBER=$(marker_value log_reader_was_member)
[[ $FORMAT == 1 ]] || { echo "Unsupported host-upgrade marker format" >&2; exit 1; }
[[ $TRANSACTION_ID =~ ^host-upgrade-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$ ]] || { echo "Host-upgrade transaction identity is invalid" >&2; exit 1; }
[[ $STATE == SNAPSHOT_READY || $STATE == APPLYING || $STATE == CANDIDATE_READY ]] || { echo "Host-upgrade transaction state is invalid" >&2; exit 1; }
VERSION_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$'
[[ $OLD_VERSION =~ $VERSION_PATTERN && $NEW_VERSION =~ $VERSION_PATTERN && $OLD_VERSION != "$NEW_VERSION" ]] || { echo "Host-upgrade release identity is invalid" >&2; exit 1; }
[[ $LOG_READER_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ && $LOG_READER_USER != root && $LOG_READER_GROUP_EXISTED =~ ^[01]$ && $LOG_READER_WAS_MEMBER =~ ^[01]$ ]] || { echo "Host-upgrade account state is invalid" >&2; exit 1; }

TRANSACTION=$ROOT/transactions/$TRANSACTION_ID
SNAPSHOT=$TRANSACTION/snapshot
ROOTFS=$SNAPSHOT/rootfs
TOOLING=$TRANSACTION/tooling
[[ -d $TRANSACTION && ! -L $TRANSACTION && $(stat -c '%u:%g:%a' "$TRANSACTION") == 0:0:700 ]] || { echo "Host-upgrade transaction directory is unsafe" >&2; exit 1; }
[[ -d $SNAPSHOT && ! -L $SNAPSHOT && $(stat -c '%u:%g:%a' "$SNAPSHOT") == 0:0:700 ]] || { echo "Host-upgrade snapshot directory is unsafe" >&2; exit 1; }
[[ -d $ROOTFS && ! -L $ROOTFS && $(stat -c '%u:%g:%a' "$ROOTFS") == 0:0:700 ]] || { echo "Host-upgrade rootfs snapshot is unsafe" >&2; exit 1; }
[[ -d $TOOLING && ! -L $TOOLING && $(stat -c '%u:%g:%a' "$TOOLING") == 0:0:700 ]] || { echo "Host-upgrade tooling directory is unsafe" >&2; exit 1; }
[[ $(realpath -e "$ROOTFS") == "$ROOTFS" ]] || { echo "Host-upgrade rootfs snapshot path is non-canonical" >&2; exit 1; }
[[ -d $ROOTFS/opt/gateway-vpn && ! -L $ROOTFS/opt/gateway-vpn ]] || { echo "Host-upgrade snapshot lacks the old release tree" >&2; exit 1; }
[[ -f $ROOTFS/var/lib/gateway-vpn/state.db && ! -L $ROOTFS/var/lib/gateway-vpn/state.db ]] || { echo "Host-upgrade snapshot lacks the old database" >&2; exit 1; }
[[ -L $ROOTFS/opt/gateway-vpn/current && $(readlink "$ROOTFS/opt/gateway-vpn/current") == releases/v$OLD_VERSION ]] || { echo "Host-upgrade snapshot current pointer is invalid" >&2; exit 1; }
[[ -L $ROOTFS/opt/gateway-vpn/recovery && $(readlink "$ROOTFS/opt/gateway-vpn/recovery") == releases/v$OLD_VERSION ]] || { echo "Host-upgrade snapshot recovery pointer is invalid" >&2; exit 1; }
OLD_RECOVERY_HELPER=$ROOTFS$RECOVERY_HELPER
OLD_RECOVERY_UNIT=$ROOTFS$RECOVERY_UNIT
OLD_RECOVERY_WANTS=$ROOTFS$RECOVERY_WANTS
if [[ -e $OLD_RECOVERY_HELPER || -L $OLD_RECOVERY_HELPER || -e $OLD_RECOVERY_UNIT || -L $OLD_RECOVERY_UNIT ]]; then
  [[ -f $OLD_RECOVERY_HELPER && ! -L $OLD_RECOVERY_HELPER && $(stat -c '%u:%g:%a' "$OLD_RECOVERY_HELPER") == 0:0:700 ]] || { echo "Snapshotted host-upgrade recovery helper is unsafe" >&2; exit 1; }
  [[ -f $OLD_RECOVERY_UNIT && ! -L $OLD_RECOVERY_UNIT && $(stat -c '%u:%g:%a' "$OLD_RECOVERY_UNIT") == 0:0:644 ]] || { echo "Snapshotted host-upgrade recovery unit is unsafe" >&2; exit 1; }
fi
if [[ -e $OLD_RECOVERY_WANTS || -L $OLD_RECOVERY_WANTS ]]; then
  [[ -f $OLD_RECOVERY_UNIT && -L $OLD_RECOVERY_WANTS && $(readlink "$OLD_RECOVERY_WANTS") == "$RECOVERY_UNIT" ]] || { echo "Snapshotted host-upgrade recovery enablement is unsafe" >&2; exit 1; }
fi

gateway_units=(
  gateway-vpn.service gateway-vpn-watchdog.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service
  gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn-network-recovery.service
  gateway-vpn-update-finalize.timer gateway-vpn-update-finalize.service gateway-vpn-update-resume.service
  gateway-vpn-update.service gateway-vpn-update-recovery.service gateway-vpn-database-restore-boot.service
  gateway-vpn-database-restore-dispatch.service gateway-vpn-database-restore.service gateway-vpn-database-restore-resume.service
  gateway-vpn-firewall-guard.service gateway-vpn-firewall.service gateway-vpn-install-recovery.service
  gateway-vpn-power-cycle@.service gateway-vpn-network-rollback@.timer gateway-vpn-network-rollback@.service
)
systemctl stop "${gateway_units[@]}" 2>/dev/null || true
systemctl stop 'gateway-vpn-power-cycle@*.service' 'gateway-vpn-network-rollback@*.timer' 'gateway-vpn-network-rollback@*.service' 2>/dev/null || true

# Remove only the fixed Gateway-owned host projection. The fail-closed nft
# table remains installed until the restored release atomically replaces it.
rm -rf /opt/gateway-vpn /etc/gateway-vpn /var/lib/gateway-vpn /var/lib/gateway-vpn-privileged /var/lib/gateway-vpn-dnsmasq /var/log/gateway-vpn
shopt -s nullglob
for path in /etc/systemd/system/gateway-vpn*.service /etc/systemd/system/gateway-vpn*.socket /etc/systemd/system/gateway-vpn*.timer; do
  [[ $path == "$RECOVERY_UNIT" ]] || rm -f -- "$path"
done
for link in /etc/systemd/system/*.target.wants/gateway-vpn* /etc/systemd/system/*.service.wants/gateway-vpn*; do
  [[ $link == "$RECOVERY_WANTS" ]] || { [[ -L $link ]] && rm -f -- "$link"; }
done
rm -f /etc/systemd/network/05-gateway-vpn-lan.network /etc/systemd/network/05-gateway-vpn-lan.netdev /etc/systemd/network/06-gateway-vpn-lan-*.network /etc/systemd/network/80-gateway-vpn-hilink.network
rm -f /etc/systemd/system/systemd-networkd-wait-online.service.d/gateway-vpn.conf
rm -f /etc/default/grub.d/90-gateway-vpn.cfg
rm -f /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf /etc/sysctl.d/90-gateway-vpn-ipv6.conf
rm -f /etc/systemd/journald@gateway-vpn.conf.d/retention.conf
rm -f /usr/lib/sysusers.d/gateway-vpn.conf /usr/lib/tmpfiles.d/gateway-vpn.conf
rm -f /usr/libexec/gateway-vpn-install-recovery
shopt -u nullglob

restore_snapshot_item() {
  local absolute=$1 source=$ROOTFS$1 destination_parent
  [[ $absolute == /* && $absolute != / && $absolute != *..* ]] || { echo "Host-upgrade restore path is invalid" >&2; exit 1; }
  [[ -e $source || -L $source ]] || return 0
  destination_parent=$(dirname "$absolute")
  [[ -d $destination_parent && ! -L $destination_parent ]] || { echo "Host-upgrade restore parent is unsafe: $destination_parent" >&2; exit 1; }
  cp -a -- "$source" "$destination_parent/"
}
for path in /opt/gateway-vpn /etc/gateway-vpn /var/lib/gateway-vpn /var/lib/gateway-vpn-privileged /var/lib/gateway-vpn-dnsmasq /var/log/gateway-vpn; do
  restore_snapshot_item "$path"
done
shopt -s nullglob
for source in \
  "$ROOTFS"/etc/systemd/system/gateway-vpn*.service "$ROOTFS"/etc/systemd/system/gateway-vpn*.socket "$ROOTFS"/etc/systemd/system/gateway-vpn*.timer \
  "$ROOTFS"/etc/systemd/network/05-gateway-vpn-lan.network "$ROOTFS"/etc/systemd/network/05-gateway-vpn-lan.netdev "$ROOTFS"/etc/systemd/network/06-gateway-vpn-lan-*.network "$ROOTFS"/etc/systemd/network/80-gateway-vpn-hilink.network \
  "$ROOTFS"/etc/systemd/system/systemd-networkd-wait-online.service.d/gateway-vpn.conf "$ROOTFS"/etc/default/grub.d/90-gateway-vpn.cfg \
  "$ROOTFS"/etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf "$ROOTFS"/etc/sysctl.d/90-gateway-vpn-ipv6.conf "$ROOTFS"/etc/systemd/journald@gateway-vpn.conf.d/retention.conf \
  "$ROOTFS"/usr/lib/sysusers.d/gateway-vpn.conf "$ROOTFS"/usr/lib/tmpfiles.d/gateway-vpn.conf \
  "$ROOTFS"/usr/libexec/gateway-vpn-install-recovery "$ROOTFS"/usr/libexec/gateway-vpn-host-upgrade-recovery \
  "$ROOTFS"/boot/grub/grub.cfg "$ROOTFS"/boot/grub/grubenv; do
  [[ ${source#"$ROOTFS"} == "$RECOVERY_UNIT" || ${source#"$ROOTFS"} == "$RECOVERY_HELPER" ]] && continue
  restore_snapshot_item "${source#"$ROOTFS"}"
done
shopt -u nullglob
sync

if ((LOG_READER_WAS_MEMBER == 0)) && getent group gateway-vpn-log-readers >/dev/null 2>&1 && id -nG "$LOG_READER_USER" 2>/dev/null | tr ' ' '\n' | grep -Fxq gateway-vpn-log-readers; then
  gpasswd -d "$LOG_READER_USER" gateway-vpn-log-readers >/dev/null
fi
if ((LOG_READER_GROUP_EXISTED == 0)) && getent group gateway-vpn-log-readers >/dev/null 2>&1; then
  [[ -z $(getent group gateway-vpn-log-readers | awk -F: '{print $4}') ]] || { echo "Restored log-reader group still has members" >&2; exit 1; }
  groupdel gateway-vpn-log-readers
fi

systemctl daemon-reload
systemd-sysusers /usr/lib/sysusers.d/gateway-vpn.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/gateway-vpn.conf
[[ ! -f /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf ]] || sysctl -q -p /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf
[[ ! -f /etc/sysctl.d/90-gateway-vpn-ipv6.conf ]] || sysctl -q -p /etc/sysctl.d/90-gateway-vpn-ipv6.conf
networkctl reload

old_binary=/opt/gateway-vpn/releases/v$OLD_VERSION/bin/gateway-vpn
verifier=$TOOLING/gateway-vpnctl
old_verifier=$TOOLING/old-gateway-vpnctl
[[ -x $old_binary ]] || { echo "Restored old release binary is unavailable" >&2; exit 1; }
[[ -f $verifier && ! -L $verifier && $(stat -c '%u:%g:%a' "$verifier") == 0:0:700 ]] || { echo "Host-upgrade database verifier is unsafe" >&2; exit 1; }
[[ -f $old_verifier && ! -L $old_verifier && $(stat -c '%u:%g:%a' "$old_verifier") == 0:0:700 ]] || { echo "Host-upgrade old-release verifier is unsafe" >&2; exit 1; }
[[ -f $TOOLING/update-signing.pub && ! -L $TOOLING/update-signing.pub && $(stat -c '%u:%g:%a' "$TOOLING/update-signing.pub") == 0:0:600 ]] || { echo "Host-upgrade trusted key snapshot is unsafe" >&2; exit 1; }
old_schema=$(sed -n 's/.*"database_schema_maximum": \([0-9][0-9]*\).*/\1/p' "/opt/gateway-vpn/releases/v$OLD_VERSION/release.json")
[[ $old_schema =~ ^[1-9][0-9]*$ ]] || { echo "Restored old release schema metadata is invalid" >&2; exit 1; }
cmp -s -- "$old_verifier" "/opt/gateway-vpn/releases/v$OLD_VERSION/bin/gateway-vpnctl" || { echo "Restored old release verifier differs from the verified snapshot" >&2; exit 1; }
"$old_verifier" release-verify --release-dir "/opt/gateway-vpn/releases/v$OLD_VERSION" --public-key "$TOOLING/update-signing.pub" --current-version 0.0.0 --current-schema "$old_schema" >/dev/null
[[ $("$old_binary" --version) == "gateway-vpn $OLD_VERSION "* ]] || { echo "Restored old release binary version is invalid" >&2; exit 1; }
"$verifier" database-verify --database /var/lib/gateway-vpn/state.db --expected-schema "$old_schema" --json >/dev/null

report_string() { sed -n "s/^[[:space:]]*\"$1\": \"\([^\"]*\)\",\{0,1\}$/\1/p" /var/lib/gateway-vpn/install-report.json; }
REPORT_VERSION=$(report_string version)
LAN_INTERFACE=$(report_string lan_interface)
LAN_MEMBERS=$(report_string lan_members)
LAN_ADDRESS=$(report_string lan_address)
[[ $REPORT_VERSION == "$OLD_VERSION" && $LAN_INTERFACE =~ ^[A-Za-z0-9_.:-]{1,15}$ && $LAN_ADDRESS =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/(1[6-9]|2[0-9]|30)$ ]] || { echo "Restored Gateway LAN report is invalid" >&2; exit 1; }
LAN_MEMBER_NAMES=()
if [[ -n $LAN_MEMBERS ]]; then
  [[ $LAN_INTERFACE == gateway-vpn-lan && $LAN_MEMBERS =~ ^[A-Za-z0-9_.:-]{1,15}(,[A-Za-z0-9_.:-]{1,15}){0,15}$ ]] || { echo "Restored Gateway LAN member report is invalid" >&2; exit 1; }
  IFS=, read -r -a LAN_MEMBER_NAMES <<<"$LAN_MEMBERS"
  if ! ip link show dev "$LAN_INTERFACE" >/dev/null 2>&1; then
    ip link add name "$LAN_INTERFACE" type bridge stp_state 1 forward_delay 4
  fi
  ip -d -o link show dev "$LAN_INTERFACE" | grep -Eq ' bridge ' || { echo "Restored Gateway LAN interface is not a bridge" >&2; exit 1; }
  for member in "${LAN_MEMBER_NAMES[@]}"; do
    ip link show dev "$member" >/dev/null
    ip link set dev "$member" up
    ip link set dev "$member" master "$LAN_INTERFACE"
  done
else
  ip link show dev "$LAN_INTERFACE" >/dev/null
fi
ip link set dev "$LAN_INTERFACE" up
ip -4 address replace "$LAN_ADDRESS" dev "$LAN_INTERFACE"
"$old_binary" firewall-boot --config /etc/gateway-vpn/config.yaml --apply

enable_if_present() {
  local unit=$1
  [[ $(systemctl show "$unit" -p LoadState --value 2>/dev/null || true) == not-found ]] || systemctl enable "$unit" >/dev/null
}
for unit in gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-watchdog.service gateway-vpn-update-recovery.service gateway-vpn-database-restore-boot.service gateway-vpn-network-recovery.service gateway-vpn-network-broker.socket gateway-vpn-mihomo.service gateway-vpn.service gateway-vpn-update-finalize.timer; do
  enable_if_present "$unit"
done
[[ ! -f /etc/gateway-vpn/dnsmasq.conf ]] || enable_if_present gateway-vpn-dnsmasq.service

systemctl reset-failed gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-watchdog.service gateway-vpn-update-recovery.service gateway-vpn-network-recovery.service gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn.service gateway-vpn-dnsmasq.service 2>/dev/null || true
[[ $(readlink /opt/gateway-vpn/current) == releases/v$OLD_VERSION && $(readlink /opt/gateway-vpn/recovery) == releases/v$OLD_VERSION ]] || { echo "Old release pointers were not restored" >&2; exit 1; }
nft list chain inet gateway_vpn forward | grep -Fq 'gateway-vpn PATH_BLOCKED'

START_UNITS=(gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-update-recovery.service gateway-vpn-network-recovery.service gateway-vpn-network-broker.socket gateway-vpn-watchdog.service gateway-vpn.service gateway-vpn-update-finalize.timer)
[[ ! -f /etc/gateway-vpn/dnsmasq.conf ]] || START_UNITS+=(gateway-vpn-dnsmasq.service)
[[ ! -f /var/lib/gateway-vpn/mihomo/active/config.yaml ]] || START_UNITS+=(gateway-vpn-mihomo.service)
restore_recovery_guard_projection() {
  systemctl disable gateway-vpn-host-upgrade-recovery.service >/dev/null 2>&1 || true
  rm -f -- "$RECOVERY_WANTS" "$RECOVERY_UNIT" "$RECOVERY_HELPER"
  restore_snapshot_item "$RECOVERY_HELPER"
  restore_snapshot_item "$RECOVERY_UNIT"
  restore_snapshot_item "$RECOVERY_WANTS"
  systemctl daemon-reload
}
if [[ ${GATEWAY_VPN_HOST_UPGRADE_RECOVERY_BOOT:-} == 1 ]]; then
  # The recovery unit is ordered Before these services. Queue their jobs and
  # return so systemd can satisfy that ordering without a start-job deadlock.
  systemctl start --no-block "${START_UNITS[@]}"
  ROLLED_BACK=$TRANSACTION/rolled-back-$(date -u +%Y%m%dT%H%M%SZ)
  mv -T "$ACTIVE" "$ROLLED_BACK"
  sync -f "$ROOT"
  restore_recovery_guard_projection
else
  systemctl start "${START_UNITS[@]}"
  for unit in gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-watchdog.service gateway-vpn-network-broker.socket gateway-vpn.service; do
    systemctl is-active --quiet "$unit"
  done
  [[ ! -f /etc/gateway-vpn/dnsmasq.conf ]] || systemctl is-active --quiet gateway-vpn-dnsmasq.service
  [[ ! -f /var/lib/gateway-vpn/mihomo/active/config.yaml ]] || systemctl is-active --quiet gateway-vpn-mihomo.service
  ROLLED_BACK=$TRANSACTION/rolled-back-$(date -u +%Y%m%dT%H%M%SZ)
  mv -T "$ACTIVE" "$ROLLED_BACK"
  sync -f "$ROOT"
  restore_recovery_guard_projection
fi
echo "Gateway VPN host-contract upgrade rolled back to $OLD_VERSION; interrupted candidate was $NEW_VERSION"
