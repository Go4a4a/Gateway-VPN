#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:?expected Gateway VPN version}
EXPECTED_SCHEMA=${2:?expected SQLite migration version}
SQLITE=${3:?absolute sqlite3 binary path}
LAN_INTERFACE=${4:-lan0}
LAN_ADDRESS=${5:-192.168.200.1/24}
FIREWALL_GENERATION=${6:-3}

[[ $EUID -eq 0 ]] || { echo "Gateway systemd release gate requires root" >&2; exit 1; }
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || { echo "Invalid expected version" >&2; exit 2; }
[[ $EXPECTED_SCHEMA =~ ^[1-9][0-9]*$ ]] || { echo "Invalid expected schema" >&2; exit 2; }
[[ $FIREWALL_GENERATION =~ ^[1-9][0-9]*$ ]] || { echo "Invalid firewall generation" >&2; exit 2; }
[[ $LAN_INTERFACE =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || { echo "Invalid LAN interface" >&2; exit 2; }
[[ $LAN_ADDRESS =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || { echo "Invalid LAN address" >&2; exit 2; }
[[ $SQLITE == /* && -x $SQLITE && ! -L $SQLITE ]] || { echo "sqlite3 gate helper must be an absolute executable non-symlink" >&2; exit 1; }

LAN_IP=${LAN_ADDRESS%/*}
RELEASE="/opt/gateway-vpn/releases/v$VERSION"
CONTROL="$RELEASE/bin/gateway-vpnctl"
DATABASE=/var/lib/gateway-vpn/state.db

[[ $(systemctl is-system-running) == running ]]
[[ $(timedatectl show -p NTPSynchronized --value) == yes ]]
[[ $(readlink /opt/gateway-vpn/current) == "releases/v$VERSION" ]]
[[ $(readlink /opt/gateway-vpn/recovery) == "releases/v$VERSION" ]]
"$CONTROL" release-verify \
  --release-dir "$RELEASE" \
  --public-key /etc/gateway-vpn/update-signing.pub \
  --current-version 0.0.0 --current-schema 1 >/dev/null

[[ $($SQLITE -readonly "$DATABASE" 'SELECT MAX(version) FROM schema_migrations;') == "$EXPECTED_SCHEMA" ]]
[[ $($SQLITE -readonly "$DATABASE" 'SELECT COUNT(*) FROM schema_migrations;') == "$EXPECTED_SCHEMA" ]]
[[ $($SQLITE -readonly "$DATABASE" 'PRAGMA quick_check;') == ok ]]
[[ $($SQLITE -readonly "$DATABASE" 'PRAGMA integrity_check;') == ok ]]
[[ -z $($SQLITE -readonly "$DATABASE" 'PRAGMA foreign_key_check;') ]]

runtime=$("$CONTROL" status --database "$DATABASE" --json)
[[ $runtime == *'"GatewayState":"ALL_UPLINKS_OFFLINE"'* ]]
[[ $runtime == *'"PathState":"PATH_BLOCKED"'* ]]
[[ $runtime == *'"ActivePathID":""'* ]]

watchdog=$(< /run/gateway-vpn-watchdog/status.json)
control=$(< /run/gateway-vpn-watchdog/control.json)
[[ $watchdog == *'"overall_state":"HEALTHY"'* ]]
[[ $watchdog == *'"connectivity_class":"EXTERNAL_CONNECTIVITY_FAILURE"'* ]]
[[ $watchdog == *'"policy_source":"SQLITE"'* ]]
[[ $control == *'"database_ok":true'* ]]
[[ $control == *'"workers_ok":true'* ]]
[[ $(stat -c '%U:%G:%a' /run/gateway-vpn-watchdog/status.json) == root:gateway-vpn:640 ]]
[[ $(stat -c '%U:%G:%a' /run/gateway-vpn-watchdog/control.json) == gateway-vpn:gateway-vpn:640 ]]

for unit in \
  gateway-vpn.service gateway-vpn-watchdog.service \
  gateway-vpn-firewall.service gateway-vpn-firewall-guard.service \
  gateway-vpn-network-broker.socket gateway-vpn-network-broker.service \
  gateway-vpn-dnsmasq.service gateway-vpn-update-recovery.service \
  gateway-vpn-update-finalize.timer ssh.service; do
  systemctl is-active --quiet "$unit"
done
! systemctl is-active --quiet gateway-vpn-mihomo.service
[[ -z $(systemctl --failed --no-legend --plain) ]]
[[ $(systemctl show gateway-vpn-update-recovery.service -p Result --value) == success ]]
[[ $(systemctl show gateway-vpn-network-recovery.service -p Result --value) == success ]]
for unit in \
  gateway-vpn.service gateway-vpn-watchdog.service \
  gateway-vpn-firewall-guard.service gateway-vpn-network-broker.service \
  gateway-vpn-dnsmasq.service; do
  [[ $(systemctl show "$unit" -p NRestarts --value) == 0 ]]
done

headers=$(curl --fail --silent --show-error --insecure --max-time 5 --dump-header - --output /dev/null "https://$LAN_IP:8443/")
grep -Eiq '^Content-Security-Policy:' <<<"$headers"
grep -Eiq '^X-Frame-Options:[[:space:]]*DENY' <<<"$headers"
grep -Eiq '^X-Content-Type-Options:[[:space:]]*nosniff' <<<"$headers"
grep -Eiq '^Cache-Control:[[:space:]]*no-store' <<<"$headers"
ss -H -ltn 'sport = :8443' | awk '{print $4}' | grep -Fxq "$LAN_IP:8443"
ss -H -ltn 'sport = :22' | awk '{print $4}' | grep -Eq '^(0\.0\.0\.0|\*):22$'
ss -H -ltn 'sport = :53' | awk '{print $4}' | grep -Fxq "$LAN_IP:53"
ss -H -lun 'sport = :67' | awk '{print $4}' | grep -Fxq "0.0.0.0%$LAN_INTERFACE:67"

[[ $(sysctl -n net.ipv6.conf.all.disable_ipv6) == 1 ]]
[[ $(sysctl -n net.ipv6.conf.default.disable_ipv6) == 1 ]]
[[ -z $(ip -6 route show default) ]]

nft --json list set inet gateway_vpn firewall_schema_generation \
  | grep -Eq '"elem"[[:space:]]*:[[:space:]]*\[[[:space:]]*'"$FIREWALL_GENERATION"'[[:space:]]*\]'
! nft list set inet gateway_vpn active_tun_interfaces | grep -Fq 'elements ='
! nft list set inet gateway_vpn active_direct_interfaces | grep -Fq 'elements ='
! nft list set inet gateway_vpn active_path_generation | grep -Fq 'elements ='
nft list chain inet gateway_vpn forward | grep -Fq 'gateway-vpn PATH_BLOCKED'

report=$(< /var/lib/gateway-vpn/install-report.json)
[[ $report == *'"version": "'"$VERSION"'"'* ]]
[[ $report == *'"lan_interface": "'"$LAN_INTERFACE"'"'* ]]
[[ $report == *'"lan_address": "'"$LAN_ADDRESS"'"'* ]]
[[ $report == *'"state": "INSTALLED_NOT_READY"'* ]]

journal=$(journalctl --namespace=gateway-vpn -b --no-pager -o cat)
if grep -Eiq 'start-limit-hit|status=226/NAMESPACE|rejected notification message|data-plane reconciliation failed' <<<"$journal"; then
  echo "Forbidden Gateway systemd failure signature found in current boot" >&2
  exit 1
fi

echo "GATEWAY_SYSTEMD_RELEASE_GATE_PASS version=$VERSION schema=$EXPECTED_SCHEMA firewall_generation=$FIREWALL_GENERATION"
