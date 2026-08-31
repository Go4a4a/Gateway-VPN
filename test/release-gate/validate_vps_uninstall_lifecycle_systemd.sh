#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

AGENT=${1:?absolute gateway-vpn-vps-agent binary}
ROOT=${2:?absolute repository root}
[[ $EUID -eq 0 && $AGENT == /* && -x $AGENT && ! -L $AGENT && $ROOT == /* && -f $ROOT/scripts/uninstall-vps.sh ]] || {
  echo "VPS uninstall lifecycle gate requires root, Agent, and repository root" >&2
  exit 2
}
[[ $(ps -p 1 -o comm=) == systemd ]] || { echo "VPS uninstall lifecycle gate requires systemd PID 1" >&2; exit 1; }

VERSION=1.2.0
UPDATE_ID=vps-update-20260831T130000Z-0123456789abcdef01234567
TRANSACTION_ROOT=/var/lib/gateway-vpn-vps-privileged/update-transactions
LOCK=/run/lock/gateway-vpn-vps-install.lock
HOLDER_PID=
TMP=$(mktemp -d)

cleanup() {
  if [[ -n $HOLDER_PID ]]; then
    kill "$HOLDER_PID" >/dev/null 2>&1 || true
    wait "$HOLDER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf /opt/gateway-vpn-vps /etc/gateway-vpn-vps /var/lib/gateway-vpn-vps /var/lib/gateway-vpn-vps-privileged "$TMP"
  rm -rf /etc/systemd/system/wg-quick@wg-mgmt.service.d
  rm -f /etc/wireguard/wg-mgmt.conf "$LOCK" /run/gateway-vpn-vps-install-authorized /run/gateway-vpn-vps-update-live /run/gateway-vpn-vps-uninstall-lock-ready
}
trap cleanup EXIT

write_journal() {
  local state=$1 destination=$2
  printf '%s\n' \
    '{' \
    '  "format_version": 1,' \
    "  \"update_id\": \"$UPDATE_ID\"," \
    "  \"state\": \"$state\"," \
    '  "started_at": "2026-08-31T13:00:00Z",' \
    '  "updated_at": "2026-08-31T13:00:00Z",' \
    '  "old_version": "1.1.0",' \
    "  \"new_version\": \"$VERSION\"," \
    '  "old_schema": 4,' \
    '  "new_schema": 4,' \
    '  "old_current_target": "releases/v1.1.0",' \
    "  \"new_current_target\": \"releases/v$VERSION\"," \
    '  "database_switch_begun": false' \
    '}' >"$destination"
  chmod 0600 "$destination"
}

rm -rf /opt/gateway-vpn-vps /etc/gateway-vpn-vps /var/lib/gateway-vpn-vps /var/lib/gateway-vpn-vps-privileged
rm -rf /etc/systemd/system/wg-quick@wg-mgmt.service.d
rm -f /etc/wireguard/wg-mgmt.conf "$LOCK" /run/gateway-vpn-vps-install-authorized /run/gateway-vpn-vps-update-live /run/gateway-vpn-vps-uninstall-lock-ready
install -d -o root -g root -m 0755 "/opt/gateway-vpn-vps/releases/v$VERSION/bin"
install -m 0755 "$AGENT" "/opt/gateway-vpn-vps/releases/v$VERSION/bin/gateway-vpn-vps-agent"
ln -s "releases/v$VERSION" /opt/gateway-vpn-vps/current
ln -s "releases/v$VERSION" /opt/gateway-vpn-vps/recovery
install -d -o root -g root -m 0700 "$TRANSACTION_ROOT" /var/lib/gateway-vpn-vps/install-transactions
install -d -o root -g root -m 0700 "$TRANSACTION_ROOT/$UPDATE_ID"
install -d -o root -g root -m 0700 /var/lib/gateway-vpn-vps/agent
printf 'preserve-settings\n' >/var/lib/gateway-vpn-vps/agent/preserved
install -d -o root -g root -m 0700 /etc/wireguard
printf 'preserve-wireguard\n' >/etc/wireguard/wg-mgmt.conf
chmod 0600 /etc/wireguard/wg-mgmt.conf

install -o root -g root -m 0600 /dev/null "$LOCK"
( exec 8<>"$LOCK"; flock -n 8; : >/run/gateway-vpn-vps-uninstall-lock-ready; sleep 60 ) &
HOLDER_PID=$!
for _ in $(seq 1 100); do [[ -e /run/gateway-vpn-vps-uninstall-lock-ready ]] && break; sleep 0.02; done
[[ -e /run/gateway-vpn-vps-uninstall-lock-ready ]]
if bash "$ROOT/scripts/uninstall-vps.sh" --apply >"$TMP/locked.out" 2>"$TMP/locked.err"; then
  echo "VPS uninstall crossed the shared lifecycle lock" >&2
  exit 1
fi
grep -Fq 'transaction is active' "$TMP/locked.err"
[[ -x /opt/gateway-vpn-vps/recovery/bin/gateway-vpn-vps-agent ]]
kill "$HOLDER_PID"
wait "$HOLDER_PID" >/dev/null 2>&1 || true
HOLDER_PID=
rm -f /run/gateway-vpn-vps-uninstall-lock-ready

write_journal PREPARED "$TRANSACTION_ROOT/$UPDATE_ID/journal.json"
write_journal PREPARED "$TRANSACTION_ROOT/active.json"
if bash "$ROOT/scripts/uninstall-vps.sh" --apply >"$TMP/nonterminal.out" 2>"$TMP/nonterminal.err"; then
  echo "VPS uninstall accepted a nonterminal update journal" >&2
  exit 1
fi
grep -Fq 'active VPS update' "$TMP/nonterminal.err"
[[ -x /opt/gateway-vpn-vps/recovery/bin/gateway-vpn-vps-agent ]]

write_journal FINALIZED "$TRANSACTION_ROOT/$UPDATE_ID/journal.json"
printf 'corrupt\n' >"$TRANSACTION_ROOT/active.json"
chmod 0600 "$TRANSACTION_ROOT/active.json"
if bash "$ROOT/scripts/uninstall-vps.sh" --apply >"$TMP/corrupt.out" 2>"$TMP/corrupt.err"; then
  echo "VPS uninstall accepted a corrupt update journal" >&2
  exit 1
fi
grep -Fq 'active VPS update' "$TMP/corrupt.err"
[[ -x /opt/gateway-vpn-vps/recovery/bin/gateway-vpn-vps-agent ]]

write_journal FINALIZED "$TRANSACTION_ROOT/active.json"
bash "$ROOT/scripts/uninstall-vps.sh" --apply >"$TMP/terminal.out" 2>"$TMP/terminal.err"
grep -Fq 'Gateway VPN VPS uninstalled' "$TMP/terminal.out"
[[ ! -e /opt/gateway-vpn-vps && ! -L /opt/gateway-vpn-vps ]]
[[ ! -e /var/lib/gateway-vpn-vps-privileged && ! -L /var/lib/gateway-vpn-vps-privileged ]]
grep -Fxq 'preserve-settings' /var/lib/gateway-vpn-vps/agent/preserved
grep -Fxq 'preserve-wireguard' /etc/wireguard/wg-mgmt.conf

echo 'VPS_UNINSTALL_LIFECYCLE_SYSTEMD_PASS lock=blocked nonterminal=blocked corrupt=blocked terminal=uninstalled preserved=settings+wireguard'
