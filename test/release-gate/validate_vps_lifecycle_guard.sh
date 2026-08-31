#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

AGENT=${1:?absolute gateway-vpn-vps-agent binary}
[[ $EUID -eq 0 && $AGENT == /* && -x $AGENT && ! -L $AGENT ]] || {
  echo "VPS lifecycle guard gate requires root and a regular executable" >&2
  exit 2
}
for command in flock grep install kill mktemp rm sed seq sleep; do
  command -v "$command" >/dev/null || { echo "Missing lifecycle gate command: $command" >&2; exit 1; }
done

TRANSACTION_ROOT=/var/lib/gateway-vpn-vps-privileged/update-transactions
LOCK=/run/lock/gateway-vpn-vps-install.lock
INSTALL_MARKER=/var/lib/gateway-vpn-vps/install-transactions/active
AUTH_MARKER=/run/gateway-vpn-vps-install-authorized
LIVE_MARKER=/run/gateway-vpn-vps-update-live
UPDATE_ID=vps-update-20260831T120000Z-0123456789abcdef01234567
HOLDER_PID=
TMP=$(mktemp -d)

cleanup() {
  if [[ -n $HOLDER_PID ]]; then
    kill "$HOLDER_PID" >/dev/null 2>&1 || true
    wait "$HOLDER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf /var/lib/gateway-vpn-vps /var/lib/gateway-vpn-vps-privileged "$TMP"
  rm -f "$LOCK" "$AUTH_MARKER" "$LIVE_MARKER" /run/gateway-vpn-vps-lifecycle-ready
}
trap cleanup EXIT
rm -rf /var/lib/gateway-vpn-vps /var/lib/gateway-vpn-vps-privileged
rm -f "$LOCK" "$AUTH_MARKER" "$LIVE_MARKER" /run/gateway-vpn-vps-lifecycle-ready

write_journal() {
  local state=$1 destination=$2
  printf '%s\n' \
    '{' \
    '  "format_version": 1,' \
    "  \"update_id\": \"$UPDATE_ID\"," \
    "  \"state\": \"$state\"," \
    '  "started_at": "2026-08-31T12:00:00Z",' \
    '  "updated_at": "2026-08-31T12:00:00Z",' \
    '  "old_version": "1.1.0",' \
    '  "new_version": "1.2.0",' \
    '  "old_schema": 4,' \
    '  "new_schema": 4,' \
    '  "old_current_target": "releases/v1.1.0",' \
    '  "new_current_target": "releases/v1.2.0",' \
    '  "database_switch_begun": false' \
    '}' >"$destination"
  chmod 0600 "$destination"
}

install -d -o root -g root -m 0700 "$TRANSACTION_ROOT"
install -d -o root -g root -m 0700 "$TRANSACTION_ROOT/$UPDATE_ID"
write_journal FINALIZED "$TRANSACTION_ROOT/$UPDATE_ID/journal.json"
write_journal FINALIZED "$TRANSACTION_ROOT/active.json"
"$AGENT" update-lifecycle-check | grep -Fq 'lifecycle is idle'

write_journal PREPARED "$TRANSACTION_ROOT/$UPDATE_ID/journal.json"
write_journal PREPARED "$TRANSACTION_ROOT/active.json"
if "$AGENT" update-lifecycle-check >"$TMP/nonterminal.out" 2>"$TMP/nonterminal.err"; then
  echo "Nonterminal VPS journal did not block lifecycle" >&2
  exit 1
fi
grep -Fq 'lifecycle is active' "$TMP/nonterminal.err"

write_journal FINALIZED "$TRANSACTION_ROOT/$UPDATE_ID/journal.json"
printf 'corrupt\n' >"$TRANSACTION_ROOT/active.json"
chmod 0600 "$TRANSACTION_ROOT/active.json"
if "$AGENT" update-lifecycle-check >"$TMP/corrupt.out" 2>"$TMP/corrupt.err"; then
  echo "Corrupt VPS active journal did not block lifecycle" >&2
  exit 1
fi
grep -Fq 'unavailable or unsafe' "$TMP/corrupt.err"

rm -rf "$TRANSACTION_ROOT"
"$AGENT" update-lifecycle-check | grep -Fq 'lifecycle is idle'
[[ ! -e $TRANSACTION_ROOT && ! -L $TRANSACTION_ROOT ]]

install -d -o root -g root -m 0755 /run/lock
( exec 8<>"$LOCK"; chmod 0600 "$LOCK"; flock -n 8; : >/run/gateway-vpn-vps-lifecycle-ready; sleep 60 ) &
HOLDER_PID=$!
for _ in $(seq 1 100); do [[ -e /run/gateway-vpn-vps-lifecycle-ready ]] && break; sleep 0.02; done
[[ -e /run/gateway-vpn-vps-lifecycle-ready ]]
if env GATEWAY_VPN_VPS_UPDATE_UNIT=1 "$AGENT" update-apply --config /missing-vps-config.yaml --apply >"$TMP/locked.out" 2>"$TMP/locked.err"; then
  echo "VPS update crossed the shared lifecycle lock" >&2
  exit 1
fi
grep -Fq 'blocked by another Gateway VPN VPS lifecycle transaction' "$TMP/locked.err"
[[ ! -e $LIVE_MARKER && ! -L $LIVE_MARKER ]]

if env GATEWAY_VPN_VPS_UPDATE_RECOVERY_UNIT=1 "$AGENT" update-recover --config /missing-vps-config.yaml --apply >"$TMP/recovery-blocked.out" 2>"$TMP/recovery-blocked.err"; then
  echo "VPS recovery unexpectedly succeeded without install-owner markers" >&2
  exit 1
fi
grep -Fq 'blocked by another Gateway VPN VPS lifecycle transaction' "$TMP/recovery-blocked.err"

install -d -o root -g root -m 0700 /var/lib/gateway-vpn-vps/install-transactions
printf 'install transaction\n' >"$INSTALL_MARKER"
chmod 0600 "$INSTALL_MARKER"
install -o root -g root -m 0600 /dev/null "$AUTH_MARKER"
if env GATEWAY_VPN_VPS_UPDATE_RECOVERY_UNIT=1 "$AGENT" update-recover --config /missing-vps-config.yaml --apply >"$TMP/recovery-owner.out" 2>"$TMP/recovery-owner.err"; then
  echo "Synthetic install-owner recovery unexpectedly reached a complete engine" >&2
  exit 1
fi
grep -Fq 'initialize VPS update recovery failed' "$TMP/recovery-owner.err"
if grep -Fq 'blocked by another Gateway VPN VPS lifecycle transaction' "$TMP/recovery-owner.err"; then
  echo "Verified install owner did not receive the narrow recovery bypass" >&2
  exit 1
fi

kill "$HOLDER_PID"
wait "$HOLDER_PID" >/dev/null 2>&1 || true
HOLDER_PID=
rm -f /run/gateway-vpn-vps-lifecycle-ready "$INSTALL_MARKER" "$AUTH_MARKER"
ln -s "$TMP/sentinel" "$LIVE_MARKER"
printf 'unchanged\n' >"$TMP/sentinel"
if env GATEWAY_VPN_VPS_UPDATE_UNIT=1 "$AGENT" update-apply --config /missing-vps-config.yaml --apply >"$TMP/symlink.out" 2>"$TMP/symlink.err"; then
  echo "VPS update accepted a symlink live marker" >&2
  exit 1
fi
grep -Fq 'create VPS update live marker failed' "$TMP/symlink.err"
grep -Fxq 'unchanged' "$TMP/sentinel"

echo 'VPS_LIFECYCLE_GUARD_PASS terminal=idle nonterminal=blocked corrupt=blocked shared-lock=blocked install-owner=bypassed marker=symlink-safe'
