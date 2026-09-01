#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

ROOT=/var/lib/gateway-vpn-uninstall
ACTIVE=$ROOT/active
TOOLING=$ROOT/tooling
TOOLING_READY=$ROOT/tooling-ready
HELPER=/usr/libexec/gateway-vpn-uninstall-job
UNIT=/etc/systemd/system/gateway-vpn-uninstall.service
LOCK_FILE=/run/lock/gateway-vpn-install.lock

[[ $EUID -eq 0 && ${GATEWAY_VPN_UNINSTALL_UNIT:-} == 1 ]] || { echo "Gateway uninstall helper may only run from its fixed root unit" >&2; exit 1; }
[[ -f $HELPER && ! -L $HELPER && $(stat -c '%u:%g:%a' "$HELPER") == 0:0:700 ]] || { echo "Gateway uninstall helper projection is unsafe" >&2; exit 1; }
[[ -f $UNIT && ! -L $UNIT && $(stat -c '%u:%g:%a' "$UNIT") == 0:0:644 ]] || { echo "Gateway uninstall unit projection is unsafe" >&2; exit 1; }
[[ -d $ROOT && ! -L $ROOT && $(stat -c '%u:%g:%a' "$ROOT") == 0:0:700 ]] || { echo "Gateway uninstall root is unsafe" >&2; exit 1; }
[[ -f $ACTIVE && ! -L $ACTIVE && $(stat -c '%u:%g:%a' "$ACTIVE") == 0:0:600 ]] || { echo "Gateway uninstall marker is unsafe" >&2; exit 1; }
[[ $(stat -c '%s' "$ACTIVE") -le 256 && $(wc -l <"$ACTIVE") == 3 ]] || { echo "Gateway uninstall marker size or schema is invalid" >&2; exit 1; }
[[ $(grep -Ec '^(format|operation_id|mode)=' "$ACTIVE") == 3 ]] || { echo "Gateway uninstall marker fields are invalid" >&2; exit 1; }
for key in format operation_id mode; do
  [[ $(grep -c "^${key}=" "$ACTIVE") == 1 ]] || { echo "Gateway uninstall marker contains duplicate or missing fields" >&2; exit 1; }
done
FORMAT=$(sed -n 's/^format=//p' "$ACTIVE")
OPERATION_ID=$(sed -n 's/^operation_id=//p' "$ACTIVE")
MODE=$(sed -n 's/^mode=//p' "$ACTIVE")
[[ $FORMAT == 1 && $OPERATION_ID =~ ^uninstall-[a-f0-9]{32}$ ]] || { echo "Gateway uninstall marker identity is invalid" >&2; exit 1; }
[[ $MODE == PRESERVE_DATA || $MODE == PURGE_DATA ]] || { echo "Gateway uninstall mode is invalid" >&2; exit 1; }
RECEIPT=$ROOT/completed-$OPERATION_ID

cleanup_guardian() {
  systemctl disable gateway-vpn-uninstall.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/multi-user.target.wants/gateway-vpn-uninstall.service "$UNIT" "$HELPER"
  systemctl daemon-reload || true
}

if [[ -e $RECEIPT || -L $RECEIPT ]]; then
  [[ -f $RECEIPT && ! -L $RECEIPT && $(stat -c '%u:%g:%a' "$RECEIPT") == 0:0:600 ]] || { echo "Gateway uninstall receipt is unsafe" >&2; exit 1; }
  grep -Fxq "operation_id=$OPERATION_ID" "$RECEIPT" || { echo "Gateway uninstall receipt identity differs" >&2; exit 1; }
  grep -Fxq "mode=$MODE" "$RECEIPT" || { echo "Gateway uninstall receipt mode differs" >&2; exit 1; }
  rm -f "$ACTIVE"
  rm -rf "$TOOLING" "$TOOLING_READY"
  sync -f "$ROOT"
  cleanup_guardian
  exit 0
fi

[[ -d /run/lock && ! -L /run/lock && $(stat -c '%u' /run/lock) == 0 ]] || { echo "Gateway runtime lock directory is unavailable" >&2; exit 1; }
if [[ ! -e $LOCK_FILE && ! -L $LOCK_FILE ]]; then
  (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create Gateway transaction lock safely" >&2; exit 1; }
fi
[[ -f $LOCK_FILE && ! -L $LOCK_FILE && $(stat -c '%u:%g:%a' "$LOCK_FILE") == 0:0:600 ]] || { echo "Gateway transaction lock is unsafe" >&2; exit 1; }
exec 9<>"$LOCK_FILE"
flock -n 9 || { echo "Another Gateway lifecycle transaction is active" >&2; exit 1; }
[[ ! -e /var/lib/gateway-vpn-privileged/install-transactions/active && ! -L /var/lib/gateway-vpn-privileged/install-transactions/active ]] || { echo "Gateway installation recovery is active" >&2; exit 1; }
[[ ! -e /var/lib/gateway-vpn-host-upgrade/active && ! -L /var/lib/gateway-vpn-host-upgrade/active ]] || { echo "Gateway host-upgrade recovery is active" >&2; exit 1; }
for pending in /var/lib/gateway-vpn/update-staging/pending-update.json /var/lib/gateway-vpn-privileged/update-rollback/pending.json /var/lib/gateway-vpn/recovery/pending-restore.json; do
  [[ ! -e $pending && ! -L $pending ]] || { echo "Gateway update or restore transaction is active" >&2; exit 1; }
done

validate_tooling() {
  [[ -d $TOOLING && ! -L $TOOLING && $(stat -c '%u:%g:%a' "$TOOLING") == 0:0:700 ]] || return 1
  [[ -f $TOOLING_READY && ! -L $TOOLING_READY && $(stat -c '%u:%g:%a' "$TOOLING_READY") == 0:0:600 ]] || return 1
  [[ $(wc -l <"$TOOLING_READY") == 5 ]] || return 1
  local file key expected actual
  for file in gateway-vpn gateway-vpnctl uninstall.sh update-signing.pub; do
    [[ -f $TOOLING/$file && ! -L $TOOLING/$file ]] || return 1
    if [[ $file == update-signing.pub ]]; then
      [[ $(stat -c '%u:%g:%a' "$TOOLING/$file") == 0:0:600 ]] || return 1
    else
      [[ $(stat -c '%u:%g:%a' "$TOOLING/$file") == 0:0:700 ]] || return 1
    fi
    key=${file}_sha256
    expected=$(grep -F "${key}=" "$TOOLING_READY" | cut -d= -f2-)
    [[ $expected =~ ^[a-f0-9]{64}$ ]] || return 1
    actual=$(sha256sum --binary "$TOOLING/$file" | awk '{print $1}')
    [[ $actual == "$expected" ]] || return 1
  done
  grep -Fxq 'format=1' "$TOOLING_READY"
}

if ! validate_tooling; then
  [[ ! -e $TOOLING_READY && ! -L $TOOLING_READY ]] || { echo "Gateway uninstall completed tooling is unsafe" >&2; exit 1; }
  if [[ -e $TOOLING || -L $TOOLING ]]; then
    [[ -d $TOOLING && ! -L $TOOLING && $(stat -c '%u:%g:%a' "$TOOLING") == 0:0:700 ]] || { echo "Interrupted Gateway uninstall tooling root is unsafe" >&2; exit 1; }
    mapfile -t TOOLING_ENTRIES < <(find "$TOOLING" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
    for entry in "${TOOLING_ENTRIES[@]}"; do
      [[ $entry == gateway-vpn || $entry == gateway-vpnctl || $entry == uninstall.sh || $entry == update-signing.pub ]] || { echo "Interrupted Gateway uninstall tooling has unknown entries" >&2; exit 1; }
      [[ -f $TOOLING/$entry && ! -L $TOOLING/$entry ]] || { echo "Interrupted Gateway uninstall tooling entry is unsafe" >&2; exit 1; }
    done
    rm -rf "$TOOLING"
  fi
  if [[ -e $ROOT/.tooling-ready.tmp || -L $ROOT/.tooling-ready.tmp ]]; then
    [[ -f $ROOT/.tooling-ready.tmp && ! -L $ROOT/.tooling-ready.tmp && $(stat -c '%u:%g:%a' "$ROOT/.tooling-ready.tmp") == 0:0:600 ]] || { echo "Interrupted Gateway uninstall tooling marker is unsafe" >&2; exit 1; }
    rm -f "$ROOT/.tooling-ready.tmp"
  fi
  [[ -L /opt/gateway-vpn/current ]] || { echo "Installed Gateway current release pointer is unavailable" >&2; exit 1; }
  CURRENT_TARGET=$(readlink /opt/gateway-vpn/current)
  [[ $CURRENT_TARGET =~ ^releases/v(.+)$ ]] || { echo "Installed Gateway current release pointer is invalid" >&2; exit 1; }
  CURRENT_VERSION=${BASH_REMATCH[1]}
  [[ $CURRENT_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || { echo "Installed Gateway version is invalid" >&2; exit 1; }
  CURRENT_RELEASE=/opt/gateway-vpn/releases/v$CURRENT_VERSION
  [[ -d $CURRENT_RELEASE && ! -L $CURRENT_RELEASE && -x $CURRENT_RELEASE/bin/gateway-vpn && -x $CURRENT_RELEASE/bin/gateway-vpnctl && -x $CURRENT_RELEASE/scripts/uninstall.sh ]] || { echo "Installed Gateway release is incomplete" >&2; exit 1; }
  [[ -f /etc/gateway-vpn/update-signing.pub && ! -L /etc/gateway-vpn/update-signing.pub && $(stat -c '%u:%a' /etc/gateway-vpn/update-signing.pub) == 0:644 ]] || { echo "Trusted Gateway update key is unavailable or unsafe" >&2; exit 1; }
  "$CURRENT_RELEASE/bin/gateway-vpnctl" release-verify --release-dir "$CURRENT_RELEASE" --public-key /etc/gateway-vpn/update-signing.pub --current-version 0.0.0 --current-schema 1 >/dev/null
  cmp -s -- "$HELPER" "$CURRENT_RELEASE/scripts/run-gateway-uninstall-job.sh" || { echo "Installed Gateway uninstall helper differs from the signed release" >&2; exit 1; }
  cmp -s -- "$UNIT" "$CURRENT_RELEASE/packaging/systemd/gateway-vpn-uninstall.service" || { echo "Installed Gateway uninstall unit differs from the signed release" >&2; exit 1; }
  install -d -m 0700 "$TOOLING"
  install -m 0700 "$CURRENT_RELEASE/bin/gateway-vpn" "$TOOLING/gateway-vpn"
  install -m 0700 "$CURRENT_RELEASE/bin/gateway-vpnctl" "$TOOLING/gateway-vpnctl"
  install -m 0700 "$CURRENT_RELEASE/scripts/uninstall.sh" "$TOOLING/uninstall.sh"
  install -m 0600 /etc/gateway-vpn/update-signing.pub "$TOOLING/update-signing.pub"
  TOOLING_TMP=$ROOT/.tooling-ready.tmp
  printf 'format=1\ngateway-vpn_sha256=%s\ngateway-vpnctl_sha256=%s\nuninstall.sh_sha256=%s\nupdate-signing.pub_sha256=%s\n' \
    "$(sha256sum --binary "$TOOLING/gateway-vpn" | awk '{print $1}')" \
    "$(sha256sum --binary "$TOOLING/gateway-vpnctl" | awk '{print $1}')" \
    "$(sha256sum --binary "$TOOLING/uninstall.sh" | awk '{print $1}')" \
    "$(sha256sum --binary "$TOOLING/update-signing.pub" | awk '{print $1}')" >"$TOOLING_TMP"
  chmod 0600 "$TOOLING_TMP"
  sync -f "$TOOLING_TMP"
  mv -T "$TOOLING_TMP" "$TOOLING_READY"
  sync -f "$ROOT"
  validate_tooling || { echo "Prepared Gateway uninstall tooling failed verification" >&2; exit 1; }
fi

"$TOOLING/gateway-vpn" update-lifecycle-check >/dev/null || { echo "Gateway update lifecycle is active or unsafe" >&2; exit 1; }

# Install the signed boot policy before stopping any process. The exact copied
# binary atomically replaces only the owned table; loading the static table text
# over an existing table would append duplicate rules on every guardian retry.
if [[ -f /etc/gateway-vpn/nftables/boot.nft && ! -L /etc/gateway-vpn/nftables/boot.nft ]]; then
  [[ $(stat -c '%u:%a' /etc/gateway-vpn/nftables/boot.nft) == 0:640 ]] || { echo "Gateway boot firewall ownership or mode is unsafe" >&2; exit 1; }
  "$TOOLING/gateway-vpn" firewall-boot --config /etc/gateway-vpn/config.yaml --apply
  /usr/sbin/nft list chain inet gateway_vpn forward | grep -F 'gateway-vpn PATH_BLOCKED' >/dev/null
elif /usr/sbin/nft list table inet gateway_vpn >/dev/null 2>&1; then
  /usr/sbin/nft list chain inet gateway_vpn forward | grep -F 'gateway-vpn PATH_BLOCKED' >/dev/null || { echo "Gateway firewall is not fail-closed during uninstall retry" >&2; exit 1; }
fi

UNINSTALL_ARGS=(--apply)
[[ $MODE != PURGE_DATA ]] || UNINSTALL_ARGS=(--purge-data --apply)
GATEWAY_VPN_UNINSTALL_GUARDIAN=1 "$TOOLING/uninstall.sh" "${UNINSTALL_ARGS[@]}"

RECEIPT_TMP=$ROOT/.receipt.tmp
if [[ -e $RECEIPT_TMP || -L $RECEIPT_TMP ]]; then
  [[ -f $RECEIPT_TMP && ! -L $RECEIPT_TMP && $(stat -c '%u:%g:%a' "$RECEIPT_TMP") == 0:0:600 ]] || { echo "Interrupted Gateway uninstall receipt temporary is unsafe" >&2; exit 1; }
  rm -f "$RECEIPT_TMP"
fi
printf 'format=1\noperation_id=%s\nmode=%s\nresult=SUCCEEDED\ncompleted_at=%s\npackages_removed=0\n' \
  "$OPERATION_ID" "$MODE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$RECEIPT_TMP"
chmod 0600 "$RECEIPT_TMP"
sync -f "$RECEIPT_TMP"
mv -T "$RECEIPT_TMP" "$RECEIPT"
sync -f "$ROOT"
rm -f "$ACTIVE"
rm -rf "$TOOLING" "$TOOLING_READY"
sync -f "$ROOT"
cleanup_guardian
echo "Gateway VPN uninstall completed; receipt: $RECEIPT"
