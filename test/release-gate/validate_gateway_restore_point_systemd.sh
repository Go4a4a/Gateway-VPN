#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
trap 'echo "Gateway restore-point systemd gate failed at line $LINENO" >&2' ERR

MODE=${1:?success-and-crash|post-reboot}
BASE_VERSION=${2:?baseline version}
MIDDLE_VERSION=${3:?middle version}
CURRENT_VERSION=${4:?current version}
MIDDLE_ARCHIVE=${5:?absolute middle signed archive}
CURRENT_ARCHIVE=${6:?absolute current signed archive}
HELPER_ROOT=${7:?absolute helper directory}

DATABASE=/var/lib/gateway-vpn/state.db
CONFIGURATION=/etc/gateway-vpn/config.yaml
JOURNAL=/var/lib/gateway-vpn-privileged/update-transactions/active.json
POINT_ROOT=/var/lib/gateway-vpn-privileged/update-restore-points
REQUEST_ROOT=/var/lib/gateway-vpn-privileged/update-rollback
EVIDENCE=/root/gateway-vpn-restore-point-gate.env
STAGE="$HELPER_ROOT/stage-signed-update"
DEADLINE="$HELPER_ROOT/force-update-deadline"
MARKER="$HELPER_ROOT/restore-point-marker"

[[ $EUID -eq 0 ]] || { echo "Gateway restore-point gate requires root" >&2; exit 1; }
[[ $MODE == success-and-crash || $MODE == post-reboot ]] || { echo "Invalid gate mode" >&2; exit 2; }
for version in "$BASE_VERSION" "$MIDDLE_VERSION" "$CURRENT_VERSION"; do
  [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || { echo "Invalid gate version" >&2; exit 2; }
done
for path in "$MIDDLE_ARCHIVE" "$CURRENT_ARCHIVE" "$STAGE" "$DEADLINE" "$MARKER"; do
  [[ $path == /* && -f $path && ! -L $path ]] || { echo "Unsafe release-gate input: $path" >&2; exit 2; }
done
[[ -x $STAGE && -x $DEADLINE && -x $MARKER ]] || { echo "Release-gate helpers must be executable" >&2; exit 2; }

journal_field() {
  local field=$1
  sed -n 's/^[[:space:]]*"'"$field"'": "\([^"]*\)".*/\1/p' "$JOURNAL" | head -n1
}

wait_journal() {
  local kind=$1 expected=$2 timeout=${3:-1200} state operation
  for _ in $(seq 1 "$timeout"); do
    if [[ -f $JOURNAL ]]; then
      state=$(journal_field state)
      operation=$(journal_field operation_kind)
      [[ $state == "$expected" && $operation == "$kind" ]] && return 0
    fi
    sleep 0.1
  done
  echo "Timed out waiting for $kind/$expected; state=${state:-} operation=${operation:-}" >&2
  systemctl status gateway-vpn-update.service gateway-vpn-update-rollback.service gateway-vpn-update-recovery.service --no-pager >&2 || true
  return 1
}

stage_update() {
  local archive=$1 current=$2
  runuser -u gateway-vpn -- env GATEWAY_VPN_RELEASE_GATE=1 "$STAGE" \
    --archive "$archive" --config "$CONFIGURATION" \
    --trusted-key /etc/gateway-vpn/update-signing.pub \
    --current-release-root "/opt/gateway-vpn/releases/v$current" \
    --current-version "$current" --release-gate-only
  systemctl start --no-block gateway-vpn-update.service
  wait_journal SIGNED_UPDATE STABILIZING
}

finalize_active() {
  local id
  id=$(journal_field update_id)
  [[ -n $id && $(journal_field state) == STABILIZING ]] || { echo "No stabilizing gate transaction" >&2; return 1; }
  # The guarded helper requires a timestamp strictly newer than every real
  # journal write before it moves only this exact transaction's deadline.
  sleep 3
  GATEWAY_VPN_RELEASE_GATE=1 "$DEADLINE" \
    --root /var/lib/gateway-vpn-privileged/update-transactions \
    --expected-update-id "$id" --release-gate-only >/dev/null
  systemctl start gateway-vpn-update-finalize.service
  [[ $(journal_field state) == FINALIZED ]]
}

set_projection_marker() {
  local value=$1
	local generation="restore-gate-$value"
	install -d -o gateway-vpn -g gateway-vpn -m 0750 \
	  "/var/lib/gateway-vpn/mihomo/generations/$generation" \
	  "/var/lib/gateway-vpn/mihomo/generations/$generation/providers"
	printf 'mode: %s\n' "$value" >"/var/lib/gateway-vpn/mihomo/generations/$generation/config.yaml"
	printf 'proxies: [] # %s\n' "$value" >"/var/lib/gateway-vpn/mihomo/generations/$generation/providers/gate.yaml"
	chown gateway-vpn:gateway-vpn \
	  "/var/lib/gateway-vpn/mihomo/generations/$generation/config.yaml" \
	  "/var/lib/gateway-vpn/mihomo/generations/$generation/providers/gate.yaml"
	chmod 0640 \
	  "/var/lib/gateway-vpn/mihomo/generations/$generation/config.yaml" \
	  "/var/lib/gateway-vpn/mihomo/generations/$generation/providers/gate.yaml"
	printf '%s\n' "$generation" >/var/lib/gateway-vpn/mihomo/state/active-generation
	printf '%s\n' "$generation" >/var/lib/gateway-vpn/mihomo/state/lkg-generation
	chown gateway-vpn:gateway-vpn \
	  /var/lib/gateway-vpn/mihomo/state/active-generation \
	  /var/lib/gateway-vpn/mihomo/state/lkg-generation
	chmod 0600 \
	  /var/lib/gateway-vpn/mihomo/state/active-generation \
	  /var/lib/gateway-vpn/mihomo/state/lkg-generation
	ln -sfn "generations/$generation" /var/lib/gateway-vpn/mihomo/.active-restore-gate
	mv -Tf /var/lib/gateway-vpn/mihomo/.active-restore-gate /var/lib/gateway-vpn/mihomo/active
  printf '%s' "$value" >/var/lib/gateway-vpn/secrets/restore-gate.txt
  printf '%s' "$value" >/var/lib/gateway-vpn/secrets/management/restore-gate.key
  printf '%s' "$value" >/var/lib/gateway-vpn/secrets/wireguard-ingress/restore-gate.key
  printf '%s' "$value" >/var/lib/gateway-vpn/tls/restore-gate.txt
  printf '%s' "$value" >/var/lib/gateway-vpn/mihomo/generations/restore-gate.txt
  printf '%s' "$value" >/var/lib/gateway-vpn/mihomo/state/restore-gate.txt
  chown gateway-vpn:gateway-vpn \
    /var/lib/gateway-vpn/secrets/restore-gate.txt \
    /var/lib/gateway-vpn/tls/restore-gate.txt \
    /var/lib/gateway-vpn/mihomo/generations/restore-gate.txt \
    /var/lib/gateway-vpn/mihomo/state/restore-gate.txt
  chown root:root \
    /var/lib/gateway-vpn/secrets/management/restore-gate.key \
    /var/lib/gateway-vpn/secrets/wireguard-ingress/restore-gate.key
  chmod 0600 \
    /var/lib/gateway-vpn/secrets/restore-gate.txt \
    /var/lib/gateway-vpn/secrets/management/restore-gate.key \
    /var/lib/gateway-vpn/secrets/wireguard-ingress/restore-gate.key \
    /var/lib/gateway-vpn/tls/restore-gate.txt \
    /var/lib/gateway-vpn/mihomo/generations/restore-gate.txt \
    /var/lib/gateway-vpn/mihomo/state/restore-gate.txt
  GATEWAY_VPN_RELEASE_GATE=1 "$MARKER" --database "$DATABASE" \
    --value "$value" --set --release-gate-only >/dev/null
}

assert_projection_marker() {
  local value=$1 generation="restore-gate-$1"
  [[ $(GATEWAY_VPN_RELEASE_GATE=1 "$MARKER" --database "$DATABASE" --get --release-gate-only) == "$value" ]]
  for path in \
    /var/lib/gateway-vpn/secrets/restore-gate.txt \
    /var/lib/gateway-vpn/secrets/management/restore-gate.key \
    /var/lib/gateway-vpn/secrets/wireguard-ingress/restore-gate.key \
    /var/lib/gateway-vpn/tls/restore-gate.txt \
    /var/lib/gateway-vpn/mihomo/generations/restore-gate.txt \
    /var/lib/gateway-vpn/mihomo/state/restore-gate.txt; do
    [[ $(<"$path") == "$value" ]]
  done
  [[ $(stat -c '%U:%G:%a' /var/lib/gateway-vpn/secrets/management/restore-gate.key) == root:root:600 ]]
  [[ $(stat -c '%U:%G:%a' /var/lib/gateway-vpn/secrets/wireguard-ingress/restore-gate.key) == root:root:600 ]]
  [[ $(stat -c '%U:%G:%a' /var/lib/gateway-vpn/tls/cert.pem) == gateway-vpn:gateway-vpn:644 ]]
  [[ $(stat -c '%U:%G:%a' /var/lib/gateway-vpn/mihomo/generations) == gateway-vpn:gateway-vpn:750 ]]
	[[ $(readlink /var/lib/gateway-vpn/mihomo/active) == "generations/$generation" ]]
	[[ $(<"/var/lib/gateway-vpn/mihomo/generations/$generation/config.yaml") == "mode: $value" ]]
	[[ $(stat -c '%U:%G:%a' "/var/lib/gateway-vpn/mihomo/generations/$generation") == gateway-vpn:gateway-vpn:750 ]]
	[[ $(stat -c '%U:%G:%a' "/var/lib/gateway-vpn/mihomo/generations/$generation/providers") == gateway-vpn:gateway-vpn:750 ]]
	[[ $(stat -c '%U:%G:%a' "/var/lib/gateway-vpn/mihomo/generations/$generation/config.yaml") == gateway-vpn:gateway-vpn:640 ]]
	[[ $(stat -c '%U:%G:%a' "/var/lib/gateway-vpn/mihomo/generations/$generation/providers/gate.yaml") == gateway-vpn:gateway-vpn:640 ]]
	runuser -u gateway-vpn-mihomo -- test -r "/var/lib/gateway-vpn/mihomo/active/config.yaml"
  [[ $(stat -c '%U:%G:%a' /var/lib/gateway-vpn/subscriptions) == gateway-vpn:gateway-vpn:700 ]]
}

request_rollback() {
  local point=$1 response
  response=$(runuser -u gateway-vpn -- curl --silent --show-error --write-out ' HTTP=%{http_code}' \
    --unix-socket /run/gateway-vpn/network-broker.sock --request POST \
    --header 'Content-Type: application/json' --data "{\"point_id\":\"$point\"}" \
    http://localhost/v1/update/restore-points/rollback)
  [[ $response == ' HTTP=204' ]] || { echo "Rollback broker response: $response" >&2; return 1; }
}

if [[ $MODE == post-reboot ]]; then
  [[ -f $EVIDENCE && ! -L $EVIDENCE && $(stat -c '%u:%g:%a' "$EVIDENCE") == 0:0:600 ]]
  # shellcheck disable=SC1090
  source "$EVIDENCE"
  systemctl is-active --quiet gateway-vpn-update-recovery.service
  [[ $(journal_field operation_kind) == RESTORE_POINT_ROLLBACK ]]
  [[ $(journal_field state) == ROLLED_BACK ]]
  [[ $(journal_field error_code) == BOOT_OR_PROCESS_RECOVERY ]]
  [[ $(readlink /opt/gateway-vpn/current) == "releases/v$MIDDLE_VERSION" ]]
  [[ $(readlink /opt/gateway-vpn/recovery) == "releases/v$MIDDLE_VERSION" ]]
  [[ ! -e $REQUEST_ROOT/pending.json && ! -L $REQUEST_ROOT/pending.json ]]
  assert_projection_marker safety
  grep -Fq '# restore-point-gate: safety' "$CONFIGURATION"
  [[ $(journal_field target_restore_point_id) == "$BASE_POINT" ]]
  [[ $(journal_field restore_point_id) == "$SAFETY_POINT" ]]
  if ! ip link show dev lan0 >/dev/null 2>&1; then
    ip link add lan0 type dummy
    ip link set lan0 up
    networkctl reload
    networkctl reconfigure lan0 || true
  fi
  for _ in $(seq 1 100); do
    ip -4 address show dev lan0 | grep -Fq '192.168.200.1/24' && break
    sleep 0.1
  done
  systemctl restart gateway-vpn-update-resume.service
  systemctl is-active --quiet gateway-vpn.service
  systemctl is-active --quiet gateway-vpn-dnsmasq.service
  [[ -z $(find /var/lib/gateway-vpn /etc/gateway-vpn -name '*.restore-candidate' -print -quit) ]]
  echo "GATEWAY_RESTORE_POINT_REBOOT_RECOVERY_PASS rollback=$(journal_field update_id) safety=$SAFETY_POINT"
  exit 0
fi

[[ $(readlink /opt/gateway-vpn/current) == "releases/v$BASE_VERSION" ]]
[[ $(readlink /opt/gateway-vpn/recovery) == "releases/v$BASE_VERSION" ]]
printf '\n# restore-point-gate: historical\n' >>"$CONFIGURATION"
chown root:gateway-vpn "$CONFIGURATION"
chmod 0640 "$CONFIGURATION"
set_projection_marker historical

nft add table inet amnezia_restore_sentinel
nft add chain inet amnezia_restore_sentinel keep
ip link add amzrst0 type dummy
ip link set amzrst0 up
nft list table inet amnezia_restore_sentinel >/run/foreign-nft.before
ip -details -o link show dev amzrst0 >/run/foreign-link.before

stage_update "$MIDDLE_ARCHIVE" "$BASE_VERSION"
BASE_POINT=$(journal_field restore_point_id)
[[ -d $POINT_ROOT/$BASE_POINT && ! -L $POINT_ROOT/$BASE_POINT ]]
finalize_active
[[ $(readlink /opt/gateway-vpn/recovery) == "releases/v$MIDDLE_VERSION" ]]

stage_update "$CURRENT_ARCHIVE" "$MIDDLE_VERSION"
MIDDLE_POINT=$(journal_field restore_point_id)
[[ -d $POINT_ROOT/$MIDDLE_POINT && ! -L $POINT_ROOT/$MIDDLE_POINT ]]
finalize_active
[[ $(readlink /opt/gateway-vpn/recovery) == "releases/v$CURRENT_VERSION" ]]

printf '# restore-point-gate: newer\n' >>"$CONFIGURATION"
set_projection_marker newer
install -d -o gateway-vpn -g gateway-vpn -m 0700 \
  /var/lib/gateway-vpn/subscriptions/newer-sub \
  /var/lib/gateway-vpn/subscriptions/newer-sub/newer-version
printf 'proxies: []\n' >/var/lib/gateway-vpn/subscriptions/newer-sub/newer-version/payload.yaml
chown gateway-vpn:gateway-vpn /var/lib/gateway-vpn/subscriptions/newer-sub/newer-version/payload.yaml
chmod 0600 /var/lib/gateway-vpn/subscriptions/newer-sub/newer-version/payload.yaml
request_rollback "$MIDDLE_POINT"
wait_journal RESTORE_POINT_ROLLBACK STABILIZING
SUCCESS_ROLLBACK=$(journal_field update_id)
[[ $(readlink /opt/gateway-vpn/current) == "releases/v$MIDDLE_VERSION" ]]
[[ $(readlink /opt/gateway-vpn/recovery) == "releases/v$CURRENT_VERSION" ]]
assert_projection_marker historical
grep -Fq '# restore-point-gate: historical' "$CONFIGURATION"
! grep -Fq '# restore-point-gate: newer' "$CONFIGURATION"
[[ ! -e /var/lib/gateway-vpn/subscriptions/newer-sub ]]
nft list table inet amnezia_restore_sentinel | cmp -s - /run/foreign-nft.before
ip -details -o link show dev amzrst0 | cmp -s - /run/foreign-link.before
finalize_active
[[ $(readlink /opt/gateway-vpn/recovery) == "releases/v$MIDDLE_VERSION" ]]

# Arm a second rollback and kill the fixed helper only after the historical
# projection has replaced the live database. Boot recovery must restore the
# just-created complete safety point and discard the stale request marker.
printf '# restore-point-gate: safety\n' >>"$CONFIGURATION"
set_projection_marker safety
systemctl mask --runtime gateway-vpn-update-resume.service
request_rollback "$BASE_POINT"
crash_state=
for _ in $(seq 1 4000); do
  crash_state=$(journal_field state 2>/dev/null || true)
  case "$crash_state" in
    DATABASE_SWITCHED|RELEASE_SWITCH_PENDING|SWITCHED|HEALTH_CHECKING)
      systemctl kill --kill-who=main --signal=KILL gateway-vpn-update-rollback.service
      break
      ;;
    STABILIZING|ROLLED_BACK|ROLLBACK_FAILED)
      echo "Rollback helper reached terminal state before SIGKILL: $crash_state" >&2
      exit 1
      ;;
  esac
  sleep 0.005
done
[[ $crash_state == DATABASE_SWITCHED || $crash_state == RELEASE_SWITCH_PENDING || $crash_state == SWITCHED || $crash_state == HEALTH_CHECKING ]]
for _ in $(seq 1 300); do
  systemctl is-failed --quiet gateway-vpn-update-rollback.service && break
  sleep 0.05
done
systemctl is-failed --quiet gateway-vpn-update-rollback.service
[[ $(journal_field operation_kind) == RESTORE_POINT_ROLLBACK ]]
[[ $(journal_field state) != ROLLED_BACK && $(journal_field state) != STABILIZING ]]
SAFETY_POINT=$(journal_field restore_point_id)
[[ -d $POINT_ROOT/$SAFETY_POINT && ! -L $POINT_ROOT/$SAFETY_POINT ]]
printf 'BASE_POINT=%q\nMIDDLE_POINT=%q\nSAFETY_POINT=%q\nSUCCESS_ROLLBACK=%q\n' \
  "$BASE_POINT" "$MIDDLE_POINT" "$SAFETY_POINT" "$SUCCESS_ROLLBACK" >"$EVIDENCE"
chmod 0600 "$EVIDENCE"
echo "GATEWAY_RESTORE_POINT_SYSTEMD_PASS rollback=$SUCCESS_ROLLBACK crash_state=$crash_state safety=$SAFETY_POINT"
