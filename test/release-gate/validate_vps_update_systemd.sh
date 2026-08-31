#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
trap 'echo "VPS update systemd gate failed at line $LINENO" >&2' ERR

BASE_VERSION=${1:?baseline version}
SUCCESS_VERSION=${2:?successful update version}
SUCCESS_ARCHIVE=${3:?absolute successful signed archive}
INTERRUPTED_VERSION=${4:?interrupted update version}
INTERRUPTED_ARCHIVE=${5:?absolute interrupted signed archive}
STAGE_HELPER=${6:?absolute stage helper}
DEADLINE_HELPER=${7:?absolute deadline helper}

[[ $EUID -eq 0 ]] || { echo "VPS update systemd gate requires root" >&2; exit 1; }
for version in "$BASE_VERSION" "$SUCCESS_VERSION" "$INTERRUPTED_VERSION"; do
  [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || { echo "Invalid release-gate version" >&2; exit 2; }
done
for path in "$SUCCESS_ARCHIVE" "$INTERRUPTED_ARCHIVE" "$STAGE_HELPER" "$DEADLINE_HELPER"; do
  [[ $path == /* && -f $path && ! -L $path ]] || { echo "Release-gate input must be an absolute regular file: $path" >&2; exit 2; }
done
[[ -x $STAGE_HELPER && -x $DEADLINE_HELPER ]] || { echo "Release-gate helpers must be executable" >&2; exit 2; }

SCHEMA=$(/opt/gateway-vpn-vps/current/bin/gateway-vpn-vps-agent --schema-version)
[[ $SCHEMA =~ ^[1-9][0-9]*$ ]]
[[ $(readlink /opt/gateway-vpn-vps/current) == "releases/v$BASE_VERSION" ]]
[[ $(readlink /opt/gateway-vpn-vps/recovery) == "releases/v$BASE_VERSION" ]]

install -d -m 0755 /run/gateway-vpn-vps-release-gate
install -m 0644 "$SUCCESS_ARCHIVE" /run/gateway-vpn-vps-release-gate/success.tar.gz
install -m 0644 "$INTERRUPTED_ARCHIVE" /run/gateway-vpn-vps-release-gate/interrupted.tar.gz

/usr/sbin/nft add table inet amnezia_update_sentinel
/usr/sbin/nft add chain inet amnezia_update_sentinel keep
/usr/sbin/ip link add amnezia-update0 type dummy
/usr/sbin/ip link set amnezia-update0 up
FOREIGN_NFT_BEFORE=$(/usr/sbin/nft list table inet amnezia_update_sentinel)
FOREIGN_LINK_BEFORE=$(/usr/sbin/ip -details -o link show dev amnezia-update0)

stage() {
  local archive=$1 current=$2
  runuser -u gateway-vpn-vps -- env GATEWAY_VPN_RELEASE_GATE=1 "$STAGE_HELPER" \
    --archive "$archive" --current-version "$current" --current-schema "$SCHEMA" \
    --profile ubuntu-24.04 --release-gate-only
}

trigger_update() {
  install -o gateway-vpn-vps -g gateway-vpn-vps -m 0600 /dev/null /var/lib/gateway-vpn-vps/agent/update.trigger
  systemctl start --no-block gateway-vpn-vps-update.service
}

wait_state() {
  local expected=$1 timeout=${2:-90} start state
  start=$(date +%s)
  while (( $(date +%s) - start < timeout )); do
    state=$(python3 - <<'PY'
import json
try:
    with open('/var/lib/gateway-vpn-vps-privileged/update-transactions/active.json', encoding='utf-8') as handle:
        print(json.load(handle).get('state', ''))
except (FileNotFoundError, json.JSONDecodeError):
    print('')
PY
)
    [[ $state == "$expected" ]] && return 0
    sleep 0.05
  done
  echo "Timed out waiting for VPS update state $expected; last=$state" >&2
  systemctl status gateway-vpn-vps-update.service gateway-vpn-vps-update-recovery.service --no-pager >&2 || true
  return 1
}

SUCCESS_ID=$(stage /run/gateway-vpn-vps-release-gate/success.tar.gz "$BASE_VERSION")
trigger_update
wait_state STABILIZING
systemctl is-active --quiet gateway-vpn-vps-agent.service
[[ $(readlink /opt/gateway-vpn-vps/current) == "releases/v$SUCCESS_VERSION" ]]
[[ $(readlink /opt/gateway-vpn-vps/recovery) == "releases/v$BASE_VERSION" ]]
[[ $(/opt/gateway-vpn-vps/current/bin/gateway-vpn-vps-agent --version) == "gateway-vpn-vps-agent $SUCCESS_VERSION "* ]]
# The guarded helper requires its synthetic updated_at to remain strictly
# newer than every real journal write while the forced deadline stays in the
# past. A fast container can reach STABILIZING in well under two seconds.
sleep 3
GATEWAY_VPN_RELEASE_GATE=1 "$DEADLINE_HELPER" --expected-update-id "$SUCCESS_ID" --release-gate-only >/dev/null
systemctl start gateway-vpn-vps-update-finalize.service
[[ $(readlink /opt/gateway-vpn-vps/current) == "releases/v$SUCCESS_VERSION" ]]
[[ $(readlink /opt/gateway-vpn-vps/recovery) == "releases/v$SUCCESS_VERSION" ]]
[[ ! -e /var/lib/gateway-vpn-vps-privileged/update-transactions/active.json ]]

INTERRUPTED_ID=$(stage /run/gateway-vpn-vps-release-gate/interrupted.tar.gz "$SUCCESS_VERSION")
trigger_update
wait_state HEALTH_CHECKING
systemctl kill --kill-who=main --signal=KILL gateway-vpn-vps-update.service
for _ in $(seq 1 600); do
  [[ ! -e /var/lib/gateway-vpn-vps-privileged/update-transactions/active.json ]] && break
  sleep 0.1
done
[[ ! -e /var/lib/gateway-vpn-vps-privileged/update-transactions/active.json ]]
for _ in $(seq 1 300); do
  systemctl is-active --quiet gateway-vpn-vps-agent.service && break
  sleep 0.1
done
if ! systemctl is-active --quiet gateway-vpn-vps-agent.service; then
  systemctl status gateway-vpn-vps-agent.service gateway-vpn-vps-update-recovery.service --no-pager >&2 || true
  echo "VPS Agent did not become active after asynchronous rollback recovery" >&2
  exit 1
fi
[[ $(readlink /opt/gateway-vpn-vps/current) == "releases/v$SUCCESS_VERSION" ]]
[[ $(readlink /opt/gateway-vpn-vps/recovery) == "releases/v$SUCCESS_VERSION" ]]
[[ $(/opt/gateway-vpn-vps/current/bin/gateway-vpn-vps-agent --version) == "gateway-vpn-vps-agent $SUCCESS_VERSION "* ]]
python3 - <<PY
import json
with open('/var/lib/gateway-vpn-vps/agent/update-status.json', encoding='utf-8') as handle:
    status=json.load(handle)
assert status['state'] == 'ROLLED_BACK', status
assert status['candidate_version'] == '$INTERRUPTED_VERSION', status
assert status['current_version'] == '$SUCCESS_VERSION', status
PY

[[ $(/usr/sbin/nft list table inet amnezia_update_sentinel) == "$FOREIGN_NFT_BEFORE" ]]
[[ $(/usr/sbin/ip -details -o link show dev amnezia-update0) == "$FOREIGN_LINK_BEFORE" ]]
/opt/gateway-vpn-vps/current/bin/gateway-vpn-vps-agent state-check --config /etc/gateway-vpn-vps/config.yaml
[[ -z $(systemctl --failed --no-legend --plain | grep -v '^gateway-vpn-vps-update.service ' || true) ]]

echo "VPS_UPDATE_SYSTEMD_GATE_PASS success=$SUCCESS_ID interrupted=$INTERRUPTED_ID rollback=$SUCCESS_VERSION"
