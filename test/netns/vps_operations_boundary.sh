#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

AGENT_BINARY=${1:-}
[[ $EUID -eq 0 && -x "$AGENT_BINARY" ]] || { echo "usage: sudo vps_operations_boundary.sh /absolute/gateway-vpn-vps-agent" >&2; exit 2; }
[[ ! -e /var/lib/gateway-vpn-vps && ! -e /var/lib/gateway-vpn-vps-privileged ]] || { echo "VPS operations gate requires a disposable clean host" >&2; exit 1; }

ROOT=$(mktemp -d)
cleanup() {
  rm -rf /var/lib/gateway-vpn-vps-privileged /var/lib/gateway-vpn-vps "$ROOT"
}
trap cleanup EXIT

AGENT_USER=nobody
AGENT_GROUP=$(id -gn "$AGENT_USER")
install -d -o root -g "$AGENT_GROUP" -m 0710 /var/lib/gateway-vpn-vps-privileged
install -d -o root -g root -m 0700 /var/lib/gateway-vpn-vps-privileged/restore-transactions /var/lib/gateway-vpn-vps-privileged/fabric
install -d -o root -g "$AGENT_GROUP" -m 0750 /var/lib/gateway-vpn-vps-privileged/operations
install -d -o "$AGENT_USER" -g "$AGENT_GROUP" -m 0700 /var/lib/gateway-vpn-vps/agent
printf '{"schema_version":1,"state":"HEALTHY","checked_at":"2026-08-30T00:00:00Z"}\n' >/var/lib/gateway-vpn-vps/agent/fabric-watchdog.json
chown "$AGENT_USER:$AGENT_GROUP" /var/lib/gateway-vpn-vps/agent/fabric-watchdog.json
chmod 0600 /var/lib/gateway-vpn-vps/agent/fabric-watchdog.json
printf 'root-only-restore-secret\n' >/var/lib/gateway-vpn-vps-privileged/restore-transactions/secret
chmod 0600 /var/lib/gateway-vpn-vps-privileged/restore-transactions/secret

cat >"$ROOT/config.yaml" <<'EOF'
version: 1
system:
  state_directory: /var/lib/gateway-vpn-vps/agent
  database: /var/lib/gateway-vpn-vps/agent/vps-agent.db
  transaction_root: /var/lib/gateway-vpn-vps-privileged/restore-transactions
listen:
  - 127.0.0.1:9443
admin_prefixes:
  - 10.80.0.0/24
tls:
  certificate: /var/lib/gateway-vpn-vps/agent/tls/cert.pem
  private_key: /var/lib/gateway-vpn-vps/agent/tls/key.pem
EOF
chmod 0600 "$ROOT/config.yaml"

"$AGENT_BINARY" operations-collect --config "$ROOT/config.yaml" --agent-user "$AGENT_USER"
SNAPSHOT=/var/lib/gateway-vpn-vps-privileged/operations/snapshot.json
[[ -f "$SNAPSHOT" && ! -L "$SNAPSHOT" ]]
[[ $(stat -c '%U:%G:%a' "$SNAPSHOT") == "root:$AGENT_GROUP:640" ]]
runuser -u "$AGENT_USER" -- test -r "$SNAPSHOT"
if runuser -u "$AGENT_USER" -- test -r /var/lib/gateway-vpn-vps-privileged/restore-transactions/secret; then
  echo "VPS Agent can read a sibling privileged restore secret" >&2
  exit 1
fi
python3 - "$SNAPSHOT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    value = json.load(handle)
assert value["schema_version"] == 1
assert value["state"] in {"HEALTHY", "DEGRADED"}
assert isinstance(value["section_errors"], list)
assert "private_key" not in json.dumps(value["host"]).lower()
PY

echo "PASS: root collector wrote a bounded snapshot readable by Agent while sibling privileged state remained inaccessible"
