#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# This is a Linux-side integration fixture for the first-install handoff.  It
# deliberately runs only the read-only topology command in a disposable
# network namespace.  The installer itself is not allowed to mutate a host
# until this same token has passed; the shell-order assertions below keep that
# boundary visible in CI without pretending that a netns is bare metal.
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
BINARY=${1:-$ROOT/dist/gateway-vpn-netns}
NETWORKAPPLY_TEST=${2:-$ROOT/dist/gateway-vpn-networkapply-test}
[[ $EUID -eq 0 ]] || { echo "initial_topology_preflight.sh requires root" >&2; exit 1; }
[[ -x $BINARY ]] || { echo "Gateway binary is required: $BINARY" >&2; exit 2; }
[[ -x $NETWORKAPPLY_TEST ]] || { echo "networkapply test binary is required: $NETWORKAPPLY_TEST" >&2; exit 2; }
for command in ip base64 sha256sum grep sed awk cmp mkdir date; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done

SUFFIX="$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE_ROOT="$ROOT/.cache/netns/initial-topology-preflight-$SUFFIX"
mkdir -p -- "$EVIDENCE_ROOT"
NS="gvpn-topology-preflight-$$"
cleanup() {
  ip netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ip netns add "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" link add enp2s0 type dummy
ip -n "$NS" link add enp3s0 type dummy
ip -n "$NS" link set enp2s0 up
ip -n "$NS" link set enp3s0 up

snapshot() {
  local output=$1
  {
    echo '[link]'
    ip -n "$NS" -j link
    echo '[address]'
    ip -n "$NS" -j address
    echo '[route]'
    ip -n "$NS" -j route
    echo '[rule]'
    ip -n "$NS" -j rule
  } >"$output"
  sha256sum -- "$output" >"$output.sha256"
}

encode() {
  printf '%s' "$1" | base64 -w0
}

run_check() {
  local label=$1 token=$2 lan_interface=$3 lan_members=$4 expected=$5
  local before="$EVIDENCE_ROOT/$label.before" after="$EVIDENCE_ROOT/$label.after" output="$EVIDENCE_ROOT/$label.output"
  snapshot "$before"
  set +e
  if [[ -n "$lan_members" ]]; then
    ip netns exec "$NS" "$BINARY" initial-topology-check --token "$token" --lan-interface "$lan_interface" --lan-members "$lan_members" >"$output" 2>&1
  else
    ip netns exec "$NS" "$BINARY" initial-topology-check --token "$token" --lan-interface "$lan_interface" >"$output" 2>&1
  fi
  local status=$?
  set -e
  snapshot "$after"
  cmp -s -- "$before" "$after" || { echo "$label changed the host network namespace" >&2; return 1; }
  if [[ "$expected" == PASS && $status -ne 0 ]]; then
    cat "$output" >&2
    echo "$label unexpectedly failed with status $status" >&2
    return 1
  fi
  if [[ "$expected" == FAIL && $status -eq 0 ]]; then
    cat "$output" >&2
    echo "$label unexpectedly accepted an invalid handoff" >&2
    return 1
  fi
  printf 'PASS: %-20s status=%s network_unchanged=true\n' "$label" "$status"
}

DIRECT_TOKEN=$(encode '{"profile":"ETHERNET_HILINK","lan_members":["enp2s0"]}')
BRIDGE_TOKEN=$(encode '{"profile":"ETHERNET_HILINK","lan_members":["enp2s0","enp3s0"]}')
UNKNOWN_TOKEN=$(encode '{"profile":"ETHERNET_HILINK","lan_members":["enp2s0"],"unknown":"rejected"}')
UNSUPPORTED_TOKEN=$(encode '{"profile":"ETHERNET_ETHERNET","lan_members":["enp2s0"],"ethernet_uplinks":[{"interface_name":"enp3s0","address_mode":"DHCP"}]}')

run_check direct_valid "$DIRECT_TOKEN" enp2s0 "" PASS
run_check bridge_valid "$BRIDGE_TOKEN" gateway-vpn-lan enp3s0,enp2s0 PASS
run_check mismatched_interface "$DIRECT_TOKEN" enp3s0 "" FAIL
run_check unknown_field "$UNKNOWN_TOKEN" enp2s0 "" FAIL
run_check unsupported_backend "$UNSUPPORTED_TOKEN" enp2s0 "" FAIL

# Keep the installer ordering contract executable on Linux as well as in the
# Go packaging tests.  The first token check must precede the first potential
# probe/mutation and the apply transaction boundary.
INSTALLER="$ROOT/scripts/install-gateway.sh"
early_line=$(grep -n 'TOPOLOGY_CHECK_ARGS=(initial-topology-check --token' "$INSTALLER" | head -n1 | cut -d: -f1)
wg_probe_line=$(grep -n '^  "\$RELEASE_DIR/bin/gateway-vpn" wireguard-ingress-bootstrap' "$INSTALLER" | head -n1 | cut -d: -f1)
apply_line=$(grep -n '^if ((APPLY)); then$' "$INSTALLER" | tail -n1 | cut -d: -f1)
[[ $early_line =~ ^[0-9]+$ && $wg_probe_line =~ ^[0-9]+$ && $apply_line =~ ^[0-9]+$ ]] || { echo "installer ordering markers are missing" >&2; exit 1; }
((early_line < wg_probe_line && early_line < apply_line)) || { echo "initial topology validation is not before probe/apply" >&2; exit 1; }
echo "PASS: installer validates initial topology before WireGuard probe and apply (lines $early_line < $wg_probe_line,$apply_line)"

# The durable network transaction tests prove that a topology apply is
# confirmable, rolls back to LKG on timeout/partial failure, and rejects a
# tampered snapshot.  They are run here so this fixture covers both the shell
# handoff boundary and the backend rollback boundary.
"$NETWORKAPPLY_TEST" -test.v -test.count=1 -test.run \
  '^(TestUbuntuBackendTopologyApplyCommitIsRecoverableAndRollbackRestoresLKG|TestUbuntuBackendTopologyRollbackRetainsBlockedFirewallAfterPartialFailure|TestUbuntuBackendRejectsTamperedTopologySnapshotMembers|TestRecoverRollsBackUnconfirmedApplyEvenBeforeDeadline)$' \
  >"$EVIDENCE_ROOT/networkapply-rollback.log"
echo "PASS: topology apply/commit/rollback backend contract"
echo "Evidence retained at $EVIDENCE_ROOT"
