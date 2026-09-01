#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

APPLY=0
INSTALL_DEPENDENCIES=0
ENABLE_DHCP=0
ENABLE_SSH=1
ENABLE_WIREGUARD_INGRESS=0
RELEASE_DIR=""
TRUSTED_UPDATE_KEY=""
RELEASE_VERSION=""
LAN_INTERFACE=""
LAN_MEMBERS=""
LAN_ADDRESS=""
LOG_READER_USER=""
BOOT_NETWORK_POLICY=""
GRUB_POLICY=""
WIREGUARD_ENDPOINT_HOST=""
WIREGUARD_SUBNET=""
WIREGUARD_LISTEN_PORT=""
WIREGUARD_CLIENT_DNS=""

usage() {
  echo "Usage: upgrade-gateway-host.sh --release-dir DIR --trusted-update-key FILE --version VERSION --lan-interface IFACE --lan-address CIDR --log-reader-user USER --boot-network-policy POLICY --grub-policy POLICY [--lan-members LIST] [--install-dependencies] [--enable-dhcp] [--disable-ssh] [--enable-wireguard-ingress and its four values] [--apply]"
}

while (($#)); do
  case "$1" in
    --release-dir) RELEASE_DIR=${2:?}; shift 2 ;;
    --trusted-update-key) TRUSTED_UPDATE_KEY=${2:?}; shift 2 ;;
    --version) RELEASE_VERSION=${2:?}; shift 2 ;;
    --lan-interface) LAN_INTERFACE=${2:?}; shift 2 ;;
    --lan-members) LAN_MEMBERS=${2:?}; shift 2 ;;
    --lan-address) LAN_ADDRESS=${2:?}; shift 2 ;;
    --log-reader-user) LOG_READER_USER=${2:?}; shift 2 ;;
    --boot-network-policy) BOOT_NETWORK_POLICY=${2:?}; shift 2 ;;
    --grub-policy) GRUB_POLICY=${2:?}; shift 2 ;;
    --install-dependencies) INSTALL_DEPENDENCIES=1; shift ;;
    --enable-dhcp) ENABLE_DHCP=1; shift ;;
    --disable-ssh) ENABLE_SSH=0; shift ;;
    --enable-wireguard-ingress) ENABLE_WIREGUARD_INGRESS=1; shift ;;
    --wireguard-endpoint-host) WIREGUARD_ENDPOINT_HOST=${2:?}; shift 2 ;;
    --wireguard-subnet) WIREGUARD_SUBNET=${2:?}; shift 2 ;;
    --wireguard-listen-port) WIREGUARD_LISTEN_PORT=${2:?}; shift 2 ;;
    --wireguard-client-dns) WIREGUARD_CLIENT_DNS=${2:?}; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n $RELEASE_DIR && -n $TRUSTED_UPDATE_KEY && -n $RELEASE_VERSION && -n $LAN_INTERFACE && -n $LAN_ADDRESS && -n $LOG_READER_USER && -n $BOOT_NETWORK_POLICY && -n $GRUB_POLICY ]] || { usage >&2; exit 2; }
[[ $EUID -eq 0 || $APPLY == 0 ]] || { echo "Host-contract upgrade --apply requires root" >&2; exit 1; }
VERSION_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$'
[[ $RELEASE_VERSION =~ $VERSION_PATTERN && $LAN_INTERFACE =~ ^[A-Za-z0-9_.:-]{1,15}$ && $LAN_ADDRESS =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[12][0-9]|30)$ ]] || { echo "Host-contract upgrade identity or LAN syntax is invalid" >&2; exit 2; }
[[ $LOG_READER_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ && $LOG_READER_USER != root ]] || { echo "Host-contract upgrade log reader is invalid" >&2; exit 2; }
[[ $BOOT_NETWORK_POLICY == gateway-nonblocking || $BOOT_NETWORK_POLICY == keep ]] || { echo "Host-contract upgrade boot-network policy is invalid" >&2; exit 2; }
[[ $GRUB_POLICY == automatic-hidden || $GRUB_POLICY == menu-5s || $GRUB_POLICY == keep ]] || { echo "Host-contract upgrade GRUB policy is invalid" >&2; exit 2; }
((ENABLE_WIREGUARD_INGRESS == 1)) || [[ -z $WIREGUARD_ENDPOINT_HOST && -z $WIREGUARD_SUBNET && -z $WIREGUARD_LISTEN_PORT && -z $WIREGUARD_CLIENT_DNS ]] || { echo "WireGuard values require enabled ingress" >&2; exit 2; }

RELEASE_DIR=$(realpath -e -- "$RELEASE_DIR")
TRUSTED_UPDATE_KEY=$(realpath -e -- "$TRUSTED_UPDATE_KEY")
[[ -d $RELEASE_DIR && ! -L $RELEASE_DIR && -x $RELEASE_DIR/bin/gateway-vpn && -x $RELEASE_DIR/bin/gateway-vpnctl && -x $RELEASE_DIR/scripts/install-gateway.sh && -x $RELEASE_DIR/scripts/recover-gateway-host-upgrade.sh && -f $RELEASE_DIR/packaging/systemd/gateway-vpn-host-upgrade-recovery.service ]] || { echo "Signed host-upgrade release is incomplete" >&2; exit 1; }
[[ -f $TRUSTED_UPDATE_KEY && ! -L $TRUSTED_UPDATE_KEY ]] || { echo "Trusted update key is unsafe" >&2; exit 1; }
case "$RELEASE_DIR/" in
  /opt/gateway-vpn/*|/etc/gateway-vpn/*|/var/lib/gateway-vpn/*|/var/lib/gateway-vpn-privileged/*|/var/lib/gateway-vpn-host-upgrade/*)
    echo "Candidate release must be outside every installed or rollback state root" >&2
    exit 1
    ;;
esac
[[ -L /opt/gateway-vpn/current && -L /opt/gateway-vpn/recovery ]] || { echo "A complete installed Gateway release is required for host upgrade" >&2; exit 1; }
CURRENT_TARGET=$(readlink /opt/gateway-vpn/current)
RECOVERY_TARGET=$(readlink /opt/gateway-vpn/recovery)
[[ $CURRENT_TARGET =~ ^releases/v(.+)$ && $RECOVERY_TARGET == "$CURRENT_TARGET" ]] || { echo "Current/recovery must reference one finalized Gateway release before host upgrade" >&2; exit 1; }
OLD_VERSION=${BASH_REMATCH[1]}
[[ $OLD_VERSION =~ $VERSION_PATTERN && $OLD_VERSION != "$RELEASE_VERSION" ]] || { echo "Host upgrade requires two different strict release versions" >&2; exit 1; }
OLD_RELEASE=/opt/gateway-vpn/releases/v$OLD_VERSION
[[ -d $OLD_RELEASE && ! -L $OLD_RELEASE && -x $OLD_RELEASE/bin/gateway-vpn && -x $OLD_RELEASE/bin/gateway-vpnctl ]] || { echo "Installed old release tree is unsafe" >&2; exit 1; }
[[ ! -e /opt/gateway-vpn/releases/v$RELEASE_VERSION && ! -L /opt/gateway-vpn/releases/v$RELEASE_VERSION ]] || { echo "Candidate release destination already exists" >&2; exit 1; }
[[ -f /etc/gateway-vpn/update-signing.pub && ! -L /etc/gateway-vpn/update-signing.pub && $(sha256sum "$TRUSTED_UPDATE_KEY" | awk '{print $1}') == $(sha256sum /etc/gateway-vpn/update-signing.pub | awk '{print $1}') ]] || { echo "Candidate and installed trusted update keys differ" >&2; exit 1; }
[[ -d /etc/gateway-vpn && ! -L /etc/gateway-vpn && $(stat -c '%u' /etc/gateway-vpn) == 0 && -f /etc/gateway-vpn/config.yaml && ! -L /etc/gateway-vpn/config.yaml ]] || { echo "Installed Gateway configuration root is unsafe" >&2; exit 1; }
[[ -f /var/lib/gateway-vpn/install-report.json && ! -L /var/lib/gateway-vpn/install-report.json && $(stat -c '%u:%g:%a' /var/lib/gateway-vpn/install-report.json) == 0:0:600 ]] || { echo "Installed Gateway report is unsafe" >&2; exit 1; }
[[ -d /var/lib/gateway-vpn && ! -L /var/lib/gateway-vpn && -f /var/lib/gateway-vpn/state.db && ! -L /var/lib/gateway-vpn/state.db ]] || { echo "Installed Gateway database root is unsafe" >&2; exit 1; }

release_number() { sed -n "s/.*\"$1\": \([0-9][0-9]*\).*/\1/p" "$2"; }
release_string() { sed -n "s/.*\"$1\": \"\([^\"]*\)\".*/\1/p" "$2"; }
OLD_SCHEMA=$(release_number database_schema_maximum "$OLD_RELEASE/release.json")
OLD_HOST_CONTRACT=$(release_string host_contract_sha256 "$OLD_RELEASE/release.json")
OLD_METADATA_VERSION=$(release_string gateway_version "$OLD_RELEASE/release.json")
NEW_SCHEMA=$(release_number database_schema_maximum "$RELEASE_DIR/release.json")
NEW_HOST_CONTRACT=$(release_string host_contract_sha256 "$RELEASE_DIR/release.json")
NEW_METADATA_VERSION=$(release_string gateway_version "$RELEASE_DIR/release.json")
[[ $OLD_SCHEMA =~ ^[1-9][0-9]*$ && $NEW_SCHEMA =~ ^[1-9][0-9]*$ && $NEW_SCHEMA -ge $OLD_SCHEMA ]] || { echo "Host-upgrade release schema metadata is invalid" >&2; exit 1; }
[[ $OLD_METADATA_VERSION == "$OLD_VERSION" && $NEW_METADATA_VERSION == "$RELEASE_VERSION" ]] || { echo "Host-upgrade version does not match signed release metadata" >&2; exit 1; }
[[ $OLD_HOST_CONTRACT =~ ^[0-9a-f]{64}$ && $NEW_HOST_CONTRACT =~ ^[0-9a-f]{64}$ && $OLD_HOST_CONTRACT != "$NEW_HOST_CONTRACT" ]] || { echo "Use pointer-only signed update when host lifecycle contracts are equal" >&2; exit 1; }
"$OLD_RELEASE/bin/gateway-vpnctl" release-verify --release-dir "$OLD_RELEASE" --public-key /etc/gateway-vpn/update-signing.pub --current-version 0.0.0 --current-schema 1 >/dev/null
"$RELEASE_DIR/bin/gateway-vpnctl" release-verify --release-dir "$RELEASE_DIR" --public-key /etc/gateway-vpn/update-signing.pub --current-version "$OLD_VERSION" --current-schema "$OLD_SCHEMA" >/dev/null
[[ $("$RELEASE_DIR/bin/gateway-vpn" --version) == "gateway-vpn $RELEASE_VERSION "* ]] || { echo "Candidate binary version does not match signed host-upgrade version" >&2; exit 1; }
"$RELEASE_DIR/bin/gateway-vpnctl" database-verify --database /var/lib/gateway-vpn/state.db --expected-schema "$OLD_SCHEMA" --json >/dev/null

report_string() { sed -n "s/^[[:space:]]*\"$1\": \"\([^\"]*\)\",\{0,1\}$/\1/p" /var/lib/gateway-vpn/install-report.json; }
report_bool() { sed -n "s/^[[:space:]]*\"$1\": \(true\|false\),\{0,1\}$/\1/p" /var/lib/gateway-vpn/install-report.json; }

candidate_runtime_ready() {
  local now status_mtime control_mtime status_age control_age status_size control_size
  [[ -f /run/gateway-vpn-watchdog/status.json && ! -L /run/gateway-vpn-watchdog/status.json ]] || return 1
  [[ -f /run/gateway-vpn-watchdog/control.json && ! -L /run/gateway-vpn-watchdog/control.json ]] || return 1
  [[ $(stat -c '%U:%G:%a' /run/gateway-vpn-watchdog/status.json) == "root:gateway-vpn:640" ]] || return 1
  [[ $(stat -c '%U:%G:%a' /run/gateway-vpn-watchdog/control.json) == "gateway-vpn:gateway-vpn:640" ]] || return 1
  status_size=$(stat -c '%s' /run/gateway-vpn-watchdog/status.json)
  control_size=$(stat -c '%s' /run/gateway-vpn-watchdog/control.json)
  [[ $status_size =~ ^[0-9]+$ && $control_size =~ ^[0-9]+$ ]] || return 1
  ((status_size > 0 && status_size <= 131072 && control_size > 0 && control_size <= 65536)) || return 1
  now=$(date +%s)
  status_mtime=$(stat -c '%Y' /run/gateway-vpn-watchdog/status.json)
  control_mtime=$(stat -c '%Y' /run/gateway-vpn-watchdog/control.json)
  [[ $now =~ ^[0-9]+$ && $status_mtime =~ ^[0-9]+$ && $control_mtime =~ ^[0-9]+$ ]] || return 1
  status_age=$((now - status_mtime))
  control_age=$((now - control_mtime))
  ((status_age >= -5 && status_age <= 30 && control_age >= -5 && control_age <= 30)) || return 1
  grep -Fq '"schema_version":1' /run/gateway-vpn-watchdog/status.json || return 1
  grep -Fq '"overall_state":"HEALTHY"' /run/gateway-vpn-watchdog/status.json || return 1
  grep -Fq '"schema_version":2' /run/gateway-vpn-watchdog/control.json || return 1
  grep -Fq '"database_ok":true' /run/gateway-vpn-watchdog/control.json || return 1
  grep -Fq '"workers_ok":true' /run/gateway-vpn-watchdog/control.json || return 1
}
REPORT_VERSION=$(report_string version)
REPORT_LAN_INTERFACE=$(report_string lan_interface)
REPORT_LAN_MEMBERS=$(report_string lan_members)
REPORT_LAN_ADDRESS=$(report_string lan_address)
REPORT_DHCP=$(report_bool dhcp_enabled)
[[ $REPORT_VERSION == "$OLD_VERSION" && $REPORT_LAN_INTERFACE == "$LAN_INTERFACE" && $REPORT_LAN_MEMBERS == "$LAN_MEMBERS" && $REPORT_LAN_ADDRESS == "$LAN_ADDRESS" ]] || { echo "Host upgrade cannot combine release replacement with LAN reconfiguration" >&2; exit 1; }
[[ $REPORT_DHCP == "$([[ $ENABLE_DHCP == 1 ]] && echo true || echo false)" ]] || { echo "Host upgrade cannot change DHCP policy" >&2; exit 1; }
REPORT_SSH=$(report_bool lan_ssh_enabled); REPORT_SSH=${REPORT_SSH:-false}
[[ $REPORT_SSH == "$([[ $ENABLE_SSH == 1 ]] && echo true || echo false)" ]] || { echo "Host upgrade cannot change SSH/SFTP policy" >&2; exit 1; }
REPORT_LOG_READER=$(report_string log_reader_user)
[[ -z $REPORT_LOG_READER || $REPORT_LOG_READER == "$LOG_READER_USER" ]] || { echo "Host upgrade cannot change the existing SFTP log-reader account" >&2; exit 1; }
REPORT_WG=$(report_bool wireguard_ingress_enabled); REPORT_WG=${REPORT_WG:-false}
[[ $REPORT_WG == "$([[ $ENABLE_WIREGUARD_INGRESS == 1 ]] && echo true || echo false)" ]] || { echo "Host upgrade cannot change WireGuard ingress policy" >&2; exit 1; }
REPORT_BOOT=$(report_string boot_network_policy); REPORT_BOOT=${REPORT_BOOT:-keep}
REPORT_GRUB=$(report_string grub_policy); REPORT_GRUB=${REPORT_GRUB:-keep}
[[ $REPORT_BOOT == "$BOOT_NETWORK_POLICY" && $REPORT_GRUB == "$GRUB_POLICY" ]] || { echo "Host upgrade cannot change boot or GRUB policy" >&2; exit 1; }
if ((ENABLE_WIREGUARD_INGRESS)); then
  [[ $(report_string wireguard_endpoint_host) == "$WIREGUARD_ENDPOINT_HOST" && $(report_string wireguard_subnet) == "$WIREGUARD_SUBNET" && $(release_number wireguard_listen_port /var/lib/gateway-vpn/install-report.json) == "$WIREGUARD_LISTEN_PORT" && $(report_string wireguard_client_dns) == "$WIREGUARD_CLIENT_DNS" ]] || { echo "Host upgrade cannot change WireGuard ingress values" >&2; exit 1; }
fi

validate_completed_install_marker() {
  local marker=$1 expected_version=$2 field_count key value
  local -a marker_members=() marker_member_states=()
  [[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a' "$marker") == 0:0:600 ]] || return 1
  value=$(stat -c '%s' "$marker")
  [[ $value =~ ^[0-9]+$ && $value -gt 0 && $value -le 2048 ]] || return 1
  field_count=$(wc -l <"$marker")
  [[ $field_count == 14 || $field_count == 16 || $field_count == 18 || $field_count == 20 || $field_count == 21 ]] || return 1
  [[ $(grep -Ec '^(version|old_ipv4_forward|old_ipv4_src_valid_mark|old_ipv6_all_disable|old_ipv6_default_disable|old_ipv6_all_forwarding|preserve_state_root|lan_interface|lan_members|lan_member_was_up|lan_address|preserve_lan_address|lan_was_up|ssh_was_enabled|ssh_was_active|ssh_socket_was_enabled|ssh_socket_was_active|log_reader_user|log_reader_was_member|boot_network_policy|grub_policy)=' "$marker") == "$field_count" ]] || return 1
  local keys=(version old_ipv4_forward old_ipv6_all_disable old_ipv6_default_disable old_ipv6_all_forwarding preserve_state_root lan_interface lan_members lan_member_was_up lan_address preserve_lan_address lan_was_up ssh_was_enabled ssh_was_active)
  if [[ $field_count == 16 || $field_count == 18 || $field_count == 20 || $field_count == 21 ]]; then keys+=(boot_network_policy grub_policy); fi
  if [[ $field_count == 18 || $field_count == 20 || $field_count == 21 ]]; then keys+=(log_reader_user log_reader_was_member); fi
  if [[ $field_count == 20 || $field_count == 21 ]]; then keys+=(ssh_socket_was_enabled ssh_socket_was_active); fi
  if [[ $field_count == 21 ]]; then keys+=(old_ipv4_src_valid_mark); fi
  for key in "${keys[@]}"; do [[ $(grep -c "^${key}=" "$marker") == 1 ]] || return 1; done
  marker_field() { sed -n "s/^$1=//p" "$marker"; }
  [[ $(marker_field version) == "$expected_version" && $(marker_field lan_interface) == "$REPORT_LAN_INTERFACE" && $(marker_field lan_members) == "$REPORT_LAN_MEMBERS" && $(marker_field lan_address) == "$REPORT_LAN_ADDRESS" ]] || return 1
  for key in old_ipv4_forward old_ipv6_all_disable old_ipv6_default_disable old_ipv6_all_forwarding preserve_state_root preserve_lan_address lan_was_up ssh_was_enabled ssh_was_active; do
    [[ $(marker_field "$key") =~ ^[01]$ ]] || return 1
  done
  value=$(marker_field lan_member_was_up)
  [[ -z $REPORT_LAN_MEMBERS && -z $value || -n $REPORT_LAN_MEMBERS && $value =~ ^[01](,[01]){0,15}$ ]] || return 1
  if [[ -n $REPORT_LAN_MEMBERS ]]; then
    IFS=, read -r -a marker_members <<<"$REPORT_LAN_MEMBERS"
    IFS=, read -r -a marker_member_states <<<"$value"
    ((${#marker_members[@]} == ${#marker_member_states[@]})) || return 1
  fi
  if [[ $field_count == 16 || $field_count == 18 || $field_count == 20 || $field_count == 21 ]]; then
    value=$(marker_field boot_network_policy); [[ $value == gateway-nonblocking || $value == keep ]] || return 1
    value=$(marker_field grub_policy); [[ $value == automatic-hidden || $value == menu-5s || $value == keep ]] || return 1
  fi
  if [[ $field_count == 18 || $field_count == 20 || $field_count == 21 ]]; then
    value=$(marker_field log_reader_user); [[ $value =~ ^[a-z_][a-z0-9_-]{0,31}$ && $value != root && $(marker_field log_reader_was_member) =~ ^[01]$ ]] || return 1
  fi
  if [[ $field_count == 20 || $field_count == 21 ]]; then
    [[ $(marker_field ssh_socket_was_enabled) =~ ^[01]$ && $(marker_field ssh_socket_was_active) =~ ^[01]$ ]] || return 1
  fi
  if [[ $field_count == 21 ]]; then
    [[ $(marker_field old_ipv4_src_valid_mark) =~ ^[01]$ ]] || return 1
  fi
}

TRANSACTIONS_DIR=/var/lib/gateway-vpn-privileged/install-transactions
[[ -d $TRANSACTIONS_DIR && ! -L $TRANSACTIONS_DIR && $(stat -c '%u:%g:%a' "$TRANSACTIONS_DIR") == 0:0:700 ]] || { echo "Installed Gateway transaction directory is unsafe" >&2; exit 1; }
ORIGINAL_INSTALL_MARKER=$(find "$TRANSACTIONS_DIR" -maxdepth 1 -type f -name 'completed-*' -printf '%T@ %p\n' | sort -nr | awk 'NR==1 {sub(/^[^ ]+ /, ""); print}')
[[ -n $ORIGINAL_INSTALL_MARKER ]] && validate_completed_install_marker "$ORIGINAL_INSTALL_MARKER" "$OLD_VERSION" || { echo "Installed Gateway completion marker is unavailable or invalid" >&2; exit 1; }

assert_no_conflicting_lifecycle() {
  local pending
  for pending in /var/lib/gateway-vpn-privileged/install-transactions/active /var/lib/gateway-vpn/update-staging/pending-update.json /var/lib/gateway-vpn-privileged/update-rollback/pending.json /var/lib/gateway-vpn/recovery/pending-restore.json; do
    [[ ! -e $pending && ! -L $pending ]] || { echo "Finish the existing Gateway transaction before host upgrade" >&2; return 1; }
  done
  "$RELEASE_DIR/bin/gateway-vpn" update-lifecycle-check >/dev/null || { echo "Finish or recover the active Gateway update before host upgrade" >&2; return 1; }
  [[ ! -e /var/lib/gateway-vpn-host-upgrade/active && ! -L /var/lib/gateway-vpn-host-upgrade/active ]] || { echo "Recover the interrupted host upgrade before retrying" >&2; return 1; }
  [[ ! -e /var/lib/gateway-vpn-uninstall/active && ! -L /var/lib/gateway-vpn-uninstall/active ]] || { echo "Complete the durable Gateway uninstall before host upgrade" >&2; return 1; }
}
assert_no_conflicting_lifecycle

if ((APPLY == 0)); then
  echo "Signed host-contract upgrade dry-run PASS: $OLD_VERSION (schema $OLD_SCHEMA, host ${OLD_HOST_CONTRACT:0:12}…) -> $RELEASE_VERSION (schema $NEW_SCHEMA, host ${NEW_HOST_CONTRACT:0:12}…)."
  echo "Apply will preserve the current LAN/DHCP/SSH/WireGuard policy, create a cold root-only rollback snapshot, replace host lifecycle files, migrate SQLite, and recover the old release on any interrupted step."
  exit 0
fi

[[ -d /run/lock && ! -L /run/lock && $(stat -c '%u' /run/lock) == 0 ]] || { echo "Gateway runtime lock directory is unavailable" >&2; exit 1; }
LOCK_FILE=/run/lock/gateway-vpn-install.lock
if [[ ! -e $LOCK_FILE && ! -L $LOCK_FILE ]]; then
  (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create Gateway transaction lock safely" >&2; exit 1; }
fi
[[ -f $LOCK_FILE && ! -L $LOCK_FILE && $(stat -c '%u:%g:%a' "$LOCK_FILE") == 0:0:600 ]] || { echo "Gateway transaction lock ownership or mode is invalid" >&2; exit 1; }
exec 9<>"$LOCK_FILE"
flock -n 9 || { echo "Another Gateway VPN install/recovery/uninstall transaction is active" >&2; exit 1; }
assert_no_conflicting_lifecycle

ROOT=/var/lib/gateway-vpn-host-upgrade
install -d -m 0700 "$ROOT" "$ROOT/transactions"
[[ -d $ROOT && ! -L $ROOT && $(stat -c '%u:%g:%a' "$ROOT") == 0:0:700 ]] || { echo "Host-upgrade transaction root is unsafe" >&2; exit 1; }
ENTROPY=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
[[ $ENTROPY =~ ^[0-9a-f]{16}$ ]] || { echo "Cannot create host-upgrade transaction identity" >&2; exit 1; }
TRANSACTION_ID=host-upgrade-$(date -u +%Y%m%dT%H%M%SZ)-$ENTROPY
TRANSACTION=$ROOT/transactions/$TRANSACTION_ID
SNAPSHOT=$TRANSACTION/snapshot
ROOTFS=$SNAPSHOT/rootfs
TOOLING=$TRANSACTION/tooling
install -d -m 0700 "$TRANSACTION" "$SNAPSHOT" "$ROOTFS" "$TOOLING"

HOST_RECOVERY_WAS_ENABLED=0
systemctl is-enabled --quiet gateway-vpn-host-upgrade-recovery.service 2>/dev/null && HOST_RECOVERY_WAS_ENABLED=1
HOST_RECOVERY_MUTATED=0
RUNTIME_QUIESCED=0

resume_old_runtime_before_marker() {
  local code=${1:-1}
  trap - ERR INT TERM EXIT
  ((code != 0)) || return 0
  if ((HOST_RECOVERY_MUTATED)); then
    systemctl disable gateway-vpn-host-upgrade-recovery.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/gateway-vpn-host-upgrade-recovery.service /usr/libexec/gateway-vpn-host-upgrade-recovery
    if [[ -f $ROOTFS/etc/systemd/system/gateway-vpn-host-upgrade-recovery.service ]]; then
      cp -a -- "$ROOTFS/etc/systemd/system/gateway-vpn-host-upgrade-recovery.service" /etc/systemd/system/
    fi
    if [[ -f $ROOTFS/usr/libexec/gateway-vpn-host-upgrade-recovery ]]; then
      cp -a -- "$ROOTFS/usr/libexec/gateway-vpn-host-upgrade-recovery" /usr/libexec/
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    if ((HOST_RECOVERY_WAS_ENABLED)); then systemctl enable gateway-vpn-host-upgrade-recovery.service >/dev/null 2>&1 || true; fi
  fi
  if ((RUNTIME_QUIESCED)); then
    local resume_units=(gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-update-recovery.service gateway-vpn-network-recovery.service gateway-vpn-network-broker.socket gateway-vpn-watchdog.service gateway-vpn.service gateway-vpn-update-finalize.timer)
    [[ ! -f /etc/gateway-vpn/dnsmasq.conf ]] || resume_units+=(gateway-vpn-dnsmasq.service)
    [[ ! -f /var/lib/gateway-vpn/mihomo/active/config.yaml ]] || resume_units+=(gateway-vpn-mihomo.service)
    systemctl reset-failed "${resume_units[@]}" >/dev/null 2>&1 || true
    systemctl start "${resume_units[@]}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$TRANSACTION"
  exit "$code"
}
trap 'resume_old_runtime_before_marker $?' ERR EXIT
trap 'resume_old_runtime_before_marker 130' INT
trap 'resume_old_runtime_before_marker 143' TERM

"$OLD_RELEASE/bin/gateway-vpn" firewall-boot --config /etc/gateway-vpn/config.yaml --apply
systemctl stop \
  gateway-vpn-update-finalize.timer gateway-vpn-update-finalize.service gateway-vpn-update-resume.service gateway-vpn-update-rollback.service \
  gateway-vpn-update.service gateway-vpn-update-recovery.service gateway-vpn-database-restore-boot.service \
  gateway-vpn-database-restore-dispatch.service gateway-vpn-database-restore.service gateway-vpn-database-restore-resume.service \
  gateway-vpn-network-recovery.service gateway-vpn-network-broker.socket gateway-vpn-network-broker.service \
  gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service gateway-vpn-watchdog.service gateway-vpn.service \
  gateway-vpn-firewall-guard.service 2>/dev/null || true
systemctl stop 'gateway-vpn-power-cycle@*.service' 'gateway-vpn-network-rollback@*.timer' 'gateway-vpn-network-rollback@*.service' 2>/dev/null || true
RUNTIME_QUIESCED=1
nft list chain inet gateway_vpn forward | grep -F 'gateway-vpn PATH_BLOCKED' >/dev/null
assert_no_conflicting_lifecycle
"$RELEASE_DIR/bin/gateway-vpnctl" database-verify --database /var/lib/gateway-vpn/state.db --expected-schema "$OLD_SCHEMA" --json >/dev/null

snapshot_item() {
  local source=$1 relative destination_parent
  [[ -e $source || -L $source ]] || return 0
  relative=${source#/}
  destination_parent=$ROOTFS/$(dirname "$relative")
  install -d -m 0700 "$destination_parent"
  cp -a -- "$source" "$destination_parent/"
}
for path in /opt/gateway-vpn /etc/gateway-vpn /var/lib/gateway-vpn /var/lib/gateway-vpn-privileged /var/lib/gateway-vpn-dnsmasq /var/log/gateway-vpn; do snapshot_item "$path"; done
shopt -s nullglob
for path in /etc/systemd/system/gateway-vpn*.service /etc/systemd/system/gateway-vpn*.socket /etc/systemd/system/gateway-vpn*.timer /etc/systemd/system/multi-user.target.wants/gateway-vpn-host-upgrade-recovery.service /etc/systemd/system/multi-user.target.wants/gateway-vpn-uninstall.service /etc/systemd/network/05-gateway-vpn-lan.network /etc/systemd/network/05-gateway-vpn-lan.netdev /etc/systemd/network/06-gateway-vpn-lan-*.network /etc/systemd/network/80-gateway-vpn-hilink.network /etc/systemd/system/systemd-networkd-wait-online.service.d/gateway-vpn.conf /etc/default/grub.d/90-gateway-vpn.cfg /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf /etc/sysctl.d/90-gateway-vpn-ipv6.conf /etc/systemd/journald@gateway-vpn.conf.d/retention.conf /usr/lib/sysusers.d/gateway-vpn.conf /usr/lib/tmpfiles.d/gateway-vpn.conf /usr/libexec/gateway-vpn-install-recovery /usr/libexec/gateway-vpn-host-upgrade-recovery /usr/libexec/gateway-vpn-uninstall-job /boot/grub/grub.cfg /boot/grub/grubenv; do snapshot_item "$path"; done
shopt -u nullglob
sync
[[ -L $ROOTFS/opt/gateway-vpn/current && $(readlink "$ROOTFS/opt/gateway-vpn/current") == releases/v$OLD_VERSION && -f $ROOTFS/var/lib/gateway-vpn/state.db ]] || { echo "Host-upgrade rollback snapshot is incomplete" >&2; exit 1; }
SNAPSHOT_INSTALL_MARKER=$ROOTFS/${ORIGINAL_INSTALL_MARKER#/}
validate_completed_install_marker "$SNAPSHOT_INSTALL_MARKER" "$OLD_VERSION" || { echo "Host-upgrade snapshot completion marker is invalid" >&2; exit 1; }
"$RELEASE_DIR/bin/gateway-vpnctl" database-verify --database "$ROOTFS/var/lib/gateway-vpn/state.db" --expected-schema "$OLD_SCHEMA" --json >/dev/null

LOG_READER_GROUP_EXISTED=0
getent group gateway-vpn-log-readers >/dev/null 2>&1 && LOG_READER_GROUP_EXISTED=1
LOG_READER_WAS_MEMBER=0
if ((LOG_READER_GROUP_EXISTED)) && id -nG "$LOG_READER_USER" | tr ' ' '\n' | grep -Fxq gateway-vpn-log-readers; then LOG_READER_WAS_MEMBER=1; fi
install -m 0700 "$RELEASE_DIR/bin/gateway-vpnctl" "$TOOLING/gateway-vpnctl"
install -m 0700 "$OLD_RELEASE/bin/gateway-vpnctl" "$TOOLING/old-gateway-vpnctl"
install -m 0600 "$TRUSTED_UPDATE_KEY" "$TOOLING/update-signing.pub"
HOST_RECOVERY_MUTATED=1
install -m 0700 "$RELEASE_DIR/scripts/recover-gateway-host-upgrade.sh" /usr/libexec/gateway-vpn-host-upgrade-recovery
install -m 0644 "$RELEASE_DIR/packaging/systemd/gateway-vpn-host-upgrade-recovery.service" /etc/systemd/system/gateway-vpn-host-upgrade-recovery.service
systemctl daemon-reload
systemctl enable gateway-vpn-host-upgrade-recovery.service >/dev/null

write_marker() {
  local state=$1 temporary=$ROOT/.active.tmp
  printf 'format=1\ntransaction_id=%s\nstate=%s\nold_version=%s\nnew_version=%s\nlog_reader_user=%s\nlog_reader_group_existed=%s\nlog_reader_was_member=%s\n' "$TRANSACTION_ID" "$state" "$OLD_VERSION" "$RELEASE_VERSION" "$LOG_READER_USER" "$LOG_READER_GROUP_EXISTED" "$LOG_READER_WAS_MEMBER" >"$temporary"
  chmod 0600 "$temporary"
  sync -f "$temporary"
  mv -T "$temporary" "$ROOT/active"
  sync -f "$ROOT"
}
write_marker SNAPSHOT_READY

rollback_upgrade() {
  local code=${1:-1}
  trap - ERR INT TERM EXIT
  ((code != 0)) || return 0
  flock -u 9 || true
  exec 9>&-
  GATEWAY_VPN_HOST_UPGRADE_RECOVERY_UNIT=1 /usr/libexec/gateway-vpn-host-upgrade-recovery --apply || true
  exit "$code"
}
trap 'rollback_upgrade $?' ERR EXIT
trap 'rollback_upgrade 130' INT
trap 'rollback_upgrade 143' TERM
write_marker APPLYING

rm -f /opt/gateway-vpn/current /opt/gateway-vpn/recovery /opt/gateway-vpn/.current.new /opt/gateway-vpn/.recovery.new /var/lib/gateway-vpn/install-report.json
rm -f /etc/gateway-vpn/update-signing.pub /etc/gateway-vpn/nftables/boot.nft /etc/gateway-vpn/dnsmasq.conf
rm -f /etc/systemd/network/05-gateway-vpn-lan.network /etc/systemd/network/05-gateway-vpn-lan.netdev /etc/systemd/network/06-gateway-vpn-lan-*.network /etc/systemd/network/80-gateway-vpn-hilink.network
rm -f /etc/systemd/system/systemd-networkd-wait-online.service.d/gateway-vpn.conf /etc/default/grub.d/90-gateway-vpn.cfg
rm -f /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf /etc/sysctl.d/90-gateway-vpn-ipv6.conf /etc/systemd/journald@gateway-vpn.conf.d/retention.conf
rm -f /usr/lib/sysusers.d/gateway-vpn.conf /usr/lib/tmpfiles.d/gateway-vpn.conf /usr/libexec/gateway-vpn-install-recovery /usr/libexec/gateway-vpn-uninstall-job
shopt -s nullglob
for path in /etc/systemd/system/gateway-vpn*.service /etc/systemd/system/gateway-vpn*.socket /etc/systemd/system/gateway-vpn*.timer; do
  [[ $path == /etc/systemd/system/gateway-vpn-host-upgrade-recovery.service ]] || rm -f -- "$path"
done
for path in /etc/systemd/system/*.target.wants/gateway-vpn* /etc/systemd/system/*.service.wants/gateway-vpn*; do
  [[ $path == */gateway-vpn-host-upgrade-recovery.service ]] || { [[ ! -L $path ]] || rm -f -- "$path"; }
done
shopt -u nullglob
if ip link show dev wg-mgmt >/dev/null 2>&1; then ip link delete dev wg-mgmt; fi

INNER_ARGS=(
  --release-dir "$RELEASE_DIR" --trusted-update-key "$TOOLING/update-signing.pub" --version "$RELEASE_VERSION"
  --lan-interface "$LAN_INTERFACE" --lan-address "$LAN_ADDRESS" --log-reader-user "$LOG_READER_USER"
  --boot-network-policy "$BOOT_NETWORK_POLICY" --grub-policy "$GRUB_POLICY" --host-upgrade-inner
)
[[ -z $LAN_MEMBERS ]] || INNER_ARGS+=(--lan-members "$LAN_MEMBERS")
((INSTALL_DEPENDENCIES == 0)) || INNER_ARGS+=(--install-dependencies)
((ENABLE_DHCP == 0)) || INNER_ARGS+=(--enable-dhcp)
((ENABLE_SSH == 1)) || INNER_ARGS+=(--disable-ssh)
if ((ENABLE_WIREGUARD_INGRESS)); then
  INNER_ARGS+=(--enable-wireguard-ingress --wireguard-endpoint-host "$WIREGUARD_ENDPOINT_HOST" --wireguard-subnet "$WIREGUARD_SUBNET" --wireguard-listen-port "$WIREGUARD_LISTEN_PORT" --wireguard-client-dns "$WIREGUARD_CLIENT_DNS")
fi
INNER_ARGS+=(--apply)
GATEWAY_VPN_HOST_UPGRADE_INNER=1 "$RELEASE_DIR/scripts/install-gateway.sh" "${INNER_ARGS[@]}"

[[ $(readlink /opt/gateway-vpn/current) == releases/v$RELEASE_VERSION && $(readlink /opt/gateway-vpn/recovery) == releases/v$RELEASE_VERSION ]] || { echo "Candidate release pointers did not converge" >&2; exit 1; }
"/opt/gateway-vpn/releases/v$RELEASE_VERSION/bin/gateway-vpnctl" database-verify --database /var/lib/gateway-vpn/state.db --expected-schema "$NEW_SCHEMA" --json >/dev/null
CANDIDATE_RUNTIME_READY=0
for _ in {1..60}; do
  if systemctl is-active --quiet gateway-vpn-firewall.service &&
     systemctl is-active --quiet gateway-vpn-firewall-guard.service &&
     systemctl is-active --quiet gateway-vpn-watchdog.service &&
     systemctl is-active --quiet gateway-vpn-network-broker.socket &&
     systemctl is-active --quiet gateway-vpn-network-broker.service &&
     systemctl is-active --quiet gateway-vpn.service &&
     { ((ENABLE_DHCP == 0)) || systemctl is-active --quiet gateway-vpn-dnsmasq.service; } &&
     candidate_runtime_ready; then
    CANDIDATE_RUNTIME_READY=1
    break
  fi
  sleep 0.5
done
((CANDIDATE_RUNTIME_READY == 1)) || { echo "Candidate Gateway runtime did not converge to a fresh healthy state" >&2; exit 1; }
grep -Fq "\"version\": \"$RELEASE_VERSION\"" /var/lib/gateway-vpn/install-report.json
nft list chain inet gateway_vpn forward | grep -F 'gateway-vpn PATH_BLOCKED' >/dev/null

OLD_MARKER=$SNAPSHOT_INSTALL_MARKER
NEW_MARKER=$(find /var/lib/gateway-vpn-privileged/install-transactions -maxdepth 1 -type f -name 'completed-*' -printf '%T@ %p\n' | sort -nr | awk 'NR==1 {sub(/^[^ ]+ /, ""); print}')
[[ -f $OLD_MARKER && ! -L $OLD_MARKER && -f $NEW_MARKER && ! -L $NEW_MARKER ]] || { echo "Host-upgrade install marker merge is unavailable" >&2; exit 1; }
validate_completed_install_marker "$OLD_MARKER" "$OLD_VERSION" || { echo "Old host-upgrade install marker changed after snapshot" >&2; exit 1; }
validate_completed_install_marker "$NEW_MARKER" "$RELEASE_VERSION" || { echo "Candidate host-upgrade install marker is invalid" >&2; exit 1; }
old_marker_value() { sed -n "s/^$1=//p" "$OLD_MARKER"; }
new_marker_value() { sed -n "s/^$1=//p" "$NEW_MARKER"; }
old_or_default() { local value; value=$(old_marker_value "$1"); printf '%s' "${value:-$2}"; }
MERGED=$NEW_MARKER.merged
OLD_MARKER_FIELD_COUNT=$(wc -l <"$OLD_MARKER")
if [[ $OLD_MARKER_FIELD_COUNT == 20 || $OLD_MARKER_FIELD_COUNT == 21 ]]; then
  ORIGINAL_SOURCE_MARK=$(old_marker_value old_ipv4_src_valid_mark)
  ORIGINAL_SOURCE_MARK=${ORIGINAL_SOURCE_MARK:-$(new_marker_value old_ipv4_src_valid_mark)}
  printf 'version=%s\nold_ipv4_forward=%s\nold_ipv4_src_valid_mark=%s\nold_ipv6_all_disable=%s\nold_ipv6_default_disable=%s\nold_ipv6_all_forwarding=%s\npreserve_state_root=%s\nlan_interface=%s\nlan_members=%s\nlan_member_was_up=%s\nlan_address=%s\npreserve_lan_address=%s\nlan_was_up=%s\nssh_was_enabled=%s\nssh_was_active=%s\nssh_socket_was_enabled=%s\nssh_socket_was_active=%s\nlog_reader_user=%s\nlog_reader_was_member=%s\nboot_network_policy=%s\ngrub_policy=%s\n' \
    "$RELEASE_VERSION" "$(old_marker_value old_ipv4_forward)" "$ORIGINAL_SOURCE_MARK" "$(old_marker_value old_ipv6_all_disable)" "$(old_marker_value old_ipv6_default_disable)" "$(old_marker_value old_ipv6_all_forwarding)" "$(old_marker_value preserve_state_root)" "$(old_marker_value lan_interface)" "$(old_marker_value lan_members)" "$(old_marker_value lan_member_was_up)" "$(old_marker_value lan_address)" "$(old_marker_value preserve_lan_address)" "$(old_marker_value lan_was_up)" "$(old_marker_value ssh_was_enabled)" "$(old_marker_value ssh_was_active)" "$(old_marker_value ssh_socket_was_enabled)" "$(old_marker_value ssh_socket_was_active)" "$(old_or_default log_reader_user "$LOG_READER_USER")" "$(old_or_default log_reader_was_member "$LOG_READER_WAS_MEMBER")" "$(old_or_default boot_network_policy keep)" "$(old_or_default grub_policy keep)" >"$MERGED"
else
  printf 'version=%s\nold_ipv4_forward=%s\nold_ipv6_all_disable=%s\nold_ipv6_default_disable=%s\nold_ipv6_all_forwarding=%s\npreserve_state_root=%s\nlan_interface=%s\nlan_members=%s\nlan_member_was_up=%s\nlan_address=%s\npreserve_lan_address=%s\nlan_was_up=%s\nssh_was_enabled=%s\nssh_was_active=%s\nlog_reader_user=%s\nlog_reader_was_member=%s\nboot_network_policy=%s\ngrub_policy=%s\n' \
    "$RELEASE_VERSION" "$(old_marker_value old_ipv4_forward)" "$(old_marker_value old_ipv6_all_disable)" "$(old_marker_value old_ipv6_default_disable)" "$(old_marker_value old_ipv6_all_forwarding)" "$(old_marker_value preserve_state_root)" "$(old_marker_value lan_interface)" "$(old_marker_value lan_members)" "$(old_marker_value lan_member_was_up)" "$(old_marker_value lan_address)" "$(old_marker_value preserve_lan_address)" "$(old_marker_value lan_was_up)" "$(old_marker_value ssh_was_enabled)" "$(old_marker_value ssh_was_active)" "$(old_or_default log_reader_user "$LOG_READER_USER")" "$(old_or_default log_reader_was_member "$LOG_READER_WAS_MEMBER")" "$(old_or_default boot_network_policy keep)" "$(old_or_default grub_policy keep)" >"$MERGED"
fi
chmod 0600 "$MERGED"
MERGED_FIELD_COUNT=$(wc -l <"$MERGED")
[[ ($OLD_MARKER_FIELD_COUNT == 20 || $OLD_MARKER_FIELD_COUNT == 21) && $MERGED_FIELD_COUNT == 21 || ($OLD_MARKER_FIELD_COUNT != 20 && $OLD_MARKER_FIELD_COUNT != 21) && $MERGED_FIELD_COUNT == 18 ]] || { echo "Merged host-upgrade install marker is invalid" >&2; exit 1; }
validate_completed_install_marker "$MERGED" "$RELEASE_VERSION" || { echo "Merged host-upgrade install marker does not preserve the original OS state" >&2; exit 1; }
sync -f "$MERGED"
mv -T "$MERGED" "$NEW_MARKER"
sync -f /var/lib/gateway-vpn-privileged/install-transactions

write_marker CANDIDATE_READY
COMPLETED=$TRANSACTION/completed-$(date -u +%Y%m%dT%H%M%SZ)
mv -T "$ROOT/active" "$COMPLETED"
sync -f "$ROOT"
trap - ERR INT TERM EXIT
flock -u 9
exec 9>&-
echo "Gateway VPN signed host-contract upgrade completed: $OLD_VERSION -> $RELEASE_VERSION; rollback snapshot retained at $SNAPSHOT"
