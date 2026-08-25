#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ROOT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
APPLY=0
INSTALL_DEPENDENCIES=0
DEPENDENCY_PREFLIGHT_ONLY=0
ENABLE_DHCP=0
RELEASE_DIR=""
TRUSTED_UPDATE_KEY=""
RELEASE_VERSION=""
LAN_INTERFACE=""
LAN_ADDRESS="192.168.200.1/24"

usage() {
  echo "Usage: install-gateway.sh --release-dir DIR --trusted-update-key FILE --version VERSION --lan-interface IFACE [--lan-address CIDR] [--install-dependencies] [--enable-dhcp] [--apply]"
  echo "Without --apply the installer performs validation and prints the planned destinations."
}

while (($#)); do
  case "$1" in
    --release-dir) RELEASE_DIR=${2:?}; shift 2 ;;
    --trusted-update-key) TRUSTED_UPDATE_KEY=${2:?}; shift 2 ;;
    --version) RELEASE_VERSION=${2:?}; shift 2 ;;
    --lan-interface) LAN_INTERFACE=${2:?}; shift 2 ;;
    --lan-address) LAN_ADDRESS=${2:?}; shift 2 ;;
    --install-dependencies) INSTALL_DEPENDENCIES=1; shift ;;
    --dependency-preflight-only) DEPENDENCY_PREFLIGHT_ONLY=1; shift ;;
    --enable-dhcp) ENABLE_DHCP=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$RELEASE_DIR" && -n "$TRUSTED_UPDATE_KEY" && -n "$RELEASE_VERSION" && -n "$LAN_INTERFACE" ]] || { usage >&2; exit 2; }
((DEPENDENCY_PREFLIGHT_ONLY == 0 || (INSTALL_DEPENDENCIES == 1 && APPLY == 0))) || { echo "--dependency-preflight-only is reserved for the non-mutating bootstrap phase" >&2; exit 2; }
((APPLY == 0)) || [[ $EUID -eq 0 ]] || { echo "--apply requires root" >&2; exit 1; }
[[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9._-]+)?$ ]] || { echo "Invalid version" >&2; exit 2; }
[[ "$LAN_INTERFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || { echo "Invalid LAN interface" >&2; exit 2; }
[[ "$LAN_ADDRESS" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || { echo "Invalid LAN CIDR" >&2; exit 2; }
LAN_IP=${LAN_ADDRESS%/*}
LAN_PREFIX=${LAN_ADDRESS#*/}
IFS=. read -r LAN_A LAN_B LAN_C LAN_D <<<"$LAN_IP"
for octet in "$LAN_A" "$LAN_B" "$LAN_C" "$LAN_D"; do
  [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || { echo "Invalid or non-canonical LAN IPv4 address" >&2; exit 2; }
  ((10#$octet <= 255)) || { echo "Invalid LAN IPv4 address" >&2; exit 2; }
done
[[ "$LAN_PREFIX" =~ ^(1[6-9]|2[0-9]|30)$ ]] || { echo "Gateway LAN prefix must be between /16 and /30" >&2; exit 2; }
LAN_A_VALUE=$((10#$LAN_A))
LAN_B_VALUE=$((10#$LAN_B))
LAN_C_VALUE=$((10#$LAN_C))
LAN_D_VALUE=$((10#$LAN_D))
if ! ((LAN_A_VALUE == 10 || (LAN_A_VALUE == 172 && LAN_B_VALUE >= 16 && LAN_B_VALUE <= 31) || (LAN_A_VALUE == 192 && LAN_B_VALUE == 168))); then
  echo "Gateway LAN must use an RFC1918 private IPv4 address" >&2
  exit 2
fi
LAN_IP_VALUE=$(((LAN_A_VALUE << 24) | (LAN_B_VALUE << 16) | (LAN_C_VALUE << 8) | LAN_D_VALUE))
LAN_HOST_MASK=$(((1 << (32 - LAN_PREFIX)) - 1))
LAN_NETWORK_VALUE=$((LAN_IP_VALUE & (0xFFFFFFFF ^ LAN_HOST_MASK)))
LAN_BROADCAST_VALUE=$((LAN_NETWORK_VALUE | LAN_HOST_MASK))
((LAN_IP_VALUE != LAN_NETWORK_VALUE && LAN_IP_VALUE != LAN_BROADCAST_VALUE)) || { echo "Gateway LAN CIDR must contain a usable host address, not the network or broadcast address" >&2; exit 2; }
WG_MANAGEMENT_START=$(((10 << 24) | (80 << 16)))
WG_MANAGEMENT_END=$((WG_MANAGEMENT_START | 255))
! ((LAN_NETWORK_VALUE <= WG_MANAGEMENT_END && WG_MANAGEMENT_START <= LAN_BROADCAST_VALUE)) || { echo "Gateway LAN must not overlap fixed WireGuard management subnet 10.80.0.0/24" >&2; exit 2; }
if ((ENABLE_DHCP)) && [[ "$LAN_PREFIX" != 24 ]]; then
  echo "Automatic DHCP range generation currently requires a /24 transit LAN" >&2
  exit 2
fi
RELEASE_DIR=$(realpath -- "$RELEASE_DIR")
TRUSTED_UPDATE_KEY=$(realpath -- "$TRUSTED_UPDATE_KEY")
[[ -f "$TRUSTED_UPDATE_KEY" && ! -L "$TRUSTED_UPDATE_KEY" ]] || { echo "Trusted update public key must be a regular non-symlink file" >&2; exit 1; }
[[ -x "$RELEASE_DIR/bin/gateway-vpn" && -x "$RELEASE_DIR/bin/gateway-vpnctl" && -x "$RELEASE_DIR/libexec/mihomo" && -x "$RELEASE_DIR/scripts/recover-gateway-install.sh" ]] || { echo "Release binaries or recovery helper are incomplete" >&2; exit 1; }
[[ -f "$RELEASE_DIR/manifest.sha256" && -f "$RELEASE_DIR/manifest.json" && -f "$RELEASE_DIR/release.sig" && -f "$RELEASE_DIR/release.json" ]] || { echo "Signed release requires release metadata, file manifest and detached signature" >&2; exit 1; }
(cd -- "$RELEASE_DIR" && sha256sum --check --strict manifest.sha256)
"$RELEASE_DIR/bin/gateway-vpnctl" release-verify --release-dir "$RELEASE_DIR" --public-key "$TRUSTED_UPDATE_KEY" --current-version 0.0.0 --current-schema 1
RELEASE_VERSION_OUTPUT=$("$RELEASE_DIR/bin/gateway-vpn" --version)
[[ "$RELEASE_VERSION_OUTPUT" == "gateway-vpn $RELEASE_VERSION "* ]] || { echo "Release binary version does not match --version" >&2; exit 1; }

source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || { echo "Gateway VPN requires Ubuntu 24.04" >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo "Gateway VPN release currently requires x86_64" >&2; exit 1; }
for command in systemctl journalctl networkctl systemd-sysusers systemd-tmpfiles base64 sha256sum realpath apt-get dpkg-query grep awk getent timedatectl df wc head install mktemp rm sync stat uname flock find sort sed mv date readlink chown chmod cat sleep; do
  command -v "$command" >/dev/null || { echo "Missing base Gateway prerequisite command: $command" >&2; exit 1; }
done
[[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == yes ]] || { echo "Gateway clock is not reported as NTP-synchronized" >&2; exit 1; }
getent ahostsv4 github.com >/dev/null || { echo "Gateway DNS resolution failed" >&2; exit 1; }
AVAILABLE_KIB=$(df --output=avail / | awk 'NR==2 {print $1}')
MEMORY_KIB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
[[ "$AVAILABLE_KIB" =~ ^[0-9]+$ && "$AVAILABLE_KIB" -ge 524288 ]] || { echo "Gateway requires at least 512 MiB free disk" >&2; exit 1; }
[[ "$MEMORY_KIB" =~ ^[0-9]+$ && "$MEMORY_KIB" -ge 524288 ]] || { echo "Gateway requires at least 512 MiB RAM" >&2; exit 1; }
apt-get check >/dev/null
[[ -d /run/lock && ! -L /run/lock && $(stat -c '%u' /run/lock) == 0 ]] || { echo "Gateway runtime lock directory is unavailable" >&2; exit 1; }
if ((APPLY)); then
  LOCK_FILE=/run/lock/gateway-vpn-install.lock
  if [[ ! -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
    (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create Gateway transaction lock safely" >&2; exit 1; }
  fi
  [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" && $(stat -c '%u:%g:%a' "$LOCK_FILE") == "0:0:600" ]] || { echo "Gateway transaction lock ownership or mode is invalid" >&2; exit 1; }
  exec 9<>"$LOCK_FILE"
  flock -n 9 || { echo "Another Gateway VPN install/recovery/uninstall transaction is active" >&2; exit 1; }
fi
[[ ! -e /var/lib/gateway-vpn-privileged/install-transactions/active && ! -L /var/lib/gateway-vpn-privileged/install-transactions/active ]] || { echo "Interrupted Gateway installation requires recovery before retry" >&2; exit 1; }
[[ ! -e /run/gateway-vpn-install-authorized && ! -L /run/gateway-vpn-install-authorized ]] || { echo "Stale Gateway install authorization artifact requires operator recovery" >&2; exit 1; }
ORPHAN_MARKER_TEMP=0
if [[ -e /var/lib/gateway-vpn-privileged/install-transactions/.active.tmp || -L /var/lib/gateway-vpn-privileged/install-transactions/.active.tmp ]]; then
  for transaction_dir in /var/lib/gateway-vpn-privileged /var/lib/gateway-vpn-privileged/install-transactions; do
    [[ -d "$transaction_dir" && ! -L "$transaction_dir" && $(stat -c '%u:%g:%a' "$transaction_dir") == "0:0:700" ]] || { echo "Orphan Gateway marker has an unsafe transaction directory" >&2; exit 1; }
  done
  ORPHAN_MARKER_TEMP=1
  [[ -f /var/lib/gateway-vpn-privileged/install-transactions/.active.tmp && ! -L /var/lib/gateway-vpn-privileged/install-transactions/.active.tmp && $(stat -c '%u:%g:%a' /var/lib/gateway-vpn-privileged/install-transactions/.active.tmp) == "0:0:600" ]] || { echo "Orphan Gateway marker ownership or mode is unsafe" >&2; exit 1; }
  ORPHAN_MARKER_BYTES=$(stat -c '%s' /var/lib/gateway-vpn-privileged/install-transactions/.active.tmp)
  [[ "$ORPHAN_MARKER_BYTES" =~ ^[0-9]+$ && "$ORPHAN_MARKER_BYTES" -le 1024 ]] || { echo "Orphan Gateway marker size is unsafe" >&2; exit 1; }
  echo "Validated harmless pre-transaction Gateway marker artifact; apply will remove it before continuing"
fi
for partial_path in /opt/gateway-vpn/.current.new /opt/gateway-vpn/.recovery.new; do
  [[ ! -e "$partial_path" && ! -L "$partial_path" ]] || { echo "Orphan Gateway installation artifact requires operator recovery before retry: $partial_path" >&2; exit 1; }
done
if ((APPLY && ORPHAN_MARKER_TEMP)); then
  rm -f -- /var/lib/gateway-vpn-privileged/install-transactions/.active.tmp
  sync -f /var/lib/gateway-vpn-privileged/install-transactions
  echo "Removed harmless pre-transaction Gateway marker artifact"
fi

REQUIRED_PACKAGES=(iproute2 nftables wireguard-tools kmod procps dnsmasq)
MISSING_PACKAGES=()
for package in "${REQUIRED_PACKAGES[@]}"; do
  status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)
  [[ "$status" == "ii " ]] || MISSING_PACKAGES+=("$package")
done

APT_PLAN_FILE=""
cleanup_temp_files() {
  [[ -z "${APT_PLAN_FILE:-}" ]] || rm -f -- "$APT_PLAN_FILE"
}
trap cleanup_temp_files EXIT

simulate_dependency_install() {
  : >"$APT_PLAN_FILE"
  apt-get -s install --no-install-recommends --no-remove --no-upgrade "${MISSING_PACKAGES[@]}" >"$APT_PLAN_FILE" || return 10
  if grep -q '^Remv ' "$APT_PLAN_FILE"; then
    echo "APT Gateway dependency plan attempts to remove packages" >&2
    return 20
  fi
  if grep -Eq '^Inst [^ ]+ \[' "$APT_PLAN_FILE"; then
    echo "APT Gateway dependency plan attempts to upgrade installed packages" >&2
    return 22
  fi
  planned_installs=$(awk '/^Inst / {count++} END {print count+0}' "$APT_PLAN_FILE")
  [[ "$planned_installs" =~ ^[0-9]+$ && "$planned_installs" -gt 0 ]] || {
    echo "APT Gateway dependency plan contains no installable package changes" >&2
    return 21
  }
  echo "APT Gateway dependency simulation validated: $planned_installs new package actions, no upgrades or removals"
}

if ((${#MISSING_PACKAGES[@]})); then
  printf 'Missing managed Gateway packages:'
  printf ' %s' "${MISSING_PACKAGES[@]}"
  printf '\n'
  ((INSTALL_DEPENDENCIES)) || {
    echo "Missing Gateway packages; re-run with --install-dependencies to validate a package plan, and add --apply to install them" >&2
    exit 1
  }
  APT_PLAN_FILE=$(mktemp)
  if simulate_dependency_install; then
    SIMULATION_RESULT=0
  else
    SIMULATION_RESULT=$?
  fi
  if ((SIMULATION_RESULT != 0)); then
    if ((APPLY == 0 && DEPENDENCY_PREFLIGHT_ONLY == 1 && SIMULATION_RESULT == 10)); then
      echo "Current APT indexes cannot produce the Gateway dependency plan; --apply would refresh indexes before a second mandatory simulation" >&2
      echo "Gateway dependency preflight incomplete; no packages or Gateway VPN files were changed" >&2
      exit 10
    fi
    exit 1
  fi
  if ((APPLY == 0)); then
    echo "Gateway dependency plan validated; full host preflight NOT_RUN because required packages are missing."
    echo "Re-run with --install-dependencies --apply to install packages, repeat full preflight, and install Gateway VPN."
    exit 0
  fi
  echo "Refreshing configured APT indexes before installing exact missing Gateway packages"
  apt-get update
  simulate_dependency_install || { echo "APT Gateway dependency simulation failed after index refresh" >&2; exit 1; }
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install --yes --no-install-recommends --no-remove --no-upgrade "${MISSING_PACKAGES[@]}"
  for package in "${MISSING_PACKAGES[@]}"; do
    status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)
    [[ "$status" == "ii " ]] || { echo "Gateway dependency package was not fully installed: $package" >&2; exit 1; }
  done
  apt-get check >/dev/null
  echo "Managed Gateway dependency packages installed and verified"
fi

for command in ip nft wg sysctl dnsmasq modprobe ss; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done
[[ -d /sys/module/wireguard ]] || modprobe -n wireguard >/dev/null 2>&1 || { echo "Kernel WireGuard support is unavailable" >&2; exit 1; }
systemctl is-active --quiet systemd-networkd.service || { echo "Gateway VPN requires active systemd-networkd" >&2; exit 1; }
[[ -c /dev/net/tun ]] || { echo "/dev/net/tun is unavailable" >&2; exit 1; }
[[ -w /proc/sys/net/ipv4/ip_forward && -w /proc/sys/net/ipv6/conf/all/disable_ipv6 && -w /proc/sys/net/ipv6/conf/default/disable_ipv6 && -w /proc/sys/net/ipv6/conf/all/forwarding ]] || { echo "Required Gateway IPv4/IPv6 sysctls are unavailable" >&2; exit 1; }
ip link show dev "$LAN_INTERFACE" >/dev/null || { echo "LAN interface not found: $LAN_INTERFACE" >&2; exit 1; }
mapfile -t LAN_IPV4_ADDRESSES < <(ip -o -4 address show dev "$LAN_INTERFACE" scope global | awk '{print $4}')
PRESERVE_LAN_ADDRESS=0
if ((${#LAN_IPV4_ADDRESSES[@]} == 1)) && [[ "${LAN_IPV4_ADDRESSES[0]}" == "$LAN_ADDRESS" ]]; then
  PRESERVE_LAN_ADDRESS=1
elif ((${#LAN_IPV4_ADDRESSES[@]} != 0)); then
  echo "LAN interface has an unexpected existing global IPv4 address" >&2
  exit 1
fi
LAN_WAS_UP=0
ip -o link show dev "$LAN_INTERFACE" | grep -Eq '<[^>]*UP[,>]' && LAN_WAS_UP=1
if ip -4 route show default dev "$LAN_INTERFACE" | grep -q .; then
  echo "LAN interface must not own a default route" >&2
  exit 1
fi
"$RELEASE_DIR/bin/gateway-vpnctl" gateway-install-preflight --lan-interface "$LAN_INTERFACE" --lan-address "$LAN_ADDRESS"
if systemctl is-active --quiet ufw.service || systemctl is-active --quiet firewalld.service; then
  echo "Active UFW/firewalld conflicts with the owned Gateway VPN ruleset" >&2
  exit 1
fi

DEST="/opt/gateway-vpn/releases/v$RELEASE_VERSION"
EXISTING=0
if [[ -e "$DEST" || -L /opt/gateway-vpn/current || -L /opt/gateway-vpn/recovery || -e /etc/gateway-vpn || -e /var/lib/gateway-vpn/install-report.json ]]; then
  [[ -d "$DEST" && ! -L "$DEST" && -L /opt/gateway-vpn/current && $(readlink /opt/gateway-vpn/current) == "releases/v$RELEASE_VERSION" && -L /opt/gateway-vpn/recovery && $(readlink /opt/gateway-vpn/recovery) == "releases/v$RELEASE_VERSION" ]] || { echo "Partial or conflicting Gateway VPN installation exists" >&2; exit 1; }
  for installed_asset in /etc/gateway-vpn/config.yaml /etc/gateway-vpn/update-signing.pub /etc/gateway-vpn/nftables/boot.nft /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf /etc/sysctl.d/90-gateway-vpn-ipv6.conf /etc/systemd/network/70-gateway-vpn-lan.network /var/lib/gateway-vpn/install-report.json /etc/systemd/system/gateway-vpn-install-recovery.service /usr/libexec/gateway-vpn-install-recovery; do
    [[ -f "$installed_asset" && ! -L "$installed_asset" ]] || { echo "Installed Gateway asset is missing or unsafe: $installed_asset" >&2; exit 1; }
  done
  [[ $(cat /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf) == $(cat "$ROOT_DIR/packaging/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf") ]] || { echo "Installed Gateway IPv4 forwarding policy differs from the signed release" >&2; exit 1; }
  [[ $(cat /etc/sysctl.d/90-gateway-vpn-ipv6.conf) == $(cat "$ROOT_DIR/packaging/sysctl.d/90-gateway-vpn-ipv6.conf") ]] || { echo "Installed Gateway IPv6 policy differs from the signed release" >&2; exit 1; }
  [[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]] || { echo "Gateway IPv4 forwarding is not active" >&2; exit 1; }
  [[ -x /usr/libexec/gateway-vpn-install-recovery ]] || { echo "Installed Gateway recovery helper is not executable" >&2; exit 1; }
  EXPECTED_LAN_NETWORK=$(sed -e "s|__LAN_INTERFACE__|$LAN_INTERFACE|g" -e "s|__LAN_ADDRESS__|$LAN_ADDRESS|g" "$ROOT_DIR/packaging/systemd-networkd/70-gateway-vpn-lan.network.in")
  [[ $(stat -c '%u:%g:%a' /etc/systemd/network/70-gateway-vpn-lan.network) == "0:0:644" ]] || { echo "Persistent Gateway LAN policy ownership or mode is invalid" >&2; exit 1; }
  [[ $(cat /etc/systemd/network/70-gateway-vpn-lan.network) == "$EXPECTED_LAN_NETWORK" ]] || { echo "Existing persistent Gateway LAN policy differs from the requested interface/CIDR" >&2; exit 1; }
  [[ $(sha256sum /etc/gateway-vpn/update-signing.pub | awk '{print $1}') == $(sha256sum "$TRUSTED_UPDATE_KEY" | awk '{print $1}') ]] || { echo "Existing Gateway trusted update key differs from the requested key" >&2; exit 1; }
  "$DEST/bin/gateway-vpnctl" release-verify --release-dir "$DEST" --public-key /etc/gateway-vpn/update-signing.pub --current-version 0.0.0 --current-schema 1
  "$DEST/bin/gateway-vpn" --check-config /etc/gateway-vpn/config.yaml
  grep -Fxq "  lan_interface: $LAN_INTERFACE" /etc/gateway-vpn/config.yaml || { echo "Existing Gateway runtime LAN interface differs; explicit reconfiguration is required" >&2; exit 1; }
  nft --check --file /etc/gateway-vpn/nftables/boot.nft
  grep -Fq "\"lan_interface\": \"$LAN_INTERFACE\"" /var/lib/gateway-vpn/install-report.json || { echo "Existing Gateway LAN interface differs; explicit reconfiguration is required" >&2; exit 1; }
  grep -Fq "\"lan_address\": \"$LAN_ADDRESS\"" /var/lib/gateway-vpn/install-report.json || { echo "Existing Gateway LAN address differs; explicit reconfiguration is required" >&2; exit 1; }
  grep -Fq "\"dhcp_enabled\": $([[ $ENABLE_DHCP == 1 ]] && echo true || echo false)" /var/lib/gateway-vpn/install-report.json || { echo "Existing Gateway DHCP policy differs; explicit reconfiguration is required" >&2; exit 1; }
  EXISTING=1
else
  for conflict in \
    /opt/gateway-vpn/current /opt/gateway-vpn/recovery /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf /etc/sysctl.d/90-gateway-vpn-ipv6.conf \
    /etc/systemd/network/70-gateway-vpn-lan.network /etc/systemd/network/80-gateway-vpn-hilink.network /etc/systemd/journald@gateway-vpn.conf.d/retention.conf \
    /usr/lib/sysusers.d/gateway-vpn.conf /usr/lib/tmpfiles.d/gateway-vpn.conf \
    /etc/systemd/system/gateway-vpn.service /etc/systemd/system/gateway-vpn-firewall.service \
    /etc/systemd/system/gateway-vpn-firewall-guard.service /etc/systemd/system/gateway-vpn-network-broker.socket \
    /etc/systemd/system/gateway-vpn-install-recovery.service /usr/libexec/gateway-vpn-install-recovery; do
    [[ ! -e "$conflict" && ! -L "$conflict" ]] || { echo "Conflicting Gateway managed path exists: $conflict" >&2; exit 1; }
  done
  if ip link show dev wg-mgmt >/dev/null 2>&1; then
    echo "Unmanaged wg-mgmt interface already exists" >&2
    exit 1
  fi
  if nft list table inet gateway_vpn >/dev/null 2>&1; then
    echo "Unmanaged table inet gateway_vpn already exists" >&2
    exit 1
  fi
fi
echo "Validated Ubuntu 24.04 release $RELEASE_VERSION"
echo "Release destination: $DEST"
echo "LAN: $LAN_INTERFACE / $LAN_ADDRESS"
echo "DHCP enable requested: $ENABLE_DHCP"
if ((EXISTING)); then
  if systemctl is-enabled --quiet gateway-vpn-install-recovery.service; then
    echo "Completed Gateway install unexpectedly has first-install recovery enabled" >&2
    exit 1
  fi
  systemctl is-active --quiet gateway-vpn-firewall.service
  systemctl is-active --quiet gateway-vpn-firewall-guard.service
  systemctl is-active --quiet gateway-vpn-network-broker.socket
  systemctl is-active --quiet gateway-vpn-network-broker.service
  systemctl is-active --quiet gateway-vpn.service
  [[ -S /run/gateway-vpn/network-broker.sock ]]
  if ((ENABLE_DHCP)); then
    systemctl is-active --quiet gateway-vpn-dnsmasq.service
  fi
  nft list table inet gateway_vpn >/dev/null
  ss -H -ltn "sport = :8443" | awk '{print $4}' | grep -Fxq "$LAN_IP:8443"
  echo "Gateway VPN $RELEASE_VERSION is already installed with the requested immutable release and LAN policy."
  exit 0
fi
if ((APPLY == 0)); then
  echo "Dry-run complete. Re-run with --apply to install."
  exit 0
fi
[[ ! -L /var/lib/gateway-vpn-privileged ]] || { echo "Privileged state root must not be a symlink" >&2; exit 1; }
PRESERVE_STATE_ROOT=0
[[ ! -e /var/lib/gateway-vpn && ! -L /var/lib/gateway-vpn ]] || PRESERVE_STATE_ROOT=1
OLD_IPV6_ALL_DISABLE=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
OLD_IPV6_DEFAULT_DISABLE=$(cat /proc/sys/net/ipv6/conf/default/disable_ipv6)
OLD_IPV6_ALL_FORWARDING=$(cat /proc/sys/net/ipv6/conf/all/forwarding)
OLD_IPV4_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
install -d -m 0700 /var/lib/gateway-vpn-privileged /var/lib/gateway-vpn-privileged/install-transactions
install -D -m 0700 "$ROOT_DIR/scripts/recover-gateway-install.sh" /usr/libexec/gateway-vpn-install-recovery
install -D -m 0644 "$ROOT_DIR/packaging/systemd/gateway-vpn-install-recovery.service" /etc/systemd/system/gateway-vpn-install-recovery.service
systemctl daemon-reload
systemctl enable gateway-vpn-install-recovery.service
MARKER_TMP=/var/lib/gateway-vpn-privileged/install-transactions/.active.tmp
printf 'version=%s\nold_ipv4_forward=%s\nold_ipv6_all_disable=%s\nold_ipv6_default_disable=%s\nold_ipv6_all_forwarding=%s\npreserve_state_root=%s\nlan_interface=%s\nlan_address=%s\npreserve_lan_address=%s\nlan_was_up=%s\n' "$RELEASE_VERSION" "$OLD_IPV4_FORWARD" "$OLD_IPV6_ALL_DISABLE" "$OLD_IPV6_DEFAULT_DISABLE" "$OLD_IPV6_ALL_FORWARDING" "$PRESERVE_STATE_ROOT" "$LAN_INTERFACE" "$LAN_ADDRESS" "$PRESERVE_LAN_ADDRESS" "$LAN_WAS_UP" >"$MARKER_TMP"
chmod 0600 "$MARKER_TMP"
sync -f "$MARKER_TMP"
mv -T "$MARKER_TMP" /var/lib/gateway-vpn-privileged/install-transactions/active
sync

rollback_install() {
  local code=${1:-1}
  trap - ERR INT TERM EXIT
  ((code != 0)) || exit 0
  flock -u 9 || true
  exec 9>&-
  if [[ -x /usr/libexec/gateway-vpn-install-recovery ]]; then
    /usr/libexec/gateway-vpn-install-recovery || true
  fi
  exit "$code"
}
trap 'rollback_install $?' ERR EXIT
trap 'rollback_install 130' INT
trap 'rollback_install 143' TERM

SNAPSHOT="/var/lib/gateway-vpn-privileged/install-transactions/install-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$SNAPSHOT"
ip -json address show >"$SNAPSHOT/ip-address.json"
ip -json route show table all >"$SNAPSHOT/ip-route.json"
ip -json rule show >"$SNAPSHOT/ip-rule.json"
nft --json list ruleset >"$SNAPSHOT/nft-ruleset.json"

install -D -m 0644 "$ROOT_DIR/packaging/sysusers.d/gateway-vpn.conf" /usr/lib/sysusers.d/gateway-vpn.conf
systemd-sysusers /usr/lib/sysusers.d/gateway-vpn.conf
install -D -m 0644 "$ROOT_DIR/packaging/tmpfiles.d/gateway-vpn.conf" /usr/lib/tmpfiles.d/gateway-vpn.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/gateway-vpn.conf
install -d -m 0750 -o root -g gateway-vpn /etc/gateway-vpn/nftables
sed "s|__LAN_INTERFACE__|$LAN_INTERFACE|g" "$ROOT_DIR/packaging/nftables/boot.nft.in" >/etc/gateway-vpn/nftables/boot.nft
chown root:gateway-vpn /etc/gateway-vpn/nftables/boot.nft
chmod 0640 /etc/gateway-vpn/nftables/boot.nft
nft --check --file /etc/gateway-vpn/nftables/boot.nft
nft --file /etc/gateway-vpn/nftables/boot.nft
nft list table inet gateway_vpn >/dev/null
sed -e "s|__LAN_INTERFACE__|$LAN_INTERFACE|g" -e "s|__LAN_ADDRESS__|$LAN_ADDRESS|g" "$ROOT_DIR/packaging/systemd-networkd/70-gateway-vpn-lan.network.in" >/etc/systemd/network/70-gateway-vpn-lan.network
chmod 0644 /etc/systemd/network/70-gateway-vpn-lan.network
install -D -m 0644 "$ROOT_DIR/packaging/systemd-networkd/80-gateway-vpn-hilink.network" /etc/systemd/network/80-gateway-vpn-hilink.network
install -D -m 0644 "$ROOT_DIR/packaging/journald/gateway-vpn.conf" /etc/systemd/journald@gateway-vpn.conf.d/retention.conf
install -D -m 0644 "$TRUSTED_UPDATE_KEY" /etc/gateway-vpn/update-signing.pub
networkctl reload
ip link set dev "$LAN_INTERFACE" up
ip -4 address replace "$LAN_ADDRESS" dev "$LAN_INTERFACE"
if [[ ! -e /var/lib/gateway-vpn/secrets/mihomo-api-secret ]]; then
  umask 077
  head -c 48 /dev/urandom | base64 -w 0 >/var/lib/gateway-vpn/secrets/mihomo-api-secret
  chown gateway-vpn:gateway-vpn /var/lib/gateway-vpn/secrets/mihomo-api-secret
  chmod 0600 /var/lib/gateway-vpn/secrets/mihomo-api-secret
fi
install -D -m 0644 "$ROOT_DIR/packaging/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf" /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf
install -D -m 0644 "$ROOT_DIR/packaging/sysctl.d/90-gateway-vpn-ipv6.conf" /etc/sysctl.d/90-gateway-vpn-ipv6.conf
sysctl --system >/dev/null

install -d -m 0755 "$DEST"
while IFS= read -r -d '' source; do
  relative=${source#"$RELEASE_DIR/"}
  mode=0644
  [[ -x "$source" ]] && mode=0755
  install -D -m "$mode" "$source" "$DEST/$relative"
done < <(find "$RELEASE_DIR" -type f -print0 | sort -z)
"$DEST/bin/gateway-vpnctl" release-verify --release-dir "$DEST" --public-key /etc/gateway-vpn/update-signing.pub --current-version 0.0.0 --current-schema 1

if [[ ! -e /etc/gateway-vpn/config.yaml ]]; then
  sed -E -e "s|^([[:space:]]*)lan_interface:.*|\1lan_interface: $LAN_INTERFACE|" -e "s|192.168.200.1/24|$LAN_ADDRESS|g" -e "s|192.168.200.1|$LAN_IP|g" "$ROOT_DIR/config.example.yaml" >/etc/gateway-vpn/config.yaml
  chown root:gateway-vpn /etc/gateway-vpn/config.yaml
  chmod 0640 /etc/gateway-vpn/config.yaml
fi
grep -Fxq "  lan_interface: $LAN_INTERFACE" /etc/gateway-vpn/config.yaml || { echo "Generated Gateway runtime LAN interface verification failed" >&2; exit 1; }
"$DEST/bin/gateway-vpn" --check-config /etc/gateway-vpn/config.yaml

for unit in gateway-vpn.service gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-mihomo.service gateway-vpn-dnsmasq.service \
  gateway-vpn-network-broker.socket gateway-vpn-network-broker.service gateway-vpn-network-recovery.service \
  gateway-vpn-network-rollback@.timer gateway-vpn-network-rollback@.service \
  gateway-vpn-database-restore.service gateway-vpn-database-restore-resume.service \
  gateway-vpn-update.service gateway-vpn-update-recovery.service gateway-vpn-update-resume.service gateway-vpn-update-finalize.service gateway-vpn-update-finalize.timer; do
  install -D -m 0644 "$ROOT_DIR/packaging/systemd/$unit" "/etc/systemd/system/$unit"
done
ln -sfn "releases/v$RELEASE_VERSION" /opt/gateway-vpn/.current.new
mv -Tf /opt/gateway-vpn/.current.new /opt/gateway-vpn/current
ln -sfn "releases/v$RELEASE_VERSION" /opt/gateway-vpn/.recovery.new
mv -Tf /opt/gateway-vpn/.recovery.new /opt/gateway-vpn/recovery
(set -o noclobber; : >/run/gateway-vpn-install-authorized) || { echo "Cannot create ephemeral Gateway service-start authorization safely" >&2; exit 1; }
chmod 0600 /run/gateway-vpn-install-authorized
[[ -f /run/gateway-vpn-install-authorized && ! -L /run/gateway-vpn-install-authorized && $(stat -c '%u:%g:%a' /run/gateway-vpn-install-authorized) == "0:0:600" ]] || { echo "Ephemeral Gateway service-start authorization is unsafe" >&2; exit 1; }
systemctl daemon-reload
systemctl try-restart systemd-journald@gateway-vpn.service
systemctl enable gateway-vpn-firewall.service gateway-vpn-firewall-guard.service gateway-vpn-update-recovery.service gateway-vpn-update-finalize.timer gateway-vpn-network-recovery.service gateway-vpn-database-restore.service gateway-vpn-network-broker.socket gateway-vpn-mihomo.service gateway-vpn.service
systemctl restart gateway-vpn-firewall.service
systemctl restart gateway-vpn-firewall-guard.service
systemctl restart gateway-vpn-update-recovery.service
systemctl restart gateway-vpn-network-recovery.service
systemctl restart gateway-vpn-network-broker.socket
systemctl restart gateway-vpn.service

if ((ENABLE_DHCP)); then
  DHCP_START="$LAN_A.$LAN_B.$LAN_C.100"
  DHCP_END="$LAN_A.$LAN_B.$LAN_C.200"
  sed -e "s|__LAN_INTERFACE__|$LAN_INTERFACE|g" \
      -e "s|__LAN_IP__|$LAN_IP|g" \
      -e "s|__DHCP_START__|$DHCP_START|g" \
      -e "s|__DHCP_END__|$DHCP_END|g" \
      -e "s|__NETMASK__|255.255.255.0|g" \
      "$ROOT_DIR/packaging/dnsmasq/dnsmasq.conf.in" >/etc/gateway-vpn/dnsmasq.conf
  chown root:gateway-vpn /etc/gateway-vpn/dnsmasq.conf
  chmod 0640 /etc/gateway-vpn/dnsmasq.conf
  dnsmasq --test --conf-file=/etc/gateway-vpn/dnsmasq.conf
  systemctl enable --now gateway-vpn-dnsmasq.service
fi
GATEWAY_RUNTIME_READY=0
for _ in {1..20}; do
  if systemctl is-active --quiet gateway-vpn-firewall.service &&
     systemctl is-active --quiet gateway-vpn-firewall-guard.service &&
     systemctl is-active --quiet gateway-vpn-network-broker.socket &&
     systemctl is-active --quiet gateway-vpn-network-broker.service &&
     systemctl is-active --quiet gateway-vpn.service &&
     [[ -S /run/gateway-vpn/network-broker.sock ]] &&
     nft list table inet gateway_vpn >/dev/null 2>&1 &&
     [[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]] &&
     ip -o -4 address show dev "$LAN_INTERFACE" scope global | awk '{print $4}' | grep -Fxq "$LAN_ADDRESS" &&
     ss -H -ltn "sport = :8443" | awk '{print $4}' | grep -Fxq "$LAN_IP:8443"; then
    GATEWAY_RUNTIME_READY=1
    break
  fi
  sleep 0.5
done
((GATEWAY_RUNTIME_READY == 1)) || { echo "Installed Gateway services did not reach blocked management-ready state" >&2; exit 1; }
if ((ENABLE_DHCP)); then
  systemctl is-active --quiet gateway-vpn-dnsmasq.service || { echo "Installed Gateway DHCP service is not active" >&2; exit 1; }
fi
EXPECTED_LAN_NETWORK=$(sed -e "s|__LAN_INTERFACE__|$LAN_INTERFACE|g" -e "s|__LAN_ADDRESS__|$LAN_ADDRESS|g" "$ROOT_DIR/packaging/systemd-networkd/70-gateway-vpn-lan.network.in")
[[ $(cat /etc/systemd/network/70-gateway-vpn-lan.network) == "$EXPECTED_LAN_NETWORK" ]] || { echo "Installed persistent Gateway LAN policy verification failed" >&2; exit 1; }
[[ -d /var/lib/gateway-vpn && ! -L /var/lib/gateway-vpn ]] || false
printf '{\n  "version": "%s",\n  "profile": "ubuntu-24.04",\n  "lan_interface": "%s",\n  "lan_address": "%s",\n  "dhcp_enabled": %s,\n  "state": "INSTALLED_NOT_READY"\n}\n' "$RELEASE_VERSION" "$LAN_INTERFACE" "$LAN_ADDRESS" "$([[ $ENABLE_DHCP == 1 ]] && echo true || echo false)" >/var/lib/gateway-vpn/install-report.json
chmod 0600 /var/lib/gateway-vpn/install-report.json
sync
timestamp=$(date -u +%Y%m%dT%H%M%S%NZ)
COMPLETED_MARKER="/var/lib/gateway-vpn-privileged/install-transactions/completed-$timestamp"
mv -T /var/lib/gateway-vpn-privileged/install-transactions/active "$COMPLETED_MARKER"
if ! sync -f /var/lib/gateway-vpn-privileged/install-transactions; then
  mv -T "$COMPLETED_MARKER" /var/lib/gateway-vpn-privileged/install-transactions/active || true
  sync -f /var/lib/gateway-vpn-privileged/install-transactions || true
  false
fi
if ! systemctl disable gateway-vpn-install-recovery.service >/dev/null 2>&1; then
  mv -T "$COMPLETED_MARKER" /var/lib/gateway-vpn-privileged/install-transactions/active || true
  sync -f /var/lib/gateway-vpn-privileged/install-transactions || true
  false
fi
trap - ERR INT TERM
rm -f /run/gateway-vpn-install-authorized || echo "Warning: installation completed but the ephemeral service-start authorization could not be removed" >&2
echo "Installed Gateway VPN $RELEASE_VERSION. Mihomo starts only after a validated active generation exists; DHCP remains opt-in."
cleanup_temp_files
trap - EXIT
