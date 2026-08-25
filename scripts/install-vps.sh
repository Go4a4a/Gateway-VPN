#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ROOT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
APPLY=0
INSTALL_DEPENDENCIES=0
DEPENDENCY_PREFLIGHT_ONLY=0
ALLOW_GATEWAY_SSH=0
RELEASE_DIR=""
TRUSTED_UPDATE_KEY=""
VERSION=""
PUBLIC_ENDPOINT=""
GATEWAY_PUBLIC_KEY=""
ADMIN_PUBLIC_KEY=""

usage() {
  echo "Usage: install-vps.sh --release-dir DIR --trusted-update-key FILE --version VERSION --public-endpoint HOST:51821 --gateway-public-key KEY --admin-public-key KEY [--install-dependencies] [--allow-gateway-ssh] [--apply]"
  echo "Without --apply the installer performs a read-only signed-release, host, and dependency-plan preflight."
}

while (($#)); do
  case "$1" in
    --release-dir) RELEASE_DIR=${2:?}; shift 2 ;;
    --trusted-update-key) TRUSTED_UPDATE_KEY=${2:?}; shift 2 ;;
    --version) VERSION=${2:?}; shift 2 ;;
    --public-endpoint) PUBLIC_ENDPOINT=${2:?}; shift 2 ;;
    --gateway-public-key) GATEWAY_PUBLIC_KEY=${2:?}; shift 2 ;;
    --admin-public-key) ADMIN_PUBLIC_KEY=${2:?}; shift 2 ;;
    --install-dependencies) INSTALL_DEPENDENCIES=1; shift ;;
    --dependency-preflight-only) DEPENDENCY_PREFLIGHT_ONLY=1; shift ;;
    --allow-gateway-ssh) ALLOW_GATEWAY_SSH=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "VPS preflight and apply require root" >&2; exit 1; }
[[ -n "$RELEASE_DIR" && -n "$TRUSTED_UPDATE_KEY" && -n "$VERSION" && -n "$PUBLIC_ENDPOINT" && -n "$GATEWAY_PUBLIC_KEY" && -n "$ADMIN_PUBLIC_KEY" ]] || { usage >&2; exit 2; }
((DEPENDENCY_PREFLIGHT_ONLY == 0 || (INSTALL_DEPENDENCIES == 1 && APPLY == 0))) || { echo "--dependency-preflight-only is reserved for the non-mutating bootstrap phase" >&2; exit 2; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || { echo "Invalid VPS release version" >&2; exit 2; }

validate_wg_public_key() {
  local key=$1 decoded canonical
  [[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 1
  decoded=$(printf '%s' "$key" | base64 --decode 2>/dev/null | wc -c)
  [[ "$decoded" == 32 ]] || return 1
  canonical=$(printf '%s' "$key" | base64 --decode 2>/dev/null | base64 -w 0)
  [[ "$canonical" == "$key" ]]
}
validate_wg_public_key "$GATEWAY_PUBLIC_KEY" || { echo "Gateway WireGuard public key is invalid" >&2; exit 2; }
validate_wg_public_key "$ADMIN_PUBLIC_KEY" || { echo "Admin WireGuard public key is invalid" >&2; exit 2; }
[[ "$GATEWAY_PUBLIC_KEY" != "$ADMIN_PUBLIC_KEY" ]] || { echo "Gateway and admin WireGuard public keys must differ" >&2; exit 2; }

RELEASE_DIR=$(realpath -- "$RELEASE_DIR")
TRUSTED_UPDATE_KEY=$(realpath -- "$TRUSTED_UPDATE_KEY")
[[ -f "$TRUSTED_UPDATE_KEY" && ! -L "$TRUSTED_UPDATE_KEY" ]] || { echo "Trusted VPS update public key must be a regular non-symlink file" >&2; exit 1; }
[[ -x "$RELEASE_DIR/bin/gateway-vpnctl" && -x "$RELEASE_DIR/scripts/install-vps.sh" && -x "$RELEASE_DIR/scripts/uninstall-vps.sh" && -x "$RELEASE_DIR/scripts/recover-vps-install.sh" ]] || { echo "VPS release executables are incomplete" >&2; exit 1; }
[[ -f "$RELEASE_DIR/manifest.sha256" && -f "$RELEASE_DIR/manifest.json" && -f "$RELEASE_DIR/release.sig" && -f "$RELEASE_DIR/release.json" ]] || { echo "Signed VPS release metadata is incomplete" >&2; exit 1; }
(cd -- "$RELEASE_DIR" && sha256sum --check --strict manifest.sha256)

source /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12) PROFILE="${ID}-${VERSION_ID}" ;;
  *) echo "Unsupported VPS OS profile: ${ID:-unknown} ${VERSION_ID:-unknown}" >&2; exit 1 ;;
esac
[[ $(uname -m) == x86_64 ]] || { echo "Gateway VPN VPS release requires x86_64" >&2; exit 1; }
"$RELEASE_DIR/bin/gateway-vpnctl" vps-release-verify --release-dir "$RELEASE_DIR" --public-key "$TRUSTED_UPDATE_KEY" --release-version "$VERSION" --profile "$PROFILE"

for command in systemctl base64 sha256sum realpath sed awk grep getent timedatectl apt-get dpkg-query find sort sync date df wc cat readlink install mktemp mv rm stat uname flock; do
  command -v "$command" >/dev/null || { echo "Missing base VPS prerequisite command: $command" >&2; exit 1; }
done
[[ -d /run/lock && ! -L /run/lock && $(stat -c '%u' /run/lock) == 0 ]] || { echo "VPS runtime lock directory is unavailable" >&2; exit 1; }
if ((APPLY)); then
  LOCK_FILE=/run/lock/gateway-vpn-vps-install.lock
  if [[ ! -e "$LOCK_FILE" && ! -L "$LOCK_FILE" ]]; then
    (set -o noclobber; : >"$LOCK_FILE") || { echo "Cannot create VPS transaction lock safely" >&2; exit 1; }
  fi
  [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" && $(stat -c '%u:%g:%a' "$LOCK_FILE") == "0:0:600" ]] || { echo "VPS transaction lock ownership or mode is invalid" >&2; exit 1; }
  exec 9<>"$LOCK_FILE"
  flock -n 9 || { echo "Another Gateway VPN VPS install/recovery/uninstall transaction is active" >&2; exit 1; }
fi
[[ ! -e /var/lib/gateway-vpn-vps/install-transactions/active && ! -L /var/lib/gateway-vpn-vps/install-transactions/active ]] || { echo "Interrupted VPS installation requires recovery before retry" >&2; exit 1; }
[[ ! -e /run/gateway-vpn-vps-install-authorized && ! -L /run/gateway-vpn-vps-install-authorized ]] || { echo "Stale VPS install authorization artifact requires operator recovery" >&2; exit 1; }
ORPHAN_MARKER_TEMP=0
if [[ -e /var/lib/gateway-vpn-vps/install-transactions/.active.tmp || -L /var/lib/gateway-vpn-vps/install-transactions/.active.tmp ]]; then
  for transaction_dir in /var/lib/gateway-vpn-vps /var/lib/gateway-vpn-vps/install-transactions; do
    [[ -d "$transaction_dir" && ! -L "$transaction_dir" && $(stat -c '%u:%g:%a' "$transaction_dir") == "0:0:700" ]] || { echo "Orphan VPS marker has an unsafe transaction directory" >&2; exit 1; }
  done
  ORPHAN_MARKER_TEMP=1
  [[ -f /var/lib/gateway-vpn-vps/install-transactions/.active.tmp && ! -L /var/lib/gateway-vpn-vps/install-transactions/.active.tmp && $(stat -c '%u:%g:%a' /var/lib/gateway-vpn-vps/install-transactions/.active.tmp) == "0:0:600" ]] || { echo "Orphan VPS marker ownership or mode is unsafe" >&2; exit 1; }
  ORPHAN_MARKER_BYTES=$(stat -c '%s' /var/lib/gateway-vpn-vps/install-transactions/.active.tmp)
  [[ "$ORPHAN_MARKER_BYTES" =~ ^[0-9]+$ && "$ORPHAN_MARKER_BYTES" -le 1024 ]] || { echo "Orphan VPS marker size is unsafe" >&2; exit 1; }
  echo "Validated harmless pre-transaction VPS marker artifact; apply will remove it before continuing"
fi
for partial_path in /etc/wireguard/.gateway-vpn-wg-mgmt.conf.tmp /opt/gateway-vpn-vps/.current.new; do
  [[ ! -e "$partial_path" && ! -L "$partial_path" ]] || { echo "Orphan VPS installation artifact requires operator recovery before retry: $partial_path" >&2; exit 1; }
done
if ((APPLY && ORPHAN_MARKER_TEMP)); then
  rm -f -- /var/lib/gateway-vpn-vps/install-transactions/.active.tmp
  sync -f /var/lib/gateway-vpn-vps/install-transactions
  echo "Removed harmless pre-transaction VPS marker artifact"
fi
[[ -w /proc/sys/net/ipv4/ip_forward && -w /proc/sys/net/ipv6/conf/all/forwarding && -w /proc/sys/net/ipv6/conf/default/forwarding ]] || { echo "Required IPv4/IPv6 forwarding sysctls are unavailable" >&2; exit 1; }
[[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == yes ]] || { echo "VPS clock is not reported as NTP-synchronized" >&2; exit 1; }
getent ahostsv4 github.com >/dev/null || { echo "VPS DNS resolution failed" >&2; exit 1; }
AVAILABLE_KIB=$(df --output=avail / | awk 'NR==2 {print $1}')
MEMORY_KIB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
[[ "$AVAILABLE_KIB" =~ ^[0-9]+$ && "$AVAILABLE_KIB" -ge 524288 ]] || { echo "VPS requires at least 512 MiB free disk" >&2; exit 1; }
[[ "$MEMORY_KIB" =~ ^[0-9]+$ && "$MEMORY_KIB" -ge 262144 ]] || { echo "VPS requires at least 256 MiB RAM" >&2; exit 1; }
apt-get check >/dev/null

validate_ubuntu_20_maintenance() {
  for prerequisite_package in ubuntu-advantage-tools python3-minimal; do
    status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$prerequisite_package" 2>/dev/null || true)
    [[ "$status" == "ii " ]] || { echo "Ubuntu 20.04 prerequisite must be installed before Gateway VPN can manage packages: $prerequisite_package" >&2; exit 1; }
  done
  command -v pro >/dev/null || { echo "Ubuntu 20.04 requires current Ubuntu Pro client" >&2; exit 1; }
  command -v python3 >/dev/null || { echo "Ubuntu 20.04 requires Python 3 for strict Ubuntu Pro status validation" >&2; exit 1; }
  pro status --format=json | python3 -c '
import datetime, json, sys
value=json.load(sys.stdin)
if value.get("attached") is not True:
    raise SystemExit("Ubuntu 20.04 is not attached to Ubuntu Pro")
expires=value.get("expires", "")
try:
    expiry=datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))
except ValueError:
    raise SystemExit("Ubuntu Pro expiry is invalid")
if expiry <= datetime.datetime.now(datetime.timezone.utc):
    raise SystemExit("Ubuntu Pro subscription is expired")
services={item.get("name"): item.get("status") for item in value.get("services", [])}
if services.get("esm-infra") != "enabled" or services.get("esm-apps") != "enabled":
    raise SystemExit("Ubuntu 20.04 requires enabled esm-infra and esm-apps")
'
  PENDING_UPDATES=$(apt-get -s upgrade 2>/dev/null | awk '/^Inst / {count++} END {print count+0}')
  [[ "$PENDING_UPDATES" == 0 ]] || { echo "Ubuntu 20.04 has pending package updates; update and re-run preflight" >&2; exit 1; }
}

if [[ "$PROFILE" == ubuntu-20.04 ]]; then
  validate_ubuntu_20_maintenance
fi

REQUIRED_PACKAGES=(iproute2 nftables wireguard-tools kmod procps python3-minimal)
MISSING_PACKAGES=()
for package in "${REQUIRED_PACKAGES[@]}"; do
  status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)
  [[ "$status" == "ii " ]] || MISSING_PACKAGES+=("$package")
done

APT_PLAN_FILE=""
PREFLIGHT_RULESET=""
cleanup_temp_files() {
  local filename
  for filename in "${APT_PLAN_FILE:-}" "${PREFLIGHT_RULESET:-}"; do
    [[ -z "$filename" ]] || rm -f -- "$filename"
  done
}
trap cleanup_temp_files EXIT

simulate_dependency_install() {
  : >"$APT_PLAN_FILE"
  apt-get -s install --no-install-recommends --no-remove --no-upgrade "${MISSING_PACKAGES[@]}" >"$APT_PLAN_FILE" || return 10
  if grep -q '^Remv ' "$APT_PLAN_FILE"; then
    echo "APT dependency plan attempts to remove packages" >&2
    return 20
  fi
  if grep -Eq '^Inst [^ ]+ \[' "$APT_PLAN_FILE"; then
    echo "APT dependency plan attempts to upgrade installed packages" >&2
    return 22
  fi
  planned_installs=$(awk '/^Inst / {count++} END {print count+0}' "$APT_PLAN_FILE")
  [[ "$planned_installs" =~ ^[0-9]+$ && "$planned_installs" -gt 0 ]] || {
    echo "APT dependency plan contains no installable package changes" >&2
    return 21
  }
  echo "APT dependency simulation validated: $planned_installs new package actions, no upgrades or removals"
}

if ((${#MISSING_PACKAGES[@]})); then
  printf 'Missing managed VPS packages:'
  printf ' %s' "${MISSING_PACKAGES[@]}"
  printf '\n'
  ((INSTALL_DEPENDENCIES)) || {
    echo "Missing VPS packages; re-run with --install-dependencies to validate a package plan, and add --apply to install them" >&2
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
      echo "Current APT indexes cannot produce the dependency plan; --apply would refresh indexes before a second mandatory simulation" >&2
      echo "VPS dependency preflight incomplete; no packages or Gateway VPN files were changed" >&2
      exit 10
    fi
    exit 1
  fi
  if ((APPLY == 0)); then
    echo "VPS dependency plan validated; full host preflight NOT_RUN because required packages are missing."
    echo "Re-run with --install-dependencies --apply to install packages, repeat full preflight, and install Gateway VPN."
    exit 0
  fi
  echo "Refreshing configured APT indexes before installing exact missing VPS packages"
  apt-get update
  if [[ "$PROFILE" == ubuntu-20.04 ]]; then
    validate_ubuntu_20_maintenance
  fi
  simulate_dependency_install || { echo "APT dependency simulation failed after index refresh" >&2; exit 1; }
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install --yes --no-install-recommends --no-remove --no-upgrade "${MISSING_PACKAGES[@]}"
  for package in "${MISSING_PACKAGES[@]}"; do
    status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)
    [[ "$status" == "ii " ]] || { echo "VPS dependency package was not fully installed: $package" >&2; exit 1; }
  done
  apt-get check >/dev/null
  echo "Managed VPS dependency packages installed and verified"
fi

for command in ip nft wg wg-quick sysctl ss python3 modprobe; do
  command -v "$command" >/dev/null || { echo "Managed VPS dependency did not provide required command: $command" >&2; exit 1; }
done
[[ -d /sys/module/wireguard ]] || modprobe -n wireguard >/dev/null 2>&1 || { echo "Kernel WireGuard support is unavailable" >&2; exit 1; }

python3 - "$PUBLIC_ENDPOINT" <<'PY'
import ipaddress
import socket
import sys

value = sys.argv[1]
host, separator, port = value.rpartition(":")
if not separator or port != "51821" or not host or len(host) > 253:
    raise SystemExit("VPS public endpoint must use HOST:51821")
try:
    literal = ipaddress.ip_address(host)
    addresses = [literal]
except ValueError:
    labels = host.rstrip(".").split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 or label[0] == "-" or label[-1] == "-" or not all(c.isascii() and (c.isalnum() or c == "-") for c in label) for label in labels):
        raise SystemExit("VPS endpoint hostname is invalid")
    addresses = []
    for item in socket.getaddrinfo(host, 51821, socket.AF_INET, socket.SOCK_DGRAM):
        address = ipaddress.ip_address(item[4][0])
        if address not in addresses:
            addresses.append(address)
if not addresses or not any(address.version == 4 and address.is_global for address in addresses):
    raise SystemExit("VPS endpoint has no public globally routable IPv4 address")
PY

validate_preserved_wg_config() {
  local filename=$1
  [[ -f "$filename" && ! -L "$filename" ]] || { echo "Preserved wg-mgmt config must be a regular non-symlink file" >&2; return 1; }
  [[ $(stat -c '%u:%g:%a' "$filename") == "0:0:600" ]] || { echo "Preserved wg-mgmt config must be root:root mode 0600" >&2; return 1; }
  local bytes
  bytes=$(stat -c '%s' "$filename")
  [[ "$bytes" =~ ^[0-9]+$ && "$bytes" -gt 0 && "$bytes" -le 4096 ]] || { echo "Preserved wg-mgmt config size is invalid" >&2; return 1; }
  python3 - "$filename" "$GATEWAY_PUBLIC_KEY" "$ADMIN_PUBLIC_KEY" <<'PY'
import base64
import binascii
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
gateway_key, admin_key = sys.argv[2:]
tokens = []
for raw in path.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if line.startswith("[") and line.endswith("]"):
        tokens.append((line, ""))
        continue
    key, separator, value = line.partition(" = ")
    if not separator or not key or not value:
        raise SystemExit("preserved wg-mgmt config syntax is invalid")
    tokens.append((key, value))

expected = [
    ("[Interface]", ""),
    ("Address", "10.80.0.1/24"),
    ("ListenPort", "51821"),
    ("PrivateKey", None),
    ("[Peer]", ""),
    ("PublicKey", gateway_key),
    ("AllowedIPs", "10.80.0.2/32"),
    ("[Peer]", ""),
    ("PublicKey", admin_key),
    ("AllowedIPs", "10.80.0.10/32"),
]
if len(tokens) != len(expected):
    raise SystemExit("preserved wg-mgmt config has unexpected fields")
for actual, wanted in zip(tokens, expected):
    if actual[0] != wanted[0] or (wanted[1] is not None and actual[1] != wanted[1]):
        raise SystemExit("preserved wg-mgmt config differs from the requested peer contract")
try:
    private_key = base64.b64decode(tokens[3][1], validate=True)
except (binascii.Error, ValueError):
    raise SystemExit("preserved wg-mgmt private key is invalid")
if len(private_key) != 32 or base64.b64encode(private_key).decode("ascii") != tokens[3][1]:
    raise SystemExit("preserved wg-mgmt private key is non-canonical")
PY
}

DEST="/opt/gateway-vpn-vps/releases/v$VERSION"
EXISTING=0
PRESERVED_WG_CONFIG=0
if [[ -e "$DEST" || -L /opt/gateway-vpn-vps/current || -e /etc/gateway-vpn-vps || -e /etc/sysctl.d/90-gateway-vpn-vps.conf || -e /etc/systemd/system/gateway-vpn-vps-firewall.service || -e /etc/systemd/system/wg-quick@wg-mgmt.service.d ]]; then
  [[ -d "$DEST" && ! -L "$DEST" && -L /opt/gateway-vpn-vps/current && $(readlink /opt/gateway-vpn-vps/current) == "releases/v$VERSION" && -f /etc/gateway-vpn-vps/update-signing.pub && -f /etc/gateway-vpn-vps/firewall.nft && -f /etc/sysctl.d/90-gateway-vpn-vps.conf && -f /etc/systemd/system/gateway-vpn-vps-firewall.service && -f /etc/systemd/system/wg-quick@wg-mgmt.service.d/gateway-vpn.conf && -f /etc/systemd/system/gateway-vpn-vps-install-recovery.service && -x /usr/libexec/gateway-vpn-vps-install-recovery && -f /etc/wireguard/wg-mgmt.conf && -f /var/lib/gateway-vpn-vps/install-report.json ]] || { echo "Partial or conflicting Gateway VPN VPS installation exists" >&2; exit 1; }
  "$DEST/bin/gateway-vpnctl" vps-release-verify --release-dir "$DEST" --public-key /etc/gateway-vpn-vps/update-signing.pub --release-version "$VERSION" --profile "$PROFILE"
  validate_preserved_wg_config /etc/wireguard/wg-mgmt.conf
  EXISTING=1
elif [[ -e /etc/wireguard/wg-mgmt.conf || -L /etc/wireguard/wg-mgmt.conf ]]; then
  validate_preserved_wg_config /etc/wireguard/wg-mgmt.conf
  PRESERVED_WG_CONFIG=1
  echo "Validated preserved wg-mgmt private key and requested peer configuration for reinstall"
fi

if ((EXISTING == 0)); then
  for conflict in /etc/sysctl.d/90-gateway-vpn-vps.conf /etc/systemd/system/gateway-vpn-vps-firewall.service /etc/systemd/system/gateway-vpn-vps-install-recovery.service /usr/libexec/gateway-vpn-vps-install-recovery /etc/systemd/system/wg-quick@wg-mgmt.service.d /etc/wireguard/.gateway-vpn-wg-mgmt.conf.tmp /opt/gateway-vpn-vps/.current.new; do
    [[ ! -e "$conflict" && ! -L "$conflict" ]] || { echo "Conflicting VPS managed path exists: $conflict" >&2; exit 1; }
  done
  if systemctl is-active --quiet ufw.service || systemctl is-active --quiet firewalld.service; then
    echo "Active UFW/firewalld conflicts with the owned Gateway VPN VPS firewall" >&2
    exit 1
  fi
  if /usr/sbin/nft list table inet gateway_vpn_vps >/dev/null 2>&1; then
    echo "Unmanaged table inet gateway_vpn_vps already exists" >&2
    exit 1
  fi
  if ip link show dev wg-mgmt >/dev/null 2>&1; then
    echo "Unmanaged wg-mgmt interface already exists" >&2
    exit 1
  fi
  if ss -H -lun 'sport = :51821' | grep -q .; then
    echo "UDP port 51821 is already in use" >&2
    exit 1
  fi
fi

PORTS=8443
((ALLOW_GATEWAY_SSH)) && PORTS="22, 8443"
if ((EXISTING)); then
  grep -Fq "\"public_endpoint\": \"$PUBLIC_ENDPOINT\"" /var/lib/gateway-vpn-vps/install-report.json || { echo "Existing VPS public endpoint differs; explicit reconfiguration is required" >&2; exit 1; }
  grep -Fq "tcp dport { $PORTS }" /etc/gateway-vpn-vps/firewall.nft || { echo "Existing VPS management-port policy differs; explicit reconfiguration is required" >&2; exit 1; }
fi
PREFLIGHT_RULESET=$(mktemp)
sed "s|__GATEWAY_TCP_PORTS__|$PORTS|g" "$ROOT_DIR/packaging/vps/nftables/gateway-vpn-vps.nft.in" >"$PREFLIGHT_RULESET"
nft --check --file "$PREFLIGHT_RULESET"
if ((EXISTING)); then
  VPS_PRIVATE_KEY=$(awk '/^PrivateKey = / {print $3}' /etc/wireguard/wg-mgmt.conf)
  VPS_PUBLIC_KEY=$(printf '%s' "$VPS_PRIVATE_KEY" | wg pubkey)
  unset VPS_PRIVATE_KEY
fi

echo "Validated VPS profile $PROFILE release $VERSION"
echo "Public endpoint: $PUBLIC_ENDPOINT"
echo "WireGuard: wg-mgmt / 10.80.0.1/24 / UDP 51821"
echo "Gateway peer: 10.80.0.2/32; admin peer: 10.80.0.10/32"
echo "Gateway TCP forwarding ports: $PORTS"
if ((EXISTING)); then
  if systemctl is-enabled --quiet gateway-vpn-vps-install-recovery.service; then
    echo "Completed VPS install unexpectedly has first-install recovery enabled" >&2
    exit 1
  fi
  systemctl is-active --quiet gateway-vpn-vps-firewall.service
  systemctl is-active --quiet wg-quick@wg-mgmt.service
  [[ $(wg show wg-mgmt listen-port) == 51821 ]]
  [[ $(wg show wg-mgmt public-key) == "$VPS_PUBLIC_KEY" ]]
  [[ $(wg show wg-mgmt peers | wc -l) == 2 ]]
  wg show wg-mgmt allowed-ips | awk -v gateway="$GATEWAY_PUBLIC_KEY" -v admin="$ADMIN_PUBLIC_KEY" '
BEGIN { gateway_ok=0; admin_ok=0; rows=0 }
{
  rows++
  if ($1 == gateway && $2 == "10.80.0.2/32") gateway_ok++
  if ($1 == admin && $2 == "10.80.0.10/32") admin_ok++
}
END { exit !(rows == 2 && gateway_ok == 1 && admin_ok == 1) }
'
  ip -4 route get 10.80.0.2 | grep -Eq 'dev wg-mgmt'
  ip -4 route get 10.80.0.10 | grep -Eq 'dev wg-mgmt'
  nft list table inet gateway_vpn_vps >/dev/null
  echo "Gateway VPN VPS $VERSION is already installed with the requested immutable release and peers."
  exit 0
fi
if ((APPLY == 0)); then
  echo "VPS dry-run complete. Re-run with --apply to install."
  exit 0
fi

rollback_install() {
  local code=$?
  ((code != 0)) || code=1
  trap - ERR INT TERM
  flock -u 9 || true
  exec 9>&-
  if [[ -x /usr/libexec/gateway-vpn-vps-install-recovery ]]; then
    /usr/libexec/gateway-vpn-vps-install-recovery || true
  fi
  exit "$code"
}

install -d -m 0700 /var/lib/gateway-vpn-vps /var/lib/gateway-vpn-vps/install-transactions
OLD_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
OLD_IPV6_ALL=$(cat /proc/sys/net/ipv6/conf/all/forwarding)
OLD_IPV6_DEFAULT=$(cat /proc/sys/net/ipv6/conf/default/forwarding)
install -D -m 0700 "$ROOT_DIR/scripts/recover-vps-install.sh" /usr/libexec/gateway-vpn-vps-install-recovery
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-install-recovery.service" /etc/systemd/system/gateway-vpn-vps-install-recovery.service
systemctl daemon-reload
systemctl enable gateway-vpn-vps-install-recovery.service
MARKER_TMP=/var/lib/gateway-vpn-vps/install-transactions/.active.tmp
printf 'version=%s\nold_ipv4_forward=%s\nold_ipv6_all_forwarding=%s\nold_ipv6_default_forwarding=%s\npreserve_wg_config=%s\n' "$VERSION" "$OLD_FORWARD" "$OLD_IPV6_ALL" "$OLD_IPV6_DEFAULT" "$PRESERVED_WG_CONFIG" >"$MARKER_TMP"
chmod 0600 "$MARKER_TMP"
sync -f "$MARKER_TMP"
mv -T "$MARKER_TMP" /var/lib/gateway-vpn-vps/install-transactions/active
sync
trap rollback_install ERR INT TERM

install -d -m 0755 "$DEST"
while IFS= read -r -d '' source; do
  relative=${source#"$RELEASE_DIR/"}
  mode=0644
  [[ -x "$source" ]] && mode=0755
  install -D -m "$mode" "$source" "$DEST/$relative"
done < <(find "$RELEASE_DIR" -type f -print0 | sort -z)
install -D -m 0644 "$TRUSTED_UPDATE_KEY" /etc/gateway-vpn-vps/update-signing.pub
"$DEST/bin/gateway-vpnctl" vps-release-verify --release-dir "$DEST" --public-key /etc/gateway-vpn-vps/update-signing.pub --release-version "$VERSION" --profile "$PROFILE"

install -d -m 0700 /etc/wireguard
if ((PRESERVED_WG_CONFIG)); then
  VPS_PRIVATE_KEY=$(awk '/^PrivateKey = / {print $3}' /etc/wireguard/wg-mgmt.conf)
  VPS_PUBLIC_KEY=$(printf '%s' "$VPS_PRIVATE_KEY" | wg pubkey)
else
  VPS_PRIVATE_KEY=$(wg genkey)
  VPS_PUBLIC_KEY=$(printf '%s' "$VPS_PRIVATE_KEY" | wg pubkey)
  WG_TEMP=/etc/wireguard/.gateway-vpn-wg-mgmt.conf.tmp
  (set -o noclobber; : >"$WG_TEMP")
  printf '[Interface]\nAddress = 10.80.0.1/24\nListenPort = 51821\nPrivateKey = %s\n\n[Peer]\n# Gateway VPN Gateway\nPublicKey = %s\nAllowedIPs = 10.80.0.2/32\n\n[Peer]\n# Administrator\nPublicKey = %s\nAllowedIPs = 10.80.0.10/32\n' "$VPS_PRIVATE_KEY" "$GATEWAY_PUBLIC_KEY" "$ADMIN_PUBLIC_KEY" >"$WG_TEMP"
  chmod 0600 "$WG_TEMP"
  sync -f "$WG_TEMP"
  mv -T "$WG_TEMP" /etc/wireguard/wg-mgmt.conf
  sync -f /etc/wireguard
fi
unset VPS_PRIVATE_KEY

install -D -m 0644 "$ROOT_DIR/packaging/vps/sysctl.d/90-gateway-vpn-vps.conf" /etc/sysctl.d/90-gateway-vpn-vps.conf
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-firewall.service" /etc/systemd/system/gateway-vpn-vps-firewall.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/wg-quick@wg-mgmt.service.d/gateway-vpn.conf" /etc/systemd/system/wg-quick@wg-mgmt.service.d/gateway-vpn.conf
install -d -m 0750 /etc/gateway-vpn-vps
sed "s|__GATEWAY_TCP_PORTS__|$PORTS|g" "$ROOT_DIR/packaging/vps/nftables/gateway-vpn-vps.nft.in" >/etc/gateway-vpn-vps/firewall.nft
chmod 0640 /etc/gateway-vpn-vps/firewall.nft
nft --check --file /etc/gateway-vpn-vps/firewall.nft
sysctl -q -p /etc/sysctl.d/90-gateway-vpn-vps.conf

install -d -m 0755 /opt/gateway-vpn-vps
ln -sfn "releases/v$VERSION" /opt/gateway-vpn-vps/.current.new
mv -Tf /opt/gateway-vpn-vps/.current.new /opt/gateway-vpn-vps/current
sync
systemctl daemon-reload
(set -o noclobber; : >/run/gateway-vpn-vps-install-authorized) || { echo "Cannot create ephemeral VPS service-start authorization safely" >&2; exit 1; }
chmod 0600 /run/gateway-vpn-vps-install-authorized
[[ -f /run/gateway-vpn-vps-install-authorized && ! -L /run/gateway-vpn-vps-install-authorized && $(stat -c '%u:%g:%a' /run/gateway-vpn-vps-install-authorized) == "0:0:600" ]] || { echo "Ephemeral VPS service-start authorization is unsafe" >&2; exit 1; }
systemctl enable gateway-vpn-vps-firewall.service wg-quick@wg-mgmt.service
systemctl restart gateway-vpn-vps-firewall.service
systemctl restart wg-quick@wg-mgmt.service
[[ $(wg show wg-mgmt listen-port) == 51821 ]]
ip -4 route get 10.80.0.2 | grep -Eq 'dev wg-mgmt'
ip -4 route get 10.80.0.10 | grep -Eq 'dev wg-mgmt'
nft list table inet gateway_vpn_vps >/dev/null

install -d -m 0700 /var/lib/gateway-vpn-vps
printf '{\n  "version": "%s",\n  "profile": "%s",\n  "public_endpoint": "%s",\n  "interface": "wg-mgmt",\n  "vps_address": "10.80.0.1/24",\n  "gateway_address": "10.80.0.2/32",\n  "admin_address": "10.80.0.10/32",\n  "vps_public_key": "%s",\n  "state": "INSTALLED_NOT_READY"\n}\n' "$VERSION" "$PROFILE" "$PUBLIC_ENDPOINT" "$VPS_PUBLIC_KEY" >/var/lib/gateway-vpn-vps/install-report.json
chmod 0600 /var/lib/gateway-vpn-vps/install-report.json
sync
timestamp=$(date -u +%Y%m%dT%H%M%S%NZ)
COMPLETED_MARKER="/var/lib/gateway-vpn-vps/install-transactions/completed-$timestamp"
mv -T /var/lib/gateway-vpn-vps/install-transactions/active "$COMPLETED_MARKER"
if ! sync -f /var/lib/gateway-vpn-vps/install-transactions; then
  mv -T "$COMPLETED_MARKER" /var/lib/gateway-vpn-vps/install-transactions/active || true
  sync -f /var/lib/gateway-vpn-vps/install-transactions || true
  false
fi
if ! systemctl disable gateway-vpn-vps-install-recovery.service >/dev/null 2>&1; then
  mv -T "$COMPLETED_MARKER" /var/lib/gateway-vpn-vps/install-transactions/active || true
  sync -f /var/lib/gateway-vpn-vps/install-transactions || true
  false
fi
trap - ERR INT TERM
rm -f /run/gateway-vpn-vps-install-authorized || echo "Warning: VPS installation completed but the ephemeral service-start authorization could not be removed" >&2
cleanup_temp_files
trap - EXIT
echo "Gateway VPN VPS $VERSION installed as INSTALLED_NOT_READY."
echo "VPS WireGuard public key: $VPS_PUBLIC_KEY"
echo "Readiness requires Gateway/admin peer configuration and a verified handshake through the public endpoint."
