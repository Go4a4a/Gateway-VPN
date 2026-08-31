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
RELEASE_VERSION=""
PUBLIC_ENDPOINT=""
GATEWAY_PUBLIC_KEY=""
ADMIN_PUBLIC_KEY=""
HUB_ADMIN_PASSWORD_FILE=""

usage() {
  echo "Usage: install-vps.sh --release-dir DIR --trusted-update-key FILE --version VERSION --public-endpoint HOST:51821 --gateway-public-key KEY --admin-public-key KEY [--hub-admin-password-file FILE] [--install-dependencies] [--allow-gateway-ssh] [--apply]"
  echo "Without --apply the installer performs a read-only signed-release, host, and dependency-plan preflight."
}

while (($#)); do
  case "$1" in
    --release-dir) RELEASE_DIR=${2:?}; shift 2 ;;
    --trusted-update-key) TRUSTED_UPDATE_KEY=${2:?}; shift 2 ;;
    --version) RELEASE_VERSION=${2:?}; shift 2 ;;
    --public-endpoint) PUBLIC_ENDPOINT=${2:?}; shift 2 ;;
    --gateway-public-key) GATEWAY_PUBLIC_KEY=${2:?}; shift 2 ;;
    --admin-public-key) ADMIN_PUBLIC_KEY=${2:?}; shift 2 ;;
    --hub-admin-password-file) HUB_ADMIN_PASSWORD_FILE=${2:?}; shift 2 ;;
    --install-dependencies) INSTALL_DEPENDENCIES=1; shift ;;
    --dependency-preflight-only) DEPENDENCY_PREFLIGHT_ONLY=1; shift ;;
    --allow-gateway-ssh) ALLOW_GATEWAY_SSH=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "VPS preflight and apply require root" >&2; exit 1; }
[[ -n "$RELEASE_DIR" && -n "$TRUSTED_UPDATE_KEY" && -n "$RELEASE_VERSION" && -n "$PUBLIC_ENDPOINT" && -n "$GATEWAY_PUBLIC_KEY" && -n "$ADMIN_PUBLIC_KEY" ]] || { usage >&2; exit 2; }
((DEPENDENCY_PREFLIGHT_ONLY == 0 || (INSTALL_DEPENDENCIES == 1 && APPLY == 0))) || { echo "--dependency-preflight-only is reserved for the non-mutating bootstrap phase" >&2; exit 2; }
[[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || { echo "Invalid VPS release version" >&2; exit 2; }

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
[[ -x "$RELEASE_DIR/bin/gateway-vpnctl" && -x "$RELEASE_DIR/bin/gateway-vpn-vps-agent" && -x "$RELEASE_DIR/scripts/install-vps.sh" && -x "$RELEASE_DIR/scripts/uninstall-vps.sh" && -x "$RELEASE_DIR/scripts/recover-vps-install.sh" ]] || { echo "VPS release executables are incomplete" >&2; exit 1; }
[[ -f "$RELEASE_DIR/manifest.sha256" && -f "$RELEASE_DIR/manifest.json" && -f "$RELEASE_DIR/release.sig" && -f "$RELEASE_DIR/release.json" ]] || { echo "Signed VPS release metadata is incomplete" >&2; exit 1; }
(cd -- "$RELEASE_DIR" && sha256sum --check --strict manifest.sha256)

source /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12) PROFILE="${ID}-${VERSION_ID}" ;;
  *) echo "Unsupported VPS OS profile: ${ID:-unknown} ${VERSION_ID:-unknown}" >&2; exit 1 ;;
esac
[[ $(uname -m) == x86_64 ]] || { echo "Gateway VPN VPS release requires x86_64" >&2; exit 1; }
"$RELEASE_DIR/bin/gateway-vpnctl" vps-release-verify --release-dir "$RELEASE_DIR" --public-key "$TRUSTED_UPDATE_KEY" --release-version "$RELEASE_VERSION" --profile "$PROFILE"
if [[ -n "$HUB_ADMIN_PASSWORD_FILE" ]]; then
  [[ -f "$HUB_ADMIN_PASSWORD_FILE" && ! -L "$HUB_ADMIN_PASSWORD_FILE" ]] || { echo "VPS Hub password file must be a regular non-symlink file" >&2; exit 1; }
  HUB_ADMIN_PASSWORD_FILE=$(realpath -- "$HUB_ADMIN_PASSWORD_FILE")
  "$RELEASE_DIR/bin/gateway-vpn-vps-agent" --check-password-file "$HUB_ADMIN_PASSWORD_FILE"
fi

for command in systemctl base64 sha256sum realpath sed awk grep getent timedatectl apt-get dpkg-query find sort sync date df wc cat readlink install mktemp mv rm stat uname flock groupadd groupdel useradd userdel chown chmod openssl ss hostname id sleep; do
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
  for prerequisite_package in ubuntu-advantage-tools python3; do
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

REQUIRED_PACKAGES=(iproute2 nftables wireguard-tools kmod procps python3 openssl passwd)
MISSING_PACKAGES=()
for package in "${REQUIRED_PACKAGES[@]}"; do
  status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)
  [[ "$status" == "ii " ]] || MISSING_PACKAGES+=("$package")
done

APT_PLAN_FILE=""
PREFLIGHT_RULESET=""
HUB_ADMIN_PASSWORD_TEMP=""
cleanup_temp_files() {
  local filename
  for filename in "${APT_PLAN_FILE:-}" "${PREFLIGHT_RULESET:-}" "${HUB_ADMIN_PASSWORD_TEMP:-}"; do
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
    # A clean supported host may not have package indexes yet. Only the
    # generic apt simulation failure is recoverable by an explicit apply;
    # semantic remove/upgrade/empty-plan rejections remain terminal.
    if ((APPLY == 0 || SIMULATION_RESULT != 10)); then
      exit 1
    fi
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
  [[ "$bytes" =~ ^[0-9]+$ && "$bytes" -gt 0 && "$bytes" -le 1048576 ]] || { echo "Preserved wg-mgmt config size is invalid" >&2; return 1; }
  python3 - "$filename" "$GATEWAY_PUBLIC_KEY" "$ADMIN_PUBLIC_KEY" "$PRESERVE_AGENT_USER" <<'PY'
import base64
import binascii
import ipaddress
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
gateway_key, admin_key, managed = sys.argv[2], sys.argv[3], sys.argv[4] == "1"
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

if not managed:
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
        raise SystemExit("preserved wg-mgmt config has unexpected legacy fields")
    for actual, wanted in zip(tokens, expected):
        if actual[0] != wanted[0] or (wanted[1] is not None and actual[1] != wanted[1]):
            raise SystemExit("preserved wg-mgmt config differs from the requested legacy peer contract")
else:
    if not tokens or tokens[0] != ("[Interface]", ""):
        raise SystemExit("managed wg-mgmt config has no Interface section")
    sections = []
    current = None
    for key, value in tokens:
        if key in ("[Interface]", "[Peer]"):
            current = {"kind": key}
            sections.append(current)
            continue
        if current is None or key in current:
            raise SystemExit("managed wg-mgmt config has duplicate or misplaced fields")
        current[key] = value
    interface = sections[0]
    if interface["kind"] != "[Interface]" or set(interface) not in ({"kind", "Address", "ListenPort", "PrivateKey"}, {"kind", "Address", "ListenPort", "PrivateKey", "Table"}):
        raise SystemExit("managed wg-mgmt Interface fields are invalid")
    if interface["ListenPort"] != "51821" or interface.get("Table", "off") != "off":
        raise SystemExit("managed wg-mgmt ownership fields changed")
    addresses = [item.strip() for item in interface["Address"].split(",")]
    if "10.80.0.1/24" not in addresses or not 1 <= len(addresses) <= 65 or len(addresses) != len(set(addresses)):
        raise SystemExit("managed wg-mgmt interface addresses are invalid")
    for value in addresses:
        address = ipaddress.ip_interface(value)
        if address.version != 4 or not address.ip.is_private or not 16 <= address.network.prefixlen <= 30 or str(address) != value:
            raise SystemExit("managed wg-mgmt contains an unsafe interface address")
    if len(sections) > 129:
        raise SystemExit("managed wg-mgmt peer count exceeds its bound")
    peer_keys = set()
    for peer in sections[1:]:
        if peer["kind"] != "[Peer]" or set(peer) != {"kind", "PublicKey", "AllowedIPs"}:
            raise SystemExit("managed wg-mgmt peer fields are invalid")
        if peer["PublicKey"] in peer_keys:
            raise SystemExit("managed wg-mgmt peer key is duplicated")
        try:
            decoded_peer_key = base64.b64decode(peer["PublicKey"], validate=True)
        except (binascii.Error, ValueError):
            raise SystemExit("managed wg-mgmt peer key is invalid")
        if len(decoded_peer_key) != 32 or base64.b64encode(decoded_peer_key).decode("ascii") != peer["PublicKey"]:
            raise SystemExit("managed wg-mgmt peer key is non-canonical")
        peer_keys.add(peer["PublicKey"])
        allowed = [item.strip() for item in peer["AllowedIPs"].split(",")]
        if not allowed or len(allowed) > 1024 or len(allowed) != len(set(allowed)):
            raise SystemExit("managed wg-mgmt AllowedIPs are invalid")
        for value in allowed:
            prefix = ipaddress.ip_network(value)
            if prefix.version != 4 or not prefix.is_private or prefix.prefixlen < 16 or str(prefix) != value:
                raise SystemExit("managed wg-mgmt contains an unsafe AllowedIPs value")
try:
    private_value = next(value for key, value in tokens if key == "PrivateKey")
    private_key = base64.b64decode(private_value, validate=True)
except (binascii.Error, ValueError):
    raise SystemExit("preserved wg-mgmt private key is invalid")
if len(private_key) != 32 or base64.b64encode(private_key).decode("ascii") != private_value:
    raise SystemExit("preserved wg-mgmt private key is non-canonical")
PY
}

AGENT_USER=gateway-vpn-vps
AGENT_STATE=/var/lib/gateway-vpn-vps/agent
PRESERVE_AGENT_USER=0
if getent passwd "$AGENT_USER" >/dev/null; then
  AGENT_PASSWD=$(getent passwd "$AGENT_USER")
  [[ $(printf '%s\n' "$AGENT_PASSWD" | awk -F: '{print NF ":" $1 ":" $6 ":" $7}') == "7:gateway-vpn-vps:/nonexistent:/usr/sbin/nologin" ]] || { echo "Existing VPS Agent account has an incompatible login contract" >&2; exit 1; }
  getent group "$AGENT_USER" >/dev/null || { echo "Existing VPS Agent account has no matching group" >&2; exit 1; }
  AGENT_USER_GID=$(printf '%s\n' "$AGENT_PASSWD" | awk -F: '{print $4}')
  AGENT_GROUP_GID=$(getent group "$AGENT_USER" | awk -F: '{print $3}')
  [[ "$AGENT_USER_GID" == "$AGENT_GROUP_GID" && $(id -gn "$AGENT_USER") == "$AGENT_USER" ]] || { echo "Existing VPS Agent account does not use its dedicated primary group" >&2; exit 1; }
  [[ -d "$AGENT_STATE" && ! -L "$AGENT_STATE" ]] || { echo "Existing VPS Agent account without preserved Agent state is a conflict" >&2; exit 1; }
  [[ -d /var/lib/gateway-vpn-vps && ! -L /var/lib/gateway-vpn-vps && $(stat -c '%U:%G:%a' /var/lib/gateway-vpn-vps) == "root:gateway-vpn-vps:710" ]] || { echo "Preserved VPS state-root ownership or mode is unsafe" >&2; exit 1; }
  [[ $(stat -c '%U:%G:%a' "$AGENT_STATE") == "gateway-vpn-vps:gateway-vpn-vps:700" ]] || { echo "Preserved VPS Agent state ownership or mode is unsafe" >&2; exit 1; }
  for preserved_agent_file in "$AGENT_STATE/vps-agent.db" "$AGENT_STATE/secrets/wireguard/server.key" "$AGENT_STATE/secrets/update/identity.key" "$AGENT_STATE/tls/cert.pem" "$AGENT_STATE/tls/key.pem"; do
    [[ -f "$preserved_agent_file" && ! -L "$preserved_agent_file" && $(stat -c '%U:%G:%a' "$preserved_agent_file") == "gateway-vpn-vps:gateway-vpn-vps:600" ]] || { echo "Preserved VPS Agent file is missing or unsafe: $preserved_agent_file" >&2; exit 1; }
  done
  PRESERVE_AGENT_USER=1
elif getent group "$AGENT_USER" >/dev/null; then
  echo "Existing gateway-vpn-vps group without its service user is a conflict" >&2
  exit 1
elif [[ -e "$AGENT_STATE" || -L "$AGENT_STATE" ]]; then
  echo "Preserved VPS Agent state without its dedicated service account is a conflict" >&2
  exit 1
fi

DEST="/opt/gateway-vpn-vps/releases/v$RELEASE_VERSION"
EXISTING=0
PRESERVED_WG_CONFIG=0
if [[ -e "$DEST" || -L /opt/gateway-vpn-vps/current || -L /opt/gateway-vpn-vps/recovery || -e /etc/gateway-vpn-vps || -e /etc/sysctl.d/90-gateway-vpn-vps.conf || -e /etc/systemd/system/gateway-vpn-vps-firewall.service || -e /etc/systemd/system/gateway-vpn-vps-agent.service || -e /etc/systemd/system/gateway-vpn-vps-operations.service || -e /etc/systemd/system/gateway-vpn-vps-update.service || -e /etc/systemd/system/wg-quick@wg-mgmt.service.d ]]; then
  [[ $PRESERVE_AGENT_USER == 1 && -d "$DEST" && ! -L "$DEST" && -L /opt/gateway-vpn-vps/current && $(readlink /opt/gateway-vpn-vps/current) == "releases/v$RELEASE_VERSION" && -L /opt/gateway-vpn-vps/recovery && $(readlink /opt/gateway-vpn-vps/recovery) == "releases/v$RELEASE_VERSION" && -f /etc/gateway-vpn-vps/update-signing.pub && -f /etc/gateway-vpn-vps/firewall.nft && -f /etc/gateway-vpn-vps/config.yaml && -f /etc/sysctl.d/90-gateway-vpn-vps.conf && -f /etc/systemd/system/gateway-vpn-vps-firewall.service && -f /etc/systemd/system/gateway-vpn-vps-agent.service && -f /etc/systemd/system/gateway-vpn-vps-restore.service && -f /etc/systemd/system/gateway-vpn-vps-restore.path && -f /etc/systemd/system/gateway-vpn-vps-restore-recovery.service && -f /etc/systemd/system/gateway-vpn-vps-fabric.service && -f /etc/systemd/system/gateway-vpn-vps-fabric.path && -f /etc/systemd/system/gateway-vpn-vps-fabric-recovery.service && -f /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.service && -f /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.timer && -f /etc/systemd/system/gateway-vpn-vps-operations.service && -f /etc/systemd/system/gateway-vpn-vps-operations.timer && -f /etc/systemd/system/gateway-vpn-vps-update.service && -f /etc/systemd/system/gateway-vpn-vps-update.path && -f /etc/systemd/system/gateway-vpn-vps-update-recovery.service && -f /etc/systemd/system/gateway-vpn-vps-update-finalize.service && -f /etc/systemd/system/gateway-vpn-vps-update-finalize.timer && -f /etc/systemd/system/wg-quick@wg-mgmt.service.d/gateway-vpn.conf && -f /etc/systemd/system/gateway-vpn-vps-install-recovery.service && -x /usr/libexec/gateway-vpn-vps-install-recovery && -f /etc/wireguard/wg-mgmt.conf && -f "$AGENT_STATE/vps-agent.db" && -f "$AGENT_STATE/tls/cert.pem" && -f "$AGENT_STATE/tls/key.pem" && -f /var/lib/gateway-vpn-vps/install-report.json ]] || { echo "Partial, stabilizing, or conflicting Gateway VPN VPS installation exists" >&2; exit 1; }
  "$RELEASE_DIR/bin/gateway-vpnctl" vps-release-verify --release-dir "$DEST" --public-key /etc/gateway-vpn-vps/update-signing.pub --release-version "$RELEASE_VERSION" --profile "$PROFILE"
  "$DEST/bin/gateway-vpn-vps-agent" update-lifecycle-check || { echo "Active, damaged, or ambiguous VPS update must be recovered before reinstall" >&2; exit 1; }
  validate_preserved_wg_config /etc/wireguard/wg-mgmt.conf
  "$DEST/bin/gateway-vpn-vps-agent" --check-config /etc/gateway-vpn-vps/config.yaml
  EXISTING=1
elif [[ -e /etc/wireguard/wg-mgmt.conf || -L /etc/wireguard/wg-mgmt.conf ]]; then
  validate_preserved_wg_config /etc/wireguard/wg-mgmt.conf
  PRESERVED_WG_CONFIG=1
  echo "Validated preserved wg-mgmt private key and requested peer configuration for reinstall"
fi

if ((EXISTING == 0)); then
  for conflict in /etc/sysctl.d/90-gateway-vpn-vps.conf /etc/systemd/system/gateway-vpn-vps-firewall.service /etc/systemd/system/gateway-vpn-vps-agent.service /etc/systemd/system/gateway-vpn-vps-restore.service /etc/systemd/system/gateway-vpn-vps-restore.path /etc/systemd/system/gateway-vpn-vps-restore-recovery.service /etc/systemd/system/gateway-vpn-vps-fabric.service /etc/systemd/system/gateway-vpn-vps-fabric.path /etc/systemd/system/gateway-vpn-vps-fabric-recovery.service /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.service /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.timer /etc/systemd/system/gateway-vpn-vps-operations.service /etc/systemd/system/gateway-vpn-vps-operations.timer /etc/systemd/system/gateway-vpn-vps-update.service /etc/systemd/system/gateway-vpn-vps-update.path /etc/systemd/system/gateway-vpn-vps-update-recovery.service /etc/systemd/system/gateway-vpn-vps-update-finalize.service /etc/systemd/system/gateway-vpn-vps-update-finalize.timer /etc/systemd/system/gateway-vpn-vps-install-recovery.service /usr/libexec/gateway-vpn-vps-install-recovery /etc/systemd/system/wg-quick@wg-mgmt.service.d /etc/wireguard/.gateway-vpn-wg-mgmt.conf.tmp /opt/gateway-vpn-vps/.current.new /opt/gateway-vpn-vps/.recovery.new; do
    [[ ! -e "$conflict" && ! -L "$conflict" ]] || { echo "Conflicting VPS managed path exists: $conflict" >&2; exit 1; }
  done
  if systemctl is-active --quiet ufw.service || systemctl is-active --quiet firewalld.service; then
    echo "Detected active host firewall; Gateway VPN will preserve it and manage only table inet gateway_vpn_vps"
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
  if ss -H -ltn 'sport = :9443' | grep -q .; then
    echo "TCP port 9443 is already in use" >&2
    exit 1
  fi
fi

PORTS=8443
((ALLOW_GATEWAY_SSH)) && PORTS="22, 8443"
if ((EXISTING)); then
  grep -Fq "\"public_endpoint\": \"$PUBLIC_ENDPOINT\"" /var/lib/gateway-vpn-vps/install-report.json || { echo "Existing VPS public endpoint differs; explicit reconfiguration is required" >&2; exit 1; }
fi
PREFLIGHT_RULESET=$(mktemp)
sed "s|__GATEWAY_TCP_PORTS__|$PORTS|g" "$ROOT_DIR/packaging/vps/nftables/gateway-vpn-vps.nft.in" >"$PREFLIGHT_RULESET"
nft --check --file "$PREFLIGHT_RULESET"
if ((EXISTING || PRESERVED_WG_CONFIG)); then
  VPS_PRIVATE_KEY=$(awk '/^PrivateKey = / {print $3}' /etc/wireguard/wg-mgmt.conf)
  VPS_PUBLIC_KEY=$(printf '%s' "$VPS_PRIVATE_KEY" | wg pubkey)
  unset VPS_PRIVATE_KEY
fi
if ((PRESERVE_AGENT_USER)); then
  AGENT_CHECK_CONFIG="$RELEASE_DIR/packaging/vps/config/config.yaml"
  ((EXISTING == 0)) || AGENT_CHECK_CONFIG=/etc/gateway-vpn-vps/config.yaml
  "$RELEASE_DIR/bin/gateway-vpn-vps-agent" state-check --config "$AGENT_CHECK_CONFIG" --expected-public-key "$VPS_PUBLIC_KEY"
fi

echo "Validated VPS profile $PROFILE release $RELEASE_VERSION"
echo "Public endpoint: $PUBLIC_ENDPOINT"
echo "WireGuard: wg-mgmt / 10.80.0.1/24 / UDP 51821"
echo "Gateway peer: 10.80.0.2/32; admin peer: 10.80.0.10/32"
echo "Gateway TCP forwarding ports: $PORTS"
echo "VPS Hub WebUI: https://10.80.0.1:9443 through administrator WireGuard, plus localhost:9443"

wait_for_vps_agent_listeners() {
  local attempt
  for ((attempt = 0; attempt < 100; attempt += 1)); do
    if ss -H -ltn 'sport = :9443' | grep -Fq '127.0.0.1:9443' &&
      ss -H -ltn 'sport = :9443' | grep -Fq '10.80.0.1:9443'; then
      return 0
    fi
    if ! systemctl is-active --quiet gateway-vpn-vps-agent.service; then
      echo "VPS Agent stopped before both HTTPS listeners became ready" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "Timed out waiting for VPS Agent HTTPS listeners on 127.0.0.1:9443 and 10.80.0.1:9443" >&2
  return 1
}

if ((EXISTING)); then
  if systemctl is-enabled --quiet gateway-vpn-vps-install-recovery.service; then
    echo "Completed VPS install unexpectedly has first-install recovery enabled" >&2
    exit 1
  fi
  systemctl is-active --quiet gateway-vpn-vps-firewall.service
  systemctl is-active --quiet wg-quick@wg-mgmt.service
  systemctl is-active --quiet gateway-vpn-vps-agent.service
  systemctl is-active --quiet gateway-vpn-vps-restore.path
  systemctl is-active --quiet gateway-vpn-vps-fabric.path
  systemctl is-enabled --quiet gateway-vpn-vps-agent.service
  systemctl is-enabled --quiet gateway-vpn-vps-restore.path
  systemctl is-enabled --quiet gateway-vpn-vps-restore-recovery.service
  systemctl is-enabled --quiet gateway-vpn-vps-fabric-recovery.service
  systemctl is-enabled --quiet gateway-vpn-vps-fabric-watchdog.timer
  systemctl is-enabled --quiet gateway-vpn-vps-operations.timer
  systemctl is-active --quiet gateway-vpn-vps-operations.timer
  systemctl is-enabled --quiet gateway-vpn-vps-update-recovery.service
  systemctl is-enabled --quiet gateway-vpn-vps-update.path
  systemctl is-active --quiet gateway-vpn-vps-update.path
  systemctl is-enabled --quiet gateway-vpn-vps-update-finalize.timer
  systemctl is-active --quiet gateway-vpn-vps-update-finalize.timer
  [[ -f /var/lib/gateway-vpn-vps-privileged/operations/snapshot.json && ! -L /var/lib/gateway-vpn-vps-privileged/operations/snapshot.json && $(stat -c '%U:%G:%a' /var/lib/gateway-vpn-vps-privileged/operations/snapshot.json) == "root:gateway-vpn-vps:640" ]]
  [[ $(wg show wg-mgmt listen-port) == 51821 ]]
  [[ $(wg show wg-mgmt public-key) == "$VPS_PUBLIC_KEY" ]]
  nft list table inet gateway_vpn_vps >/dev/null
  wait_for_vps_agent_listeners
  echo "Gateway VPN VPS $RELEASE_VERSION is already installed with the requested immutable release and peers."
  exit 0
fi
if ((APPLY == 0)); then
  echo "VPS dry-run complete. Re-run with --apply to install."
  exit 0
fi

if ((PRESERVE_AGENT_USER)); then
  [[ -z "$HUB_ADMIN_PASSWORD_FILE" ]] || { echo "A preserved VPS Hub already has an administrator; do not provide a bootstrap password" >&2; exit 1; }
  echo "Validated preserved VPS Hub identity, settings, and administrator state"
elif [[ -n "$HUB_ADMIN_PASSWORD_FILE" ]]; then
  HUB_ADMIN_PASSWORD_FILE=$(realpath -- "$HUB_ADMIN_PASSWORD_FILE")
  [[ -f "$HUB_ADMIN_PASSWORD_FILE" && ! -L "$HUB_ADMIN_PASSWORD_FILE" ]] || { echo "VPS Hub password file must be a regular non-symlink file" >&2; exit 1; }
  PASSWORD_MODE=$(stat -c '%a' "$HUB_ADMIN_PASSWORD_FILE")
  (( (8#$PASSWORD_MODE & 077) == 0 )) || { echo "VPS Hub password file must not be accessible to group or others" >&2; exit 1; }
else
  [[ -t 0 ]] || { echo "Non-interactive VPS install requires --hub-admin-password-file" >&2; exit 1; }
  read -r -s -p "New VPS Hub administrator password (minimum 12 characters): " HUB_ADMIN_PASSWORD
  echo
  read -r -s -p "Repeat VPS Hub administrator password: " HUB_ADMIN_PASSWORD_CONFIRMATION
  echo
  [[ "$HUB_ADMIN_PASSWORD" == "$HUB_ADMIN_PASSWORD_CONFIRMATION" && ${#HUB_ADMIN_PASSWORD} -ge 12 ]] || { unset HUB_ADMIN_PASSWORD HUB_ADMIN_PASSWORD_CONFIRMATION; echo "VPS Hub administrator passwords do not match or are too short" >&2; exit 1; }
  HUB_ADMIN_PASSWORD_TEMP=$(mktemp)
  printf '%s\n' "$HUB_ADMIN_PASSWORD" >"$HUB_ADMIN_PASSWORD_TEMP"
  chmod 0600 "$HUB_ADMIN_PASSWORD_TEMP"
  unset HUB_ADMIN_PASSWORD HUB_ADMIN_PASSWORD_CONFIRMATION
  HUB_ADMIN_PASSWORD_FILE=$HUB_ADMIN_PASSWORD_TEMP
fi
if ((PRESERVE_AGENT_USER == 0)); then
  "$RELEASE_DIR/bin/gateway-vpn-vps-agent" --check-password-file "$HUB_ADMIN_PASSWORD_FILE"
fi

rollback_install() {
  local code=${1:-1}
  trap - ERR INT TERM EXIT
  ((code != 0)) || exit 0
  flock -u 9 || true
  exec 9>&-
  if [[ -x /usr/libexec/gateway-vpn-vps-install-recovery ]]; then
    /usr/libexec/gateway-vpn-vps-install-recovery || true
  fi
  exit "$code"
}

if ((PRESERVE_AGENT_USER == 0)); then
  install -d -o root -g root -m 0700 /var/lib/gateway-vpn-vps
fi
install -d -o root -g root -m 0700 /var/lib/gateway-vpn-vps/install-transactions
OLD_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
OLD_IPV6_ALL=$(cat /proc/sys/net/ipv6/conf/all/forwarding)
OLD_IPV6_DEFAULT=$(cat /proc/sys/net/ipv6/conf/default/forwarding)
install -D -m 0700 "$ROOT_DIR/scripts/recover-vps-install.sh" /usr/libexec/gateway-vpn-vps-install-recovery
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-install-recovery.service" /etc/systemd/system/gateway-vpn-vps-install-recovery.service
systemctl daemon-reload
systemctl enable gateway-vpn-vps-install-recovery.service
MARKER_TMP=/var/lib/gateway-vpn-vps/install-transactions/.active.tmp
printf 'version=%s\nold_ipv4_forward=%s\nold_ipv6_all_forwarding=%s\nold_ipv6_default_forwarding=%s\npreserve_wg_config=%s\npreserve_agent_user=%s\n' "$RELEASE_VERSION" "$OLD_FORWARD" "$OLD_IPV6_ALL" "$OLD_IPV6_DEFAULT" "$PRESERVED_WG_CONFIG" "$PRESERVE_AGENT_USER" >"$MARKER_TMP"
chmod 0600 "$MARKER_TMP"
sync -f "$MARKER_TMP"
mv -T "$MARKER_TMP" /var/lib/gateway-vpn-vps/install-transactions/active
sync
trap 'rollback_install $?' ERR EXIT
trap 'rollback_install 130' INT
trap 'rollback_install 143' TERM

if ((PRESERVE_AGENT_USER == 0)); then
  groupadd --system "$AGENT_USER"
  useradd --system --gid "$AGENT_USER" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$AGENT_USER"
fi
getent passwd "$AGENT_USER" >/dev/null && getent group "$AGENT_USER" >/dev/null || { echo "VPS Agent service account creation failed" >&2; false; }
chown root:"$AGENT_USER" /var/lib/gateway-vpn-vps
chmod 0710 /var/lib/gateway-vpn-vps
chown root:root /var/lib/gateway-vpn-vps/install-transactions
chmod 0700 /var/lib/gateway-vpn-vps/install-transactions
install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0700 "$AGENT_STATE" "$AGENT_STATE/backups" "$AGENT_STATE/secrets" "$AGENT_STATE/secrets/wireguard" "$AGENT_STATE/secrets/update" "$AGENT_STATE/tls"
install -d -o root -g "$AGENT_USER" -m 0710 /var/lib/gateway-vpn-vps-privileged
install -d -o root -g root -m 0700 /var/lib/gateway-vpn-vps-privileged/restore-transactions /var/lib/gateway-vpn-vps-privileged/fabric /var/lib/gateway-vpn-vps-privileged/update-transactions
install -d -o root -g "$AGENT_USER" -m 0750 /var/lib/gateway-vpn-vps-privileged/operations

install -d -m 0755 "$DEST"
while IFS= read -r -d '' source; do
  relative=${source#"$RELEASE_DIR/"}
  mode=0644
  [[ -x "$source" ]] && mode=0755
  install -D -m "$mode" "$source" "$DEST/$relative"
done < <(find "$RELEASE_DIR" -type f -print0 | sort -z)
install -D -m 0644 "$TRUSTED_UPDATE_KEY" /etc/gateway-vpn-vps/update-signing.pub
"$DEST/bin/gateway-vpnctl" vps-release-verify --release-dir "$DEST" --public-key /etc/gateway-vpn-vps/update-signing.pub --release-version "$RELEASE_VERSION" --profile "$PROFILE"

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
if ((PRESERVE_AGENT_USER == 0)); then
  VPS_ID="vps-$(openssl rand -hex 16)"
  (set -o noclobber; printf '%s\n' "$VPS_PRIVATE_KEY" >"$AGENT_STATE/secrets/wireguard/server.key")
  (set -o noclobber; openssl rand -hex 32 >"$AGENT_STATE/secrets/update/identity.key")
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -days 365 -nodes \
    -subj "/CN=Gateway VPN VPS $VPS_ID" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:10.80.0.1" \
    -keyout "$AGENT_STATE/tls/key.pem" -out "$AGENT_STATE/tls/cert.pem" >/dev/null 2>&1
  chown -R "$AGENT_USER":"$AGENT_USER" "$AGENT_STATE"
  find "$AGENT_STATE" -type d -exec chmod 0700 {} +
  find "$AGENT_STATE" -type f -exec chmod 0600 {} +
  sync
fi
unset VPS_PRIVATE_KEY

install -D -m 0644 "$ROOT_DIR/packaging/vps/sysctl.d/90-gateway-vpn-vps.conf" /etc/sysctl.d/90-gateway-vpn-vps.conf
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-firewall.service" /etc/systemd/system/gateway-vpn-vps-firewall.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-agent.service" /etc/systemd/system/gateway-vpn-vps-agent.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-restore.service" /etc/systemd/system/gateway-vpn-vps-restore.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-restore.path" /etc/systemd/system/gateway-vpn-vps-restore.path
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-restore-recovery.service" /etc/systemd/system/gateway-vpn-vps-restore-recovery.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-fabric.service" /etc/systemd/system/gateway-vpn-vps-fabric.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-fabric.path" /etc/systemd/system/gateway-vpn-vps-fabric.path
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-fabric-recovery.service" /etc/systemd/system/gateway-vpn-vps-fabric-recovery.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-fabric-watchdog.service" /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-fabric-watchdog.timer" /etc/systemd/system/gateway-vpn-vps-fabric-watchdog.timer
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-operations.service" /etc/systemd/system/gateway-vpn-vps-operations.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-operations.timer" /etc/systemd/system/gateway-vpn-vps-operations.timer
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-update.service" /etc/systemd/system/gateway-vpn-vps-update.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-update.path" /etc/systemd/system/gateway-vpn-vps-update.path
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-update-recovery.service" /etc/systemd/system/gateway-vpn-vps-update-recovery.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-update-finalize.service" /etc/systemd/system/gateway-vpn-vps-update-finalize.service
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/gateway-vpn-vps-update-finalize.timer" /etc/systemd/system/gateway-vpn-vps-update-finalize.timer
install -D -m 0644 "$ROOT_DIR/packaging/vps/systemd/wg-quick@wg-mgmt.service.d/gateway-vpn.conf" /etc/systemd/system/wg-quick@wg-mgmt.service.d/gateway-vpn.conf
install -d -o root -g "$AGENT_USER" -m 0750 /etc/gateway-vpn-vps
install -o root -g "$AGENT_USER" -m 0640 "$ROOT_DIR/packaging/vps/config/config.yaml" /etc/gateway-vpn-vps/config.yaml
sed "s|__GATEWAY_TCP_PORTS__|$PORTS|g" "$ROOT_DIR/packaging/vps/nftables/gateway-vpn-vps.nft.in" >/etc/gateway-vpn-vps/firewall.nft
chown root:"$AGENT_USER" /etc/gateway-vpn-vps/firewall.nft
chmod 0640 /etc/gateway-vpn-vps/firewall.nft
nft --check --file /etc/gateway-vpn-vps/firewall.nft
"$DEST/bin/gateway-vpn-vps-agent" --check-config /etc/gateway-vpn-vps/config.yaml
sysctl -q -p /etc/sysctl.d/90-gateway-vpn-vps.conf

install -d -m 0755 /opt/gateway-vpn-vps
ln -sfn "releases/v$RELEASE_VERSION" /opt/gateway-vpn-vps/.current.new
ln -sfn "releases/v$RELEASE_VERSION" /opt/gateway-vpn-vps/.recovery.new
mv -Tf /opt/gateway-vpn-vps/.current.new /opt/gateway-vpn-vps/current
mv -Tf /opt/gateway-vpn-vps/.recovery.new /opt/gateway-vpn-vps/recovery
sync
if ((PRESERVE_AGENT_USER == 0)); then
  HOST_LABEL=$(hostname -s)
  HOST_LABEL=${HOST_LABEL:0:96}
  "$DEST/bin/gateway-vpn-vps-agent" identity-init --config /etc/gateway-vpn-vps/config.yaml --vps-id "$VPS_ID" --display-name "VPS $HOST_LABEL" --public-key "$VPS_PUBLIC_KEY" >/dev/null
  "$DEST/bin/gateway-vpn-vps-agent" init-admin --config /etc/gateway-vpn-vps/config.yaml --password-file "$HUB_ADMIN_PASSWORD_FILE"
  chown -R "$AGENT_USER":"$AGENT_USER" "$AGENT_STATE"
  find "$AGENT_STATE" -type d -exec chmod 0700 {} +
  find "$AGENT_STATE" -type f -exec chmod 0600 {} +
  sync
else
  [[ ! -e "$AGENT_STATE/restore.trigger" && ! -L "$AGENT_STATE/restore.trigger" && ! -e "$AGENT_STATE/fabric.trigger" && ! -L "$AGENT_STATE/fabric.trigger" && ! -e "$AGENT_STATE/update.trigger" && ! -L "$AGENT_STATE/update.trigger" ]] || { echo "A pending preserved VPS transaction must finish before reinstall" >&2; false; }
fi
"$DEST/bin/gateway-vpn-vps-agent" legacy-adopt --config /etc/gateway-vpn-vps/config.yaml --gateway-public-key "$GATEWAY_PUBLIC_KEY" --admin-public-key "$ADMIN_PUBLIC_KEY" --endpoint "$PUBLIC_ENDPOINT" >/dev/null
systemctl daemon-reload
(set -o noclobber; : >/run/gateway-vpn-vps-install-authorized) || { echo "Cannot create ephemeral VPS service-start authorization safely" >&2; exit 1; }
chmod 0600 /run/gateway-vpn-vps-install-authorized
[[ -f /run/gateway-vpn-vps-install-authorized && ! -L /run/gateway-vpn-vps-install-authorized && $(stat -c '%u:%g:%a' /run/gateway-vpn-vps-install-authorized) == "0:0:600" ]] || { echo "Ephemeral VPS service-start authorization is unsafe" >&2; exit 1; }
systemctl enable gateway-vpn-vps-firewall.service wg-quick@wg-mgmt.service gateway-vpn-vps-update-recovery.service gateway-vpn-vps-update.path gateway-vpn-vps-update-finalize.timer gateway-vpn-vps-restore-recovery.service gateway-vpn-vps-fabric-recovery.service gateway-vpn-vps-restore.path gateway-vpn-vps-fabric.path gateway-vpn-vps-fabric-watchdog.timer gateway-vpn-vps-operations.timer gateway-vpn-vps-agent.service
systemctl restart gateway-vpn-vps-firewall.service
systemctl restart wg-quick@wg-mgmt.service
systemctl restart gateway-vpn-vps-update-recovery.service
systemctl restart gateway-vpn-vps-restore-recovery.service
systemctl restart gateway-vpn-vps-fabric-recovery.service
"$DEST/bin/gateway-vpn-vps-agent" fabric-apply --config /etc/gateway-vpn-vps/config.yaml --agent-user "$AGENT_USER"
systemctl restart gateway-vpn-vps-restore.path
systemctl restart gateway-vpn-vps-fabric.path
systemctl restart gateway-vpn-vps-fabric-watchdog.timer
systemctl start gateway-vpn-vps-operations.service
systemctl restart gateway-vpn-vps-operations.timer
systemctl restart gateway-vpn-vps-update.path
systemctl restart gateway-vpn-vps-update-finalize.timer
systemctl restart gateway-vpn-vps-agent.service
[[ $(wg show wg-mgmt listen-port) == 51821 ]]
ip -4 -o address show dev wg-mgmt | grep -Fq '10.80.0.1/24'
[[ -f /var/lib/gateway-vpn-vps-privileged/fabric/applied.json && ! -L /var/lib/gateway-vpn-vps-privileged/fabric/applied.json ]]
nft list table inet gateway_vpn_vps >/dev/null
systemctl is-active --quiet gateway-vpn-vps-agent.service
systemctl is-active --quiet gateway-vpn-vps-restore.path
systemctl is-active --quiet gateway-vpn-vps-fabric.path
systemctl is-active --quiet gateway-vpn-vps-operations.timer
systemctl is-active --quiet gateway-vpn-vps-update.path
systemctl is-active --quiet gateway-vpn-vps-update-finalize.timer
[[ -f /var/lib/gateway-vpn-vps-privileged/operations/snapshot.json && ! -L /var/lib/gateway-vpn-vps-privileged/operations/snapshot.json && $(stat -c '%U:%G:%a' /var/lib/gateway-vpn-vps-privileged/operations/snapshot.json) == "root:gateway-vpn-vps:640" ]]
wait_for_vps_agent_listeners

install -d -o root -g "$AGENT_USER" -m 0710 /var/lib/gateway-vpn-vps
printf '{\n  "version": "%s",\n  "profile": "%s",\n  "public_endpoint": "%s",\n  "interface": "wg-mgmt",\n  "vps_address": "10.80.0.1/24",\n  "gateway_address": "10.80.0.2/32",\n  "admin_address": "10.80.0.10/32",\n  "vps_public_key": "%s",\n  "state": "INSTALLED_NOT_READY"\n}\n' "$RELEASE_VERSION" "$PROFILE" "$PUBLIC_ENDPOINT" "$VPS_PUBLIC_KEY" >/var/lib/gateway-vpn-vps/install-report.json
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
echo "Gateway VPN VPS $RELEASE_VERSION installed as INSTALLED_NOT_READY."
echo "VPS WireGuard public key: $VPS_PUBLIC_KEY"
echo "Readiness requires Gateway/admin peer configuration and a verified handshake through the public endpoint."
