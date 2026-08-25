#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:-}
CHANNEL=${2:-}
SIGNING_PUBLIC_KEY=${3:-}
GITHUB_REPOSITORY=${4:-}
RELEASE_TAG=${5:-}
GATEWAY_SSH=${6:-}
VPS_SSH=${7:-}
KNOWN_HOSTS=${8:-}
LAN_INTERFACE=${9:-}
LAN_ADDRESS=${10:-}
PUBLIC_ENDPOINT=${11:-}
ADMIN_PUBLIC_KEY=${12:-}
[[ -n "$VERSION" && -n "$CHANNEL" && -f "$SIGNING_PUBLIC_KEY" && -n "$GITHUB_REPOSITORY" && -n "$RELEASE_TAG" && -n "$GATEWAY_SSH" && -n "$VPS_SSH" && "$KNOWN_HOSTS" == /* && -n "$LAN_INTERFACE" && -n "$LAN_ADDRESS" && -n "$PUBLIC_ENDPOINT" && -n "$ADMIN_PUBLIC_KEY" ]] || {
  echo "Usage: generate-deploy-command.sh VERSION CHANNEL PUBLIC_KEY OWNER/REPO RELEASE_TAG GATEWAY_USER@HOST VPS_USER@HOST /KNOWN_HOSTS LAN_IFACE LAN_CIDR HOST:51821 'ADMIN_PUBLIC_KEY|-' [options]" >&2
  exit 2
}
shift 12
GATEWAY_PORT=22
VPS_PORT=22
GATEWAY_IDENTITY=""
VPS_IDENTITY=""
ADMIN_CONFIG=""
ENABLE_DHCP=0
ALLOW_GATEWAY_SSH=0
while (($#)); do
  case "$1" in
    --gateway-port) GATEWAY_PORT=${2:?}; shift 2 ;;
    --vps-port) VPS_PORT=${2:?}; shift 2 ;;
    --gateway-identity) GATEWAY_IDENTITY=${2:?}; shift 2 ;;
    --vps-identity) VPS_IDENTITY=${2:?}; shift 2 ;;
    --admin-config) ADMIN_CONFIG=${2:?}; shift 2 ;;
    --enable-dhcp) ENABLE_DHCP=1; shift ;;
    --allow-gateway-ssh) ALLOW_GATEWAY_SSH=1; shift ;;
    *) echo "Unknown deploy command-generator argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$GATEWAY_PORT" =~ ^[0-9]+$ && "$VPS_PORT" =~ ^[0-9]+$ ]] || { echo "SSH ports must be decimal integers" >&2; exit 2; }
if [[ "$ADMIN_PUBLIC_KEY" == - ]]; then
  ADMIN_PUBLIC_KEY=""
fi
[[ -n "$ADMIN_PUBLIC_KEY" && -z "$ADMIN_CONFIG" || -z "$ADMIN_PUBLIC_KEY" && "$ADMIN_CONFIG" == /* ]] || { echo "Provide either ADMIN_PUBLIC_KEY or '-' with --admin-config /ABSOLUTE/PATH" >&2; exit 2; }

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT/dist"}
CONTROL=${GATEWAY_VPNCTL:-"$OUTPUT_DIR/gateway-vpn-gateway-$VERSION-linux-amd64/bin/gateway-vpnctl"}
MANIFEST="$OUTPUT_DIR/channel-$CHANNEL.json"
SIGNATURE="$OUTPUT_DIR/channel-$CHANNEL.sig"
[[ -x "$CONTROL" && -f "$MANIFEST" && -f "$SIGNATURE" && -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || { echo "Verified channel files or Gateway controller are unavailable" >&2; exit 1; }
SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ "$SOURCE_COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || { echo "Git commit identity is invalid" >&2; exit 1; }

OUTPUT="$OUTPUT_DIR/deploy-gateway-vps-$VERSION.command.txt"
[[ ! -e "$OUTPUT" ]] || { echo "Generated deploy command already exists: $OUTPUT" >&2; exit 1; }
TEMP=$(mktemp "$OUTPUT_DIR/.deploy-command.XXXXXX")
trap 'rm -f "$TEMP"' EXIT
ARGS=(
  channel-deploy-command
  --manifest "$MANIFEST"
  --signature "$SIGNATURE"
  --public-key "$SIGNING_PUBLIC_KEY"
  --channel "$CHANNEL"
  --release-version "$VERSION"
  --source-commit "$SOURCE_COMMIT"
  --github-repository "$GITHUB_REPOSITORY"
  --release-tag "$RELEASE_TAG"
  --gateway-ssh "$GATEWAY_SSH"
  --gateway-port "$GATEWAY_PORT"
  --vps-ssh "$VPS_SSH"
  --vps-port "$VPS_PORT"
  --known-hosts "$KNOWN_HOSTS"
  --lan-interface "$LAN_INTERFACE"
  --lan-address "$LAN_ADDRESS"
  --public-endpoint "$PUBLIC_ENDPOINT"
)
[[ -z "$ADMIN_PUBLIC_KEY" ]] || ARGS+=(--admin-public-key "$ADMIN_PUBLIC_KEY")
[[ -z "$ADMIN_CONFIG" ]] || ARGS+=(--admin-config "$ADMIN_CONFIG")
[[ -z "$GATEWAY_IDENTITY" ]] || ARGS+=(--gateway-identity "$GATEWAY_IDENTITY")
[[ -z "$VPS_IDENTITY" ]] || ARGS+=(--vps-identity "$VPS_IDENTITY")
((ENABLE_DHCP == 0)) || ARGS+=(--enable-dhcp)
((ALLOW_GATEWAY_SSH == 0)) || ARGS+=(--allow-gateway-ssh)
"$CONTROL" "${ARGS[@]}" >"$TEMP"
chmod 0644 "$TEMP"
mv -T "$TEMP" "$OUTPUT"
trap - EXIT
echo "Exact one-command Gateway+VPS deploy written to $OUTPUT"
