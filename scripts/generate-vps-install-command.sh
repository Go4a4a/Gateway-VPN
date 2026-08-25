#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:-}
CHANNEL=${2:-}
SIGNING_PUBLIC_KEY=${3:-}
GITHUB_REPOSITORY=${4:-}
RELEASE_TAG=${5:-}
PUBLIC_ENDPOINT=${6:-}
GATEWAY_PUBLIC_KEY=${7:-}
ADMIN_PUBLIC_KEY=${8:-}
[[ -n "$VERSION" && -n "$CHANNEL" && -f "$SIGNING_PUBLIC_KEY" && -n "$GITHUB_REPOSITORY" && -n "$RELEASE_TAG" && -n "$PUBLIC_ENDPOINT" && -n "$GATEWAY_PUBLIC_KEY" && -n "$ADMIN_PUBLIC_KEY" ]] || {
  echo "Usage: generate-vps-install-command.sh VERSION CHANNEL PUBLIC_KEY OWNER/REPO RELEASE_TAG HOST:51821 GATEWAY_PUBLIC_KEY ADMIN_PUBLIC_KEY [--allow-gateway-ssh]" >&2
  exit 2
}
shift 8
ALLOW_GATEWAY_SSH=0
if [[ ${1:-} == --allow-gateway-ssh ]]; then
  ALLOW_GATEWAY_SSH=1
  shift
fi
(($# == 0)) || { echo "Unknown VPS command-generator argument" >&2; exit 2; }

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT/dist"}
CONTROL=${GATEWAY_VPNCTL:-"$OUTPUT_DIR/gateway-vpn-vps-$VERSION-linux-amd64/bin/gateway-vpnctl"}
MANIFEST="$OUTPUT_DIR/channel-$CHANNEL.json"
SIGNATURE="$OUTPUT_DIR/channel-$CHANNEL.sig"
[[ -x "$CONTROL" && -f "$MANIFEST" && -f "$SIGNATURE" && -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || { echo "Verified channel files or VPS controller are unavailable" >&2; exit 1; }
SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ "$SOURCE_COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || { echo "Git commit identity is invalid" >&2; exit 1; }

OUTPUT="$OUTPUT_DIR/install-vps-$VERSION.command.txt"
[[ ! -e "$OUTPUT" ]] || { echo "Generated VPS command already exists: $OUTPUT" >&2; exit 1; }
TEMP=$(mktemp "$OUTPUT_DIR/.install-vps-command.XXXXXX")
trap 'rm -f "$TEMP"' EXIT
ARGS=(
  channel-vps-install-command
  --manifest "$MANIFEST"
  --signature "$SIGNATURE"
  --public-key "$SIGNING_PUBLIC_KEY"
  --channel "$CHANNEL"
  --release-version "$VERSION"
  --source-commit "$SOURCE_COMMIT"
  --github-repository "$GITHUB_REPOSITORY"
  --release-tag "$RELEASE_TAG"
  --public-endpoint "$PUBLIC_ENDPOINT"
  --gateway-public-key "$GATEWAY_PUBLIC_KEY"
  --admin-public-key "$ADMIN_PUBLIC_KEY"
  --install-dependencies
  --apply
)
if ((ALLOW_GATEWAY_SSH)); then
  ARGS+=(--allow-gateway-ssh)
fi
"$CONTROL" "${ARGS[@]}" >"$TEMP"
chmod 0644 "$TEMP"
mv -T "$TEMP" "$OUTPUT"
trap - EXIT
echo "Exact one-command VPS installer written to $OUTPUT"
