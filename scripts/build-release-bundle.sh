#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:-}
CHANNEL=${2:-}
MIHOMO_VERSION=${3:-}
MIHOMO_BINARY=${4:-}
SIGNING_PRIVATE_KEY=${5:-}
SIGNING_PUBLIC_KEY=${6:-}
GITHUB_REPOSITORY=${7:-}
RELEASE_TAG=${8:-}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ &&
  "$CHANNEL" =~ ^[a-z][a-z0-9-]{0,31}$ &&
  "$MIHOMO_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ &&
  "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ &&
  "$RELEASE_TAG" == "v$VERSION" ]] || {
  echo "Usage: build-release-bundle.sh VERSION CHANNEL MIHOMO_VERSION MIHOMO_BINARY PRIVATE_KEY PUBLIC_KEY OWNER/REPO vVERSION" >&2
  exit 2
}
shift 8
(($# == 0)) || { echo "Unexpected release bundle argument" >&2; exit 2; }

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ -f "$MIHOMO_BINARY" && ! -L "$MIHOMO_BINARY" && -f "$SIGNING_PRIVATE_KEY" && ! -L "$SIGNING_PRIVATE_KEY" && -f "$SIGNING_PUBLIC_KEY" && ! -L "$SIGNING_PUBLIC_KEY" ]] || {
  echo "Release bundle inputs must be regular non-symlink files" >&2
  exit 1
}
PRIVATE_MODE=$(stat -c %a "$SIGNING_PRIVATE_KEY")
[[ "$PRIVATE_MODE" =~ ^[0-7]{3,4}$ ]] && (( (8#$PRIVATE_MODE & 077) == 0 )) || {
  echo "Release signing private key must not be accessible to group or others" >&2
  exit 1
}
[[ ! -e "$ROOT/dist" ]] || { echo "Release bundle requires an absent dist directory" >&2; exit 1; }
COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ "$COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ && -z $(git -C "$ROOT" status --porcelain --untracked-files=normal) ]] || {
  echo "Release bundle requires a clean committed worktree" >&2
  exit 1
}

# Reject a mismatched, relocated, permission-weakened, symlinked or otherwise
# unsafe signing identity before the expensive release build starts.
(
  cd -- "$ROOT"
  go run ./cmd/gateway-vpnctl release-key-verify \
    --private-key "$SIGNING_PRIVATE_KEY" --public-key "$SIGNING_PUBLIC_KEY"
)

MIHOMO_SHA256=$(sha256sum --binary "$MIHOMO_BINARY" | awk '{print $1}')
"$ROOT/scripts/build-release.sh" "$VERSION" "$MIHOMO_VERSION" "$MIHOMO_BINARY" "$MIHOMO_SHA256" "$SIGNING_PRIVATE_KEY"
"$ROOT/scripts/build-vps-release.sh" "$VERSION" "$SIGNING_PRIVATE_KEY"
"$ROOT/scripts/build-deploy.sh" "$VERSION"

CHANNEL_ARGS=(
  "$VERSION" "$CHANNEL" "$SIGNING_PRIVATE_KEY" "$SIGNING_PUBLIC_KEY"
  "$GITHUB_REPOSITORY" "$RELEASE_TAG"
)
CHANNEL_ARGS+=(
  "bootstrap=$ROOT/dist/gateway-vpn-bootstrap-$VERSION-linux-amd64"
  "deploy=$ROOT/dist/gateway-vpn-deploy-$VERSION-linux-amd64"
  "deploy-windows=$ROOT/dist/gateway-vpn-deploy-$VERSION-windows-amd64.exe"
  "gateway=$ROOT/dist/gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz"
  "vps=$ROOT/dist/gateway-vpn-vps-$VERSION-linux-amd64.tar.gz"
)
"$ROOT/scripts/build-channel.sh" "${CHANNEL_ARGS[@]}"

CONTROL="$ROOT/dist/gateway-vpn-gateway-$VERSION-linux-amd64/bin/gateway-vpnctl"
"$CONTROL" release-verify \
  --release-dir "$ROOT/dist/gateway-vpn-gateway-$VERSION-linux-amd64" \
  --public-key "$ROOT/dist/update-signing.pub" --initial-install
"$CONTROL" vps-release-verify \
  --release-dir "$ROOT/dist/gateway-vpn-vps-$VERSION-linux-amd64" \
  --public-key "$ROOT/dist/update-signing.pub" --release-version "$VERSION"
"$CONTROL" channel-verify \
  --manifest "$ROOT/dist/channel-$CHANNEL.json" \
  --signature "$ROOT/dist/channel-$CHANNEL.sig" \
  --public-key "$ROOT/dist/update-signing.pub" \
  --channel "$CHANNEL" --release-version "$VERSION" --source-commit "$COMMIT" \
  --artifact "bootstrap=$ROOT/dist/gateway-vpn-bootstrap-$VERSION-linux-amd64" \
  --artifact "deploy=$ROOT/dist/gateway-vpn-deploy-$VERSION-linux-amd64" \
  --artifact "deploy-windows=$ROOT/dist/gateway-vpn-deploy-$VERSION-windows-amd64.exe" \
  --artifact "gateway=$ROOT/dist/gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz" \
  --artifact "vps=$ROOT/dist/gateway-vpn-vps-$VERSION-linux-amd64.tar.gz"

echo "Gateway VPN signed release bundle $VERSION prepared and re-verified from commit $COMMIT"
