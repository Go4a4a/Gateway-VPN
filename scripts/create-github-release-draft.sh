#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:-}
CHANNEL=${2:-}
GITHUB_REPOSITORY=${3:-}
RELEASE_TAG=${4:-}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ &&
  "$CHANNEL" =~ ^[a-z][a-z0-9-]{0,31}$ &&
  "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ &&
  "$RELEASE_TAG" == "v$VERSION" ]] || {
  echo "Usage: create-github-release-draft.sh VERSION CHANNEL OWNER/REPO vVERSION" >&2
  exit 2
}

for command in git gh go; do
  command -v "$command" >/dev/null || { echo "Missing publisher command: $command" >&2; exit 1; }
done
[[ -n ${GH_TOKEN:-} ]] || { echo "GH_TOKEN is required for non-interactive draft creation" >&2; exit 1; }

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
TAG_COMMIT=$(git -C "$ROOT" rev-parse --verify "$RELEASE_TAG^{commit}") || {
  echo "Exact local release tag is missing" >&2
  exit 1
}
[[ "$COMMIT" == "$TAG_COMMIT" && -z $(git -C "$ROOT" status --porcelain --untracked-files=normal) ]] || {
  echo "Draft creation requires clean HEAD at the exact release tag" >&2
  exit 1
}

ASSETS=(
  "$ROOT/dist/gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz"
  "$ROOT/dist/gateway-vpn-vps-$VERSION-linux-amd64.tar.gz"
  "$ROOT/dist/gateway-vpn-bootstrap-$VERSION-linux-amd64"
  "$ROOT/dist/gateway-vpn-deploy-$VERSION-linux-amd64"
  "$ROOT/dist/gateway-vpn-deploy-$VERSION-linux-amd64.spdx.json"
  "$ROOT/dist/gateway-vpn-deploy-$VERSION-linux-amd64.intoto.json"
  "$ROOT/dist/gateway-vpn-deploy-$VERSION-windows-amd64.exe"
  "$ROOT/dist/gateway-vpn-deploy-$VERSION-windows-amd64.spdx.json"
  "$ROOT/dist/gateway-vpn-deploy-$VERSION-windows-amd64.intoto.json"
  "$ROOT/dist/channel-$CHANNEL.json"
  "$ROOT/dist/channel-$CHANNEL.sig"
  "$ROOT/dist/update-signing.pub"
  "$ROOT/dist/install-gateway-$VERSION.command.txt"
  "$ROOT/dist/install-deploy-windows-$VERSION.command.txt"
)
for asset in "${ASSETS[@]}"; do
  [[ -f "$asset" && ! -L "$asset" ]] || { echo "Required exact release asset is missing or unsafe: $asset" >&2; exit 1; }
done

# Rebuild the verifier from the clean tagged source immediately before the
# external write. This avoids trusting a verifier binary from the candidate
# tree and detects any post-build modification of the signed role artifacts.
(
  cd -- "$ROOT"
  go run ./cmd/gateway-vpnctl release-verify \
    --release-dir "$ROOT/dist/gateway-vpn-gateway-$VERSION-linux-amd64" \
    --public-key "$ROOT/dist/update-signing.pub" --initial-install
  go run ./cmd/gateway-vpnctl vps-release-verify \
    --release-dir "$ROOT/dist/gateway-vpn-vps-$VERSION-linux-amd64" \
    --public-key "$ROOT/dist/update-signing.pub" --release-version "$VERSION"
  go run ./cmd/gateway-vpnctl channel-verify \
    --manifest "$ROOT/dist/channel-$CHANNEL.json" \
    --signature "$ROOT/dist/channel-$CHANNEL.sig" \
    --public-key "$ROOT/dist/update-signing.pub" \
    --channel "$CHANNEL" --release-version "$VERSION" --source-commit "$COMMIT" \
    --artifact "bootstrap=$ROOT/dist/gateway-vpn-bootstrap-$VERSION-linux-amd64" \
    --artifact "deploy=$ROOT/dist/gateway-vpn-deploy-$VERSION-linux-amd64" \
    --artifact "deploy-windows=$ROOT/dist/gateway-vpn-deploy-$VERSION-windows-amd64.exe" \
    --artifact "gateway=$ROOT/dist/gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz" \
    --artifact "vps=$ROOT/dist/gateway-vpn-vps-$VERSION-linux-amd64.tar.gz"
)

REMOTE_COMMIT=$(gh api "repos/$GITHUB_REPOSITORY/commits/$RELEASE_TAG" --jq .sha)
[[ "$REMOTE_COMMIT" == "$COMMIT" ]] || { echo "Remote release tag does not resolve to local HEAD" >&2; exit 1; }
if gh release view "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  echo "GitHub release or draft already exists for $RELEASE_TAG" >&2
  exit 1
fi

gh release create "$RELEASE_TAG" "${ASSETS[@]}" \
  --repo "$GITHUB_REPOSITORY" --verify-tag --draft \
  --title "Gateway VPN $VERSION" \
  --notes "Signed Gateway/VPS/bootstrap/deploy test candidate from exact commit $COMMIT. Review all assets and enable GitHub release immutability before publishing this draft."

gh release view "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --json url,isDraft,tagName
echo "Draft created only; publish it manually after verifying release immutability is enabled"
