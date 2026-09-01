#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:-}
CHANNEL=${2:-}
SIGNING_PRIVATE_KEY=${3:-}
SIGNING_PUBLIC_KEY=${4:-}
URGENCY=${5:-}
SUMMARY=${6:-}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ &&
  "$CHANNEL" =~ ^(stable|testing)$ && "$URGENCY" =~ ^(routine|recommended|security)$ &&
  -n "$SUMMARY" && ${#SUMMARY} -le 512 ]] || {
  echo "Usage: build-mihomo-channel.sh VERSION CHANNEL PRIVATE_KEY PUBLIC_KEY URGENCY SUMMARY COMPATIBLE_GATEWAY_VERSION [...]" >&2
  exit 2
}
shift 6
(($# > 0 && $# <= 32)) || { echo "At least one and at most 32 exact compatible Gateway versions are required" >&2; exit 2; }

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT/dist"}
CONTROL=${GATEWAY_VPNCTL:-"$OUTPUT_DIR/gateway-vpn-gateway-$VERSION-linux-amd64/bin/gateway-vpnctl"}
RELEASE_DIR="$OUTPUT_DIR/gateway-vpn-gateway-$VERSION-linux-amd64"
ARTIFACT="$OUTPUT_DIR/gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz"
[[ -x "$CONTROL" && -d "$RELEASE_DIR" && ! -L "$RELEASE_DIR" && -f "$ARTIFACT" && ! -L "$ARTIFACT" &&
  -f "$SIGNING_PRIVATE_KEY" && ! -L "$SIGNING_PRIVATE_KEY" && -f "$SIGNING_PUBLIC_KEY" && ! -L "$SIGNING_PUBLIC_KEY" ]] || {
  echo "Verified release, archive, signing identity, or control binary is unavailable" >&2
  exit 1
}
SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
SOURCE_DATE_EPOCH=$(git -C "$ROOT" show -s --format=%ct "$SOURCE_COMMIT")
[[ "$SOURCE_COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ && "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ && -z $(git -C "$ROOT" status --porcelain --untracked-files=normal) ]] || {
  echo "Mihomo channel build requires a clean committed worktree" >&2
  exit 1
}
GENERATED_AT=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)

COMPATIBILITY_ARGS=()
for compatible in "$@"; do
  [[ "$compatible" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || {
    echo "Invalid compatible Gateway version: $compatible" >&2
    exit 2
  }
  COMPATIBILITY_ARGS+=(--compatible-gateway-version "$compatible")
done

"$CONTROL" mihomo-channel-sign \
  --channel "$CHANNEL" --release-dir "$RELEASE_DIR" --artifact "$ARTIFACT" \
  --source-commit "$SOURCE_COMMIT" --generated-at "$GENERATED_AT" \
  --urgency "$URGENCY" --summary "$SUMMARY" "${COMPATIBILITY_ARGS[@]}" \
  --private-key "$SIGNING_PRIVATE_KEY" --output-dir "$OUTPUT_DIR"

"$CONTROL" mihomo-channel-verify \
  --manifest "$OUTPUT_DIR/mihomo-channel-$CHANNEL.json" \
  --signature "$OUTPUT_DIR/mihomo-channel-$CHANNEL.sig" \
  --public-key "$SIGNING_PUBLIC_KEY" --release-dir "$RELEASE_DIR" --artifact "$ARTIFACT" \
  --channel "$CHANNEL" --release-version "$VERSION" --source-commit "$SOURCE_COMMIT"

echo "Signed Mihomo maintenance channel prepared for Gateway release $VERSION"
