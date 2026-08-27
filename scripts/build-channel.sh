#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:-}
CHANNEL=${2:-}
SIGNING_PRIVATE_KEY=${3:-}
SIGNING_PUBLIC_KEY=${4:-}
GITHUB_REPOSITORY=${5:-}
RELEASE_TAG=${6:-}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ && "$CHANNEL" =~ ^[a-z][a-z0-9-]{0,31}$ && "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "$RELEASE_TAG" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$ ]] || {
  echo "Usage: build-channel.sh VERSION CHANNEL PRIVATE_KEY PUBLIC_KEY OWNER/REPO RELEASE_TAG ROLE=ARTIFACT [...]" >&2
  exit 2
}
shift 6
(($# >= 2)) || { echo "At least Gateway and bootstrap ROLE=ARTIFACT inputs are required" >&2; exit 2; }

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT/dist"}
CONTROL=${GATEWAY_VPNCTL:-"$OUTPUT_DIR/gateway-vpn-gateway-$VERSION-linux-amd64/bin/gateway-vpnctl"}
[[ -x "$CONTROL" && -f "$SIGNING_PRIVATE_KEY" && -f "$SIGNING_PUBLIC_KEY" && -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || {
  echo "Trusted channel builder inputs or output directory are unavailable" >&2
  exit 1
}
SOURCE_COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD)
[[ "$SOURCE_COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || { echo "Git commit identity is invalid" >&2; exit 1; }
[[ -z $(git -C "$ROOT" status --porcelain --untracked-files=normal) ]] || { echo "Channel build requires a clean committed worktree" >&2; exit 1; }
SOURCE_DATE_EPOCH=$(git -C "$ROOT" show -s --format=%ct "$SOURCE_COMMIT")
[[ "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] || { echo "Git commit timestamp is invalid" >&2; exit 1; }
GENERATED_AT=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
[[ "$GENERATED_AT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || { echo "Canonical channel date is invalid" >&2; exit 1; }

SIGN_ARGS=(
  channel-sign
  --channel "$CHANNEL"
  --release-version "$VERSION"
  --source-commit "$SOURCE_COMMIT"
  --generated-at "$GENERATED_AT"
  --private-key "$SIGNING_PRIVATE_KEY"
  --output-dir "$OUTPUT_DIR"
)
for artifact in "$@"; do
  [[ "$artifact" == *=* ]] || { echo "Artifact must use ROLE=FILE: $artifact" >&2; exit 2; }
  SIGN_ARGS+=(--artifact "$artifact")
done
"$CONTROL" "${SIGN_ARGS[@]}"

MANIFEST="$OUTPUT_DIR/channel-$CHANNEL.json"
SIGNATURE="$OUTPUT_DIR/channel-$CHANNEL.sig"
PUBLISHED_KEY="$OUTPUT_DIR/update-signing.pub"
[[ ! -e "$PUBLISHED_KEY" ]] || { echo "Published update key already exists: $PUBLISHED_KEY" >&2; exit 1; }
install -m 0644 "$SIGNING_PUBLIC_KEY" "$PUBLISHED_KEY"
VERIFY_ARGS=(
  channel-verify
  --manifest "$MANIFEST"
  --signature "$SIGNATURE"
  --public-key "$PUBLISHED_KEY"
  --channel "$CHANNEL"
  --release-version "$VERSION"
  --source-commit "$SOURCE_COMMIT"
)
for artifact in "$@"; do
  VERIFY_ARGS+=(--artifact "$artifact")
done
"$CONTROL" "${VERIFY_ARGS[@]}"

COMMAND_FILE="$OUTPUT_DIR/install-gateway-$VERSION.command.txt"
[[ ! -e "$COMMAND_FILE" ]] || { echo "Generated install command already exists: $COMMAND_FILE" >&2; exit 1; }
TEMP_COMMAND=$(mktemp "$OUTPUT_DIR/.install-gateway-command.XXXXXX")
trap 'rm -f "$TEMP_COMMAND"' EXIT
COMMAND_ARGS=(
  channel-install-command
  --manifest "$MANIFEST"
  --signature "$SIGNATURE"
  --public-key "$PUBLISHED_KEY"
  --channel "$CHANNEL"
  --release-version "$VERSION"
  --source-commit "$SOURCE_COMMIT"
  --github-repository "$GITHUB_REPOSITORY"
  --release-tag "$RELEASE_TAG"
  --interactive
)
"$CONTROL" "${COMMAND_ARGS[@]}" >"$TEMP_COMMAND"
chmod 0644 "$TEMP_COMMAND"
mv -T "$TEMP_COMMAND" "$COMMAND_FILE"
trap - EXIT
echo "Exact one-command Gateway installer written to $COMMAND_FILE"
