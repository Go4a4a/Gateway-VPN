#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

MIHOMO_VERSION=${1:-}
ARCHIVE_SHA256=${2:-}
OUTPUT=${3:-}
[[ "$MIHOMO_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && "$ARCHIVE_SHA256" =~ ^[0-9a-fA-F]{64}$ && "$OUTPUT" == /* && "$OUTPUT" != *$'\n'* ]] || {
  echo "Usage: fetch-mihomo-release.sh vX.Y.Z ARCHIVE_SHA256 /absolute/output/mihomo" >&2
  exit 2
}

for command in curl gzip sha256sum stat timeout dirname mktemp mv chmod rm awk; do
  command -v "$command" >/dev/null || { echo "Missing trusted-builder command: $command" >&2; exit 1; }
done

OUTPUT_DIRECTORY=$(dirname -- "$OUTPUT")
[[ -d "$OUTPUT_DIRECTORY" && ! -L "$OUTPUT_DIRECTORY" && ! -e "$OUTPUT" ]] || {
  echo "Mihomo output directory is unsafe or output already exists" >&2
  exit 1
}

ASSET="mihomo-linux-amd64-v1-$MIHOMO_VERSION.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/$MIHOMO_VERSION/$ASSET"
ARCHIVE=$(mktemp "$OUTPUT_DIRECTORY/.mihomo-archive.XXXXXX")
TEMP_OUTPUT=$(mktemp "$OUTPUT_DIRECTORY/.mihomo-binary.XXXXXX")
cleanup() {
  rm -f -- "$ARCHIVE" "$TEMP_OUTPUT"
}
trap cleanup EXIT INT TERM

curl --fail --location --max-redirs 5 \
  --proto '=https' --proto-redir '=https' \
  --connect-timeout 15 --max-time 300 \
  --retry 3 --retry-all-errors --max-filesize 67108864 \
  --output "$ARCHIVE" "$URL"

ARCHIVE_SIZE=$(stat -c %s "$ARCHIVE")
[[ "$ARCHIVE_SIZE" =~ ^[0-9]+$ ]] && ((ARCHIVE_SIZE > 0 && ARCHIVE_SIZE <= 67108864)) || {
  echo "Downloaded Mihomo archive size is invalid" >&2
  exit 1
}
ACTUAL_ARCHIVE_SHA256=$(sha256sum --binary "$ARCHIVE" | awk '{print $1}')
[[ ${ACTUAL_ARCHIVE_SHA256,,} == ${ARCHIVE_SHA256,,} ]] || {
  echo "Downloaded Mihomo archive SHA-256 mismatch" >&2
  exit 1
}

# ulimit -f caps a hostile/corrupt decompression before it can consume the
# builder disk. The official compatible amd64 binary is far below 128 MiB.
if ! (ulimit -f 262144; gzip -dc -- "$ARCHIVE" >"$TEMP_OUTPUT"); then
  echo "Mihomo archive decompression failed or exceeded 128 MiB" >&2
  exit 1
fi
BINARY_SIZE=$(stat -c %s "$TEMP_OUTPUT")
[[ "$BINARY_SIZE" =~ ^[0-9]+$ ]] && ((BINARY_SIZE > 0 && BINARY_SIZE <= 134217728)) || {
  echo "Decompressed Mihomo binary size is invalid" >&2
  exit 1
}
chmod 0755 "$TEMP_OUTPUT"
VERSION_OUTPUT=$(timeout 10s "$TEMP_OUTPUT" -v 2>&1) || {
  echo "Pinned Mihomo binary version probe failed" >&2
  exit 1
}
[[ "$VERSION_OUTPUT" == *"$MIHOMO_VERSION"* ]] || {
  echo "Pinned Mihomo binary does not report the requested version" >&2
  exit 1
}

BINARY_SHA256=$(sha256sum --binary "$TEMP_OUTPUT" | awk '{print $1}')
mv -T "$TEMP_OUTPUT" "$OUTPUT"
rm -f -- "$ARCHIVE"
trap - EXIT INT TERM
echo "Pinned Mihomo $MIHOMO_VERSION prepared; binary SHA-256=$BINARY_SHA256"
