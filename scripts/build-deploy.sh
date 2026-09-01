#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:-}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || {
  echo "Usage: build-deploy.sh VERSION" >&2
  exit 2
}

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT/dist"}
LINUX_DEST="$OUTPUT_DIR/gateway-vpn-deploy-$VERSION-linux-amd64"
WINDOWS_DEST="$OUTPUT_DIR/gateway-vpn-deploy-$VERSION-windows-amd64.exe"
OUTPUTS=(
  "$LINUX_DEST"
  "$OUTPUT_DIR/gateway-vpn-deploy-$VERSION-linux-amd64.spdx.json"
  "$OUTPUT_DIR/gateway-vpn-deploy-$VERSION-linux-amd64.intoto.json"
  "$WINDOWS_DEST"
  "$OUTPUT_DIR/gateway-vpn-deploy-$VERSION-windows-amd64.spdx.json"
  "$OUTPUT_DIR/gateway-vpn-deploy-$VERSION-windows-amd64.intoto.json"
)
[[ -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || {
  echo "Deploy output directory is unsafe or an artifact already exists" >&2
  exit 1
}
for output in "${OUTPUTS[@]}"; do
  [[ ! -e "$output" ]] || { echo "Deploy artifact already exists: $output" >&2; exit 1; }
done
COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD) || { echo "Deploy build requires a committed Git revision" >&2; exit 1; }
[[ "$COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || { echo "Git commit identity is invalid" >&2; exit 1; }
[[ -z $(git -C "$ROOT" status --porcelain --untracked-files=normal) ]] || { echo "Deploy build requires a clean committed worktree" >&2; exit 1; }

SOURCE_DATE_EPOCH=$(git -C "$ROOT" show -s --format=%ct "$COMMIT")
[[ "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] || { echo "Git commit timestamp is invalid" >&2; exit 1; }
BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
[[ "$BUILD_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || { echo "Canonical build date is invalid" >&2; exit 1; }
LDFLAGS="-s -w -X gateway-vpn/internal/buildinfo.Version=$VERSION -X gateway-vpn/internal/buildinfo.Commit=$COMMIT -X gateway-vpn/internal/buildinfo.Date=$BUILD_DATE"
(
  cd -- "$ROOT"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$LINUX_DEST" ./cmd/gateway-vpn-deploy
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$WINDOWS_DEST" ./cmd/gateway-vpn-deploy
)
chmod 0755 "$LINUX_DEST" "$WINDOWS_DEST"

write_metadata() {
  local os_name=$1
  local artifact=$2
  local artifact_name=${artifact##*/}
  local stem="gateway-vpn-deploy-$VERSION-$os_name-amd64"
  local sbom="$OUTPUT_DIR/$stem.spdx.json"
  local provenance="$OUTPUT_DIR/$stem.intoto.json"
  local digest
  digest=$(sha256sum --binary "$artifact" | awk '{print $1}')
  printf '{\n  "spdxVersion": "SPDX-2.3",\n  "dataLicense": "CC0-1.0",\n  "SPDXID": "SPDXRef-DOCUMENT",\n  "name": "Gateway-VPN-Deploy-%s-%s-amd64",\n  "documentNamespace": "https://gateway-vpn.invalid/spdx/deploy/%s/%s/%s",\n  "creationInfo": {"created": "%s", "creators": ["Tool: gateway-vpn-build-deploy"]},\n  "packages": [{"name": "Gateway VPN deploy launcher", "SPDXID": "SPDXRef-GatewayVPNDeploy", "versionInfo": "%s", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "checksums": [{"algorithm": "SHA256", "checksumValue": "%s"}]}]\n}\n' "$VERSION" "$os_name" "$VERSION" "$os_name" "$COMMIT" "$BUILD_DATE" "$VERSION" "$digest" >"$sbom"
  printf '{\n  "_type": "https://in-toto.io/Statement/v1",\n  "subject": [{"name": "%s", "digest": {"sha256": "%s"}}],\n  "predicateType": "https://slsa.dev/provenance/v1",\n  "predicate": {"buildDefinition": {"buildType": "https://gateway-vpn.invalid/build/deploy-go-%s-amd64/v1", "externalParameters": {"version": "%s"}, "internalParameters": {"commit": "%s"}, "resolvedDependencies": []}, "runDetails": {"builder": {"id": "gateway-vpn-build-deploy"}, "metadata": {"invocationId": "%s-%s-%s"}}}\n}\n' "$artifact_name" "$digest" "$os_name" "$VERSION" "$COMMIT" "$VERSION" "$os_name" "$COMMIT" >"$provenance"
  chmod 0644 "$sbom" "$provenance"
  echo "Deploy launcher prepared at $artifact"
  echo "Deploy $os_name/amd64 SHA-256: $digest"
}

write_metadata linux "$LINUX_DEST"
write_metadata windows "$WINDOWS_DEST"
