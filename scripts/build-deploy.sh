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
DEST="$OUTPUT_DIR/gateway-vpn-deploy-$VERSION-linux-amd64"
SBOM="$OUTPUT_DIR/gateway-vpn-deploy-$VERSION-linux-amd64.spdx.json"
PROVENANCE="$OUTPUT_DIR/gateway-vpn-deploy-$VERSION-linux-amd64.intoto.json"
[[ -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" && ! -e "$DEST" && ! -e "$SBOM" && ! -e "$PROVENANCE" ]] || {
  echo "Deploy output directory is unsafe or an artifact already exists" >&2
  exit 1
}
COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD) || { echo "Deploy build requires a committed Git revision" >&2; exit 1; }
[[ "$COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || { echo "Git commit identity is invalid" >&2; exit 1; }
[[ -z $(git -C "$ROOT" status --porcelain --untracked-files=normal) ]] || { echo "Deploy build requires a clean committed worktree" >&2; exit 1; }

BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-s -w -X gateway-vpn/internal/buildinfo.Version=$VERSION -X gateway-vpn/internal/buildinfo.Commit=$COMMIT -X gateway-vpn/internal/buildinfo.Date=$BUILD_DATE"
(
  cd -- "$ROOT"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$DEST" ./cmd/gateway-vpn-deploy
)
chmod 0755 "$DEST"
DEPLOY_SHA256=$(sha256sum --binary "$DEST" | awk '{print $1}')
printf '{\n  "spdxVersion": "SPDX-2.3",\n  "dataLicense": "CC0-1.0",\n  "SPDXID": "SPDXRef-DOCUMENT",\n  "name": "Gateway-VPN-Deploy-%s-linux-amd64",\n  "documentNamespace": "https://gateway-vpn.invalid/spdx/deploy/%s/%s",\n  "creationInfo": {"created": "%s", "creators": ["Tool: gateway-vpn-build-deploy"]},\n  "packages": [{"name": "Gateway VPN deploy launcher", "SPDXID": "SPDXRef-GatewayVPNDeploy", "versionInfo": "%s", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "checksums": [{"algorithm": "SHA256", "checksumValue": "%s"}]}]\n}\n' "$VERSION" "$VERSION" "$COMMIT" "$BUILD_DATE" "$VERSION" "$DEPLOY_SHA256" >"$SBOM"
printf '{\n  "_type": "https://in-toto.io/Statement/v1",\n  "subject": [{"name": "gateway-vpn-deploy-%s-linux-amd64", "digest": {"sha256": "%s"}}],\n  "predicateType": "https://slsa.dev/provenance/v1",\n  "predicate": {"buildDefinition": {"buildType": "https://gateway-vpn.invalid/build/deploy-go-linux-amd64/v1", "externalParameters": {"version": "%s"}, "internalParameters": {"commit": "%s"}, "resolvedDependencies": []}, "runDetails": {"builder": {"id": "gateway-vpn-build-deploy"}, "metadata": {"invocationId": "%s-%s"}}}\n}\n' "$VERSION" "$DEPLOY_SHA256" "$VERSION" "$COMMIT" "$VERSION" "$COMMIT" >"$PROVENANCE"
chmod 0644 "$SBOM" "$PROVENANCE"
echo "Deploy launcher prepared at $DEST"
echo "Deploy SHA-256: $DEPLOY_SHA256"
