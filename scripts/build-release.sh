#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:-}
MIHOMO_VERSION=${2:-}
MIHOMO_BINARY=${3:-}
MIHOMO_SHA256=${4:-}
SIGNING_PRIVATE_KEY=${5:-}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ && "$MIHOMO_VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9._-]+)?$ ]] || { echo "Usage: build-release.sh VERSION MIHOMO_VERSION MIHOMO_BINARY MIHOMO_SHA256 SIGNING_PRIVATE_KEY" >&2; exit 2; }
[[ -f "$MIHOMO_BINARY" && "$MIHOMO_SHA256" =~ ^[0-9a-fA-F]{64}$ && -f "$SIGNING_PRIVATE_KEY" ]] || { echo "Mihomo binary/hash or Ed25519 signing key is invalid" >&2; exit 2; }
ACTUAL_MIHOMO_SHA256=$(sha256sum --binary "$MIHOMO_BINARY" | awk '{print $1}')
[[ ${ACTUAL_MIHOMO_SHA256,,} == ${MIHOMO_SHA256,,} ]] || { echo "Mihomo SHA-256 mismatch" >&2; exit 1; }

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
DEST="$ROOT/dist/gateway-vpn-gateway-$VERSION-linux-amd64"
BOOTSTRAP="$ROOT/dist/gateway-vpn-bootstrap-$VERSION-linux-amd64"
[[ ! -e "$DEST" ]] || { echo "Release destination exists: $DEST" >&2; exit 1; }
[[ ! -e "$BOOTSTRAP" ]] || { echo "Bootstrap destination exists: $BOOTSTRAP" >&2; exit 1; }
COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD) || { echo "Release build requires a committed Git revision" >&2; exit 1; }
[[ "$COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || { echo "Git commit identity is invalid" >&2; exit 1; }
[[ -z $(git -C "$ROOT" status --porcelain --untracked-files=normal) ]] || { echo "Release build requires a clean committed worktree" >&2; exit 1; }
SOURCE_DATE_EPOCH=$(git -C "$ROOT" show -s --format=%ct "$COMMIT")
[[ "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] || { echo "Git commit timestamp is invalid" >&2; exit 1; }
BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
[[ "$BUILD_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || { echo "Canonical build date is invalid" >&2; exit 1; }
mkdir -p "$DEST/bin" "$DEST/libexec" "$DEST/scripts" "$DEST/share/doc" "$DEST/share/supply-chain"
DATABASE_SCHEMA=$(find "$ROOT/migrations" -maxdepth 1 -type f -name '[0-9][0-9][0-9][0-9][0-9][0-9]_*.sql' -printf '%f\n' | sort | tail -n1 | cut -d_ -f1 | sed 's/^0*//')
[[ "$DATABASE_SCHEMA" =~ ^[1-9][0-9]*$ ]] || { echo "Cannot determine embedded database schema" >&2; exit 1; }
LDFLAGS="-s -w -X gateway-vpn/internal/buildinfo.Version=$VERSION -X gateway-vpn/internal/buildinfo.Commit=$COMMIT -X gateway-vpn/internal/buildinfo.Date=$BUILD_DATE -X gateway-vpn/internal/buildinfo.MihomoVersion=$MIHOMO_VERSION"
(
  cd -- "$ROOT"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$DEST/bin/gateway-vpn" ./cmd/gateway-vpn
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$DEST/bin/gateway-vpnctl" ./cmd/gateway-vpnctl
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$BOOTSTRAP" ./cmd/gateway-vpn-bootstrap
)
install -m 0755 "$MIHOMO_BINARY" "$DEST/libexec/mihomo"
install -m 0755 "$ROOT/scripts/install-gateway.sh" "$ROOT/scripts/recover-gateway-install.sh" "$ROOT/scripts/upgrade-gateway-host.sh" "$ROOT/scripts/recover-gateway-host-upgrade.sh" "$ROOT/scripts/run-gateway-uninstall-job.sh" "$ROOT/scripts/uninstall.sh" "$DEST/scripts/"
install -m 0644 "$ROOT/config.example.yaml" "$DEST/config.example.yaml"
while IFS= read -r -d '' source; do
  relative=${source#"$ROOT/"}
  install -D -m 0644 "$source" "$DEST/$relative"
done < <(find "$ROOT/packaging" -type f ! -path "$ROOT/packaging/vps/*" -print0 | sort -z)
install -m 0644 "$ROOT/docs/PLAN_v1.1.md" "$ROOT/docs/OPERATIONS.md" "$ROOT/docs/SECURITY.md" "$ROOT/docs/NETWORKING.md" "$DEST/share/doc/"
HOST_CONTRACT_SHA256=$("$DEST/bin/gateway-vpnctl" release-host-contract --release-dir "$DEST")
[[ "$HOST_CONTRACT_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "Cannot determine signed host lifecycle contract" >&2; exit 1; }
printf '{\n  "format_version": 2,\n  "gateway_version": "%s",\n  "mihomo_version": "%s",\n  "os": "linux",\n  "arch": "amd64",\n  "mihomo_sha256": "%s",\n  "database_schema_minimum": 1,\n  "database_schema_maximum": %s,\n  "config_schema_generation": 1,\n  "host_contract_sha256": "%s",\n  "gateway_api_contract": "gateway-vpn-api-v1",\n  "mihomo_api_contract": "mihomo-local-v1",\n  "build_commit": "%s",\n  "build_date": "%s"\n}\n' "$VERSION" "$MIHOMO_VERSION" "${MIHOMO_SHA256,,}" "$DATABASE_SCHEMA" "$HOST_CONTRACT_SHA256" "$COMMIT" "$BUILD_DATE" >"$DEST/release.json"
GATEWAY_SHA256=$(sha256sum --binary "$DEST/bin/gateway-vpn" | awk '{print $1}')
CONTROL_SHA256=$(sha256sum --binary "$DEST/bin/gateway-vpnctl" | awk '{print $1}')
printf '{\n  "spdxVersion": "SPDX-2.3",\n  "dataLicense": "CC0-1.0",\n  "SPDXID": "SPDXRef-DOCUMENT",\n  "name": "Gateway-VPN-%s-linux-amd64",\n  "documentNamespace": "https://gateway-vpn.invalid/spdx/%s/%s",\n  "creationInfo": {"created": "%s", "creators": ["Tool: gateway-vpn-build-release"]},\n  "packages": [\n    {"name": "Gateway VPN", "SPDXID": "SPDXRef-GatewayVPN", "versionInfo": "%s", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "checksums": [{"algorithm": "SHA256", "checksumValue": "%s"}]},\n    {"name": "Mihomo", "SPDXID": "SPDXRef-Mihomo", "versionInfo": "%s", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "checksums": [{"algorithm": "SHA256", "checksumValue": "%s"}]}\n  ]\n}\n' "$VERSION" "$VERSION" "$COMMIT" "$BUILD_DATE" "$VERSION" "$GATEWAY_SHA256" "$MIHOMO_VERSION" "${MIHOMO_SHA256,,}" >"$DEST/share/supply-chain/sbom.spdx.json"
printf '{\n  "_type": "https://in-toto.io/Statement/v1",\n  "subject": [\n    {"name": "bin/gateway-vpn", "digest": {"sha256": "%s"}},\n    {"name": "bin/gateway-vpnctl", "digest": {"sha256": "%s"}},\n    {"name": "libexec/mihomo", "digest": {"sha256": "%s"}}\n  ],\n  "predicateType": "https://slsa.dev/provenance/v1",\n  "predicate": {"buildDefinition": {"buildType": "https://gateway-vpn.invalid/build/go-linux-amd64/v1", "externalParameters": {"gateway_version": "%s", "mihomo_version": "%s"}, "internalParameters": {"commit": "%s"}, "resolvedDependencies": []}, "runDetails": {"builder": {"id": "gateway-vpn-build-release"}, "metadata": {"invocationId": "%s-%s"}}}\n}\n' "$GATEWAY_SHA256" "$CONTROL_SHA256" "${MIHOMO_SHA256,,}" "$VERSION" "$MIHOMO_VERSION" "$COMMIT" "$VERSION" "$COMMIT" >"$DEST/share/supply-chain/provenance.intoto.json"
(
  cd -- "$DEST"
  find . -type f ! -path './manifest.sha256' ! -path './manifest.json' ! -path './release.sig' -print0 | sort -z | xargs -0 sha256sum --binary >manifest.sha256
)
"$DEST/bin/gateway-vpnctl" release-sign --release-dir "$DEST" --private-key "$SIGNING_PRIVATE_KEY"
ARCHIVE="$ROOT/dist/gateway-vpn-gateway-$VERSION-linux-amd64.tar.gz"
ARCHIVE_ENTRIES=()
while IFS= read -r -d '' entry; do
  ARCHIVE_ENTRIES+=("$entry")
done < <(find "$DEST" -mindepth 1 -maxdepth 1 -printf '%f\0' | sort -z)
((${#ARCHIVE_ENTRIES[@]} > 0)) || { echo "Gateway release tree is empty" >&2; exit 1; }
# Do not archive `.` itself: the production strict extractor intentionally
# rejects a standalone root entry and accepts only actual relative contents.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -C "$DEST" -czf "$ARCHIVE" -- "${ARCHIVE_ENTRIES[@]}"
ARCHIVE_SHA256=$(sha256sum --binary "$ARCHIVE" | awk '{print $1}')
BOOTSTRAP_SHA256=$(sha256sum --binary "$BOOTSTRAP" | awk '{print $1}')
echo "Release prepared at $DEST"
echo "Signed archive prepared at $ARCHIVE"
echo "Gateway archive SHA-256: $ARCHIVE_SHA256"
echo "Bootstrap binary prepared at $BOOTSTRAP"
echo "Bootstrap SHA-256: $BOOTSTRAP_SHA256"
