#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

VERSION=${1:-}
SIGNING_PRIVATE_KEY=${2:-}
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ && -f "$SIGNING_PRIVATE_KEY" ]] || {
  echo "Usage: build-vps-release.sh VERSION SIGNING_PRIVATE_KEY" >&2
  exit 2
}

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
DEST="$ROOT/dist/gateway-vpn-vps-$VERSION-linux-amd64"
ARCHIVE="$ROOT/dist/gateway-vpn-vps-$VERSION-linux-amd64.tar.gz"
[[ ! -e "$DEST" && ! -e "$ARCHIVE" ]] || { echo "VPS release destination already exists" >&2; exit 1; }
COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD) || { echo "VPS release build requires a committed Git revision" >&2; exit 1; }
[[ "$COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || { echo "Git commit identity is invalid" >&2; exit 1; }
[[ -z $(git -C "$ROOT" status --porcelain --untracked-files=normal) ]] || { echo "VPS release build requires a clean committed worktree" >&2; exit 1; }

mkdir -p "$DEST/bin" "$DEST/scripts" "$DEST/share/doc" "$DEST/share/supply-chain"
SOURCE_DATE_EPOCH=$(git -C "$ROOT" show -s --format=%ct "$COMMIT")
[[ "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] || { echo "Git commit timestamp is invalid" >&2; exit 1; }
BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
[[ "$BUILD_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || { echo "Canonical build date is invalid" >&2; exit 1; }
LDFLAGS="-s -w -X gateway-vpn/internal/buildinfo.Version=$VERSION -X gateway-vpn/internal/buildinfo.Commit=$COMMIT -X gateway-vpn/internal/buildinfo.Date=$BUILD_DATE"
(
  cd -- "$ROOT"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$DEST/bin/gateway-vpnctl" ./cmd/gateway-vpnctl
)
install -m 0755 "$ROOT/scripts/install-vps.sh" "$ROOT/scripts/uninstall-vps.sh" "$ROOT/scripts/recover-vps-install.sh" "$DEST/scripts/"
while IFS= read -r -d '' source; do
  relative=${source#"$ROOT/"}
  install -D -m 0644 "$source" "$DEST/$relative"
done < <(find "$ROOT/packaging/vps" -type f -print0 | sort -z)
install -m 0644 "$ROOT/docs/PLAN_v1.1.md" "$ROOT/docs/OPERATIONS.md" "$ROOT/docs/SECURITY.md" "$ROOT/docs/NETWORKING.md" "$DEST/share/doc/"
printf '{\n  "format_version": 1,\n  "role": "vps",\n  "version": "%s",\n  "os": "linux",\n  "arch": "amd64",\n  "source_commit": "%s",\n  "build_date": "%s",\n  "supported_profiles": ["debian-12", "ubuntu-20.04", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"],\n  "interface_name": "wg-mgmt",\n  "management_subnet": "10.80.0.0/24",\n  "listen_port": 51821\n}\n' "$VERSION" "$COMMIT" "$BUILD_DATE" >"$DEST/release.json"

CONTROL_SHA256=$(sha256sum --binary "$DEST/bin/gateway-vpnctl" | awk '{print $1}')
printf '{\n  "spdxVersion": "SPDX-2.3",\n  "dataLicense": "CC0-1.0",\n  "SPDXID": "SPDXRef-DOCUMENT",\n  "name": "Gateway-VPN-VPS-%s-linux-amd64",\n  "documentNamespace": "https://gateway-vpn.invalid/spdx/vps/%s/%s",\n  "creationInfo": {"created": "%s", "creators": ["Tool: gateway-vpn-build-vps-release"]},\n  "packages": [{"name": "Gateway VPN VPS role", "SPDXID": "SPDXRef-GatewayVPNVPS", "versionInfo": "%s", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "checksums": [{"algorithm": "SHA256", "checksumValue": "%s"}]}]\n}\n' "$VERSION" "$VERSION" "$COMMIT" "$BUILD_DATE" "$VERSION" "$CONTROL_SHA256" >"$DEST/share/supply-chain/sbom.spdx.json"
printf '{\n  "_type": "https://in-toto.io/Statement/v1",\n  "subject": [{"name": "bin/gateway-vpnctl", "digest": {"sha256": "%s"}}],\n  "predicateType": "https://slsa.dev/provenance/v1",\n  "predicate": {"buildDefinition": {"buildType": "https://gateway-vpn.invalid/build/vps-linux-amd64/v1", "externalParameters": {"version": "%s", "profiles": ["debian-12", "ubuntu-20.04", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"]}, "internalParameters": {"commit": "%s"}, "resolvedDependencies": []}, "runDetails": {"builder": {"id": "gateway-vpn-build-vps-release"}, "metadata": {"invocationId": "%s-%s"}}}\n}\n' "$CONTROL_SHA256" "$VERSION" "$COMMIT" "$VERSION" "$COMMIT" >"$DEST/share/supply-chain/provenance.intoto.json"
(
  cd -- "$DEST"
  find . -type f ! -path './manifest.sha256' ! -path './manifest.json' ! -path './release.sig' -print0 | sort -z | xargs -0 sha256sum --binary >manifest.sha256
)
"$DEST/bin/gateway-vpnctl" vps-release-sign --release-dir "$DEST" --private-key "$SIGNING_PRIVATE_KEY"
ARCHIVE_ENTRIES=()
while IFS= read -r -d '' entry; do
  ARCHIVE_ENTRIES+=("$entry")
done < <(find "$DEST" -mindepth 1 -maxdepth 1 -printf '%f\0' | sort -z)
((${#ARCHIVE_ENTRIES[@]} > 0)) || { echo "VPS release tree is empty" >&2; exit 1; }
# Keep the archive compatible with the same strict extractor used by the
# bootstrap and runtime updater: actual top-level entries only, never `.`.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" -C "$DEST" -czf "$ARCHIVE" -- "${ARCHIVE_ENTRIES[@]}"
ARCHIVE_SHA256=$(sha256sum --binary "$ARCHIVE" | awk '{print $1}')
echo "VPS release prepared at $DEST"
echo "Signed VPS archive prepared at $ARCHIVE"
echo "VPS archive SHA-256: $ARCHIVE_SHA256"
