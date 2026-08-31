#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SOURCE_ROOT=${1:?read-only source root}
BUILD_ROOT=${2:?empty persistent build root}

[[ $SOURCE_ROOT == /* && -d $SOURCE_ROOT && ! -L $SOURCE_ROOT ]] || {
  echo "Restore-point fixture source root is unsafe" >&2
  exit 2
}
[[ $BUILD_ROOT == /* && -d $BUILD_ROOT && ! -L $BUILD_ROOT ]] || {
  echo "Restore-point fixture build root is unsafe" >&2
  exit 2
}
[[ -x /opt/mihomo && -x $SOURCE_ROOT/scripts/build-release.sh ]] || {
  echo "Offline release builder inputs are unavailable" >&2
  exit 1
}
if find "$BUILD_ROOT" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "Restore-point fixture build root must be empty" >&2
  exit 2
fi

tar --exclude=.git --exclude=dist --exclude=.cache --exclude=.tools -C "$SOURCE_ROOT" -cf - . \
  | tar -C "$BUILD_ROOT" -xf -
cd -- "$BUILD_ROOT"
git init -b main >/dev/null
git config user.name "Gateway VPN restore-point gate"
git config user.email "restore-point-gate@invalid"
git add -A
git commit -m "Disposable restore-point gate source" >/dev/null

install -d -m 0700 dist/test-signer
install -d -m 0700 /dev/shm/gateway-vpn-restore-gate
GOPROXY=off GOSUMDB=off go run ./cmd/gateway-vpnctl release-keygen \
  --private-key /dev/shm/gateway-vpn-restore-gate/release-signing.pem \
  --public-key /dev/shm/gateway-vpn-restore-gate/update-signing.pub
install -m 0644 /dev/shm/gateway-vpn-restore-gate/update-signing.pub \
  dist/test-signer/update-signing.pub

MIHOMO_SHA256=$(sha256sum --binary /opt/mihomo | awk '{print $1}')
export GOPROXY=off GOSUMDB=off
for version in \
  0.1.0-restoregate.1 \
  0.1.0-restoregate.2 \
  0.1.0-restoregate.3; do
  ./scripts/build-release.sh \
    "$version" v1.19.30 /opt/mihomo "$MIHOMO_SHA256" \
    /dev/shm/gateway-vpn-restore-gate/release-signing.pem
done

echo "GATEWAY_RESTORE_POINT_FIXTURE_PASS signer=$(sha256sum --binary dist/test-signer/update-signing.pub | awk '{print $1}')"
