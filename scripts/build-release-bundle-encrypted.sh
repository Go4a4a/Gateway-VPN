#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
case $- in *x*) set +x ;; esac

VERSION=${1:-}
CHANNEL=${2:-}
MIHOMO_VERSION=${3:-}
MIHOMO_BINARY=${4:-}
ENCRYPTED_KEY_FILE=${5:-}
GITHUB_REPOSITORY=${6:-}
RELEASE_TAG=${7:-}
LAN_INTERFACE=${8:-}
LAN_ADDRESS=${9:-}
[[ -n "$VERSION" && -n "$CHANNEL" && -n "$MIHOMO_VERSION" && -n "$MIHOMO_BINARY" && -n "$ENCRYPTED_KEY_FILE" &&
  -n "$GITHUB_REPOSITORY" && -n "$RELEASE_TAG" && -n "$LAN_INTERFACE" && -n "$LAN_ADDRESS" ]] || {
  echo "Usage: build-release-bundle-encrypted.sh VERSION CHANNEL MIHOMO_VERSION MIHOMO_BINARY KEY.gvkey OWNER/REPO vVERSION LAN_INTERFACE LAN_CIDR [--enable-dhcp] [--passphrase-file /secure/tmp/passphrase]" >&2
  exit 2
}
shift 9
ENABLE_DHCP=0
PASSPHRASE_FILE=
while (($# > 0)); do
  case "$1" in
    --enable-dhcp)
      ((ENABLE_DHCP == 0)) || { echo "Duplicate --enable-dhcp" >&2; exit 2; }
      ENABLE_DHCP=1
      shift
      ;;
    --passphrase-file)
      [[ -z "$PASSPHRASE_FILE" && -n ${2:-} ]] || { echo "Invalid --passphrase-file" >&2; exit 2; }
      PASSPHRASE_FILE=$2
      shift 2
      ;;
    *) echo "Unexpected encrypted release bundle argument" >&2; exit 2 ;;
  esac
done

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ $(uname -s) == Linux ]] || { echo "Encrypted production signing requires a trusted Linux builder" >&2; exit 1; }
[[ -d /dev/shm && ! -L /dev/shm && $(stat -f -c %T /dev/shm) == tmpfs ]] || {
  echo "Encrypted production signing requires real /dev/shm tmpfs" >&2
  exit 1
}
SECRET_ROOT=
BUILD_ROOT=
cleanup() {
	unset PASSPHRASE
	if [[ -n ${SECRET_ROOT:-} && "$SECRET_ROOT" == /dev/shm/gateway-vpn-key-unlock.* && -d "$SECRET_ROOT" && ! -L "$SECRET_ROOT" ]]; then
		rm -rf -- "$SECRET_ROOT"
	fi
	if [[ -n ${BUILD_ROOT:-} && "$BUILD_ROOT" == /tmp/gateway-vpn-key-helper.* && -d "$BUILD_ROOT" && ! -L "$BUILD_ROOT" ]]; then
		rm -rf -- "$BUILD_ROOT"
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
SECRET_ROOT=$(mktemp -d /dev/shm/gateway-vpn-key-unlock.XXXXXX)
[[ "$SECRET_ROOT" == /dev/shm/gateway-vpn-key-unlock.* && -d "$SECRET_ROOT" && ! -L "$SECRET_ROOT" ]] || exit 1
chmod 0700 "$SECRET_ROOT"
[[ -d /tmp && ! -L /tmp ]] || { echo "Encrypted key helper build requires a real /tmp directory" >&2; exit 1; }
BUILD_ROOT=$(mktemp -d /tmp/gateway-vpn-key-helper.XXXXXX)
[[ "$BUILD_ROOT" == /tmp/gateway-vpn-key-helper.* && -d "$BUILD_ROOT" && ! -L "$BUILD_ROOT" ]] || exit 1
chmod 0700 "$BUILD_ROOT"

if [[ -z "$PASSPHRASE_FILE" ]]; then
  [[ -r /dev/tty && -w /dev/tty ]] || { echo "Interactive terminal is unavailable; use --passphrase-file" >&2; exit 1; }
  IFS= read -r -s -p "Encrypted release-key passphrase: " PASSPHRASE </dev/tty
  printf '\n' >/dev/tty
  [[ -n "$PASSPHRASE" ]] || { echo "Passphrase is empty" >&2; exit 1; }
	PASSPHRASE_FILE="$SECRET_ROOT/passphrase"
  (umask 077; printf '%s' "$PASSPHRASE" >"$PASSPHRASE_FILE")
  unset PASSPHRASE
fi

CONTROL="$BUILD_ROOT/gateway-vpnctl"
UNLOCKED="$SECRET_ROOT/unlocked"
install -d -m 0700 "$UNLOCKED"
(
  cd -- "$ROOT"
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$CONTROL" ./cmd/gateway-vpnctl
)
"$CONTROL" release-keyfile-unlock \
  --key-file "$ENCRYPTED_KEY_FILE" --passphrase-file "$PASSPHRASE_FILE" \
  --private-key "$UNLOCKED/release-signing.pem" --public-key "$UNLOCKED/update-signing.pub"

BUNDLE_ARGS=(
  "$VERSION" "$CHANNEL" "$MIHOMO_VERSION" "$MIHOMO_BINARY"
  "$UNLOCKED/release-signing.pem" "$UNLOCKED/update-signing.pub"
  "$GITHUB_REPOSITORY" "$RELEASE_TAG" "$LAN_INTERFACE" "$LAN_ADDRESS"
)
if ((ENABLE_DHCP)); then
  BUNDLE_ARGS+=(--enable-dhcp)
fi
"$ROOT/scripts/build-release-bundle.sh" "${BUNDLE_ARGS[@]}"
echo "Encrypted key file remained at rest; temporary plaintext signing identity was removed from tmpfs"
