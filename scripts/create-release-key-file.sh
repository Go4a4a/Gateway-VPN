#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
case $- in *x*) set +x ;; esac

PRIMARY_KEY_FILE=${1:-}
BACKUP_KEY_FILE=${2:-}
[[ -n "$PRIMARY_KEY_FILE" && -n "$BACKUP_KEY_FILE" ]] || {
  echo "Usage: create-release-key-file.sh PRIMARY.gvkey BACKUP.gvkey [--passphrase-file /secure/tmp/passphrase]" >&2
  exit 2
}
shift 2
PASSPHRASE_FILE=
if [[ ${1:-} == --passphrase-file ]]; then
  PASSPHRASE_FILE=${2:-}
  [[ -n "$PASSPHRASE_FILE" ]] || { echo "--passphrase-file requires a path" >&2; exit 2; }
  shift 2
fi
(($# == 0)) || { echo "Unexpected encrypted key-file argument" >&2; exit 2; }

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ $(uname -s) == Linux ]] || { echo "Encrypted production key creation requires a trusted Linux builder" >&2; exit 1; }
[[ -d /dev/shm && ! -L /dev/shm && $(stat -f -c %T /dev/shm) == tmpfs ]] || {
  echo "Encrypted production key creation requires real /dev/shm tmpfs" >&2
  exit 1
}
SECRET_ROOT=
BUILD_ROOT=
cleanup() {
	unset PASSPHRASE CONFIRMATION
	if [[ -n ${SECRET_ROOT:-} && "$SECRET_ROOT" == /dev/shm/gateway-vpn-key-create.* && -d "$SECRET_ROOT" && ! -L "$SECRET_ROOT" ]]; then
		rm -rf -- "$SECRET_ROOT"
	fi
	if [[ -n ${BUILD_ROOT:-} && "$BUILD_ROOT" == /tmp/gateway-vpn-key-helper.* && -d "$BUILD_ROOT" && ! -L "$BUILD_ROOT" ]]; then
		rm -rf -- "$BUILD_ROOT"
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
SECRET_ROOT=$(mktemp -d /dev/shm/gateway-vpn-key-create.XXXXXX)
[[ "$SECRET_ROOT" == /dev/shm/gateway-vpn-key-create.* && -d "$SECRET_ROOT" && ! -L "$SECRET_ROOT" ]] || exit 1
chmod 0700 "$SECRET_ROOT"
[[ -d /tmp && ! -L /tmp ]] || { echo "Encrypted key helper build requires a real /tmp directory" >&2; exit 1; }
BUILD_ROOT=$(mktemp -d /tmp/gateway-vpn-key-helper.XXXXXX)
[[ "$BUILD_ROOT" == /tmp/gateway-vpn-key-helper.* && -d "$BUILD_ROOT" && ! -L "$BUILD_ROOT" ]] || exit 1
chmod 0700 "$BUILD_ROOT"

if [[ -z "$PASSPHRASE_FILE" ]]; then
  [[ -r /dev/tty && -w /dev/tty ]] || { echo "Interactive terminal is unavailable; use --passphrase-file" >&2; exit 1; }
  IFS= read -r -s -p "New encrypted release-key passphrase: " PASSPHRASE </dev/tty
  printf '\n' >/dev/tty
  IFS= read -r -s -p "Repeat passphrase: " CONFIRMATION </dev/tty
  printf '\n' >/dev/tty
  [[ -n "$PASSPHRASE" && "$PASSPHRASE" == "$CONFIRMATION" ]] || { echo "Passphrases do not match" >&2; exit 1; }
	PASSPHRASE_FILE="$SECRET_ROOT/passphrase"
  (umask 077; printf '%s' "$PASSPHRASE" >"$PASSPHRASE_FILE")
  unset PASSPHRASE CONFIRMATION
fi

CONTROL="$BUILD_ROOT/gateway-vpnctl"
(
  cd -- "$ROOT"
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$CONTROL" ./cmd/gateway-vpnctl
)
"$CONTROL" release-keyfile-create \
  --key-file "$PRIMARY_KEY_FILE" --passphrase-file "$PASSPHRASE_FILE"
"$CONTROL" release-keyfile-backup \
  --key-file "$PRIMARY_KEY_FILE" --backup-key-file "$BACKUP_KEY_FILE" --passphrase-file "$PASSPHRASE_FILE"
"$CONTROL" release-keyfile-verify \
  --key-file "$PRIMARY_KEY_FILE" --passphrase-file "$PASSPHRASE_FILE"
"$CONTROL" release-keyfile-verify \
  --key-file "$BACKUP_KEY_FILE" --passphrase-file "$PASSPHRASE_FILE"
echo "Encrypted production signing key file and verified backup created; store their passphrase separately"
