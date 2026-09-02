#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

usage() {
  cat >&2 <<'EOF'
Usage:
  validate_gateway_install_marker_lifecycle.sh --release-gate-only marker VERSION FIELD_COUNT OLD_SOURCE_MARK
  validate_gateway_install_marker_lifecycle.sh --release-gate-only rewrite FIELD_COUNT
  validate_gateway_install_marker_lifecycle.sh --release-gate-only activate FIELD_COUNT
  validate_gateway_install_marker_lifecycle.sh --release-gate-only cleaned recovery|uninstall EXPECTED_SOURCE_MARK

OLD_SOURCE_MARK is 0, 1, or absent. This helper is destructive and may only be
used on a disposable Ubuntu/systemd release-gate host.
EOF
  exit 2
}

[[ ${GATEWAY_VPN_RELEASE_GATE:-} == 1 ]] || {
  echo "GATEWAY_VPN_RELEASE_GATE=1 is required" >&2
  exit 1
}
[[ ${1:-} == --release-gate-only ]] || usage
shift
[[ $EUID -eq 0 ]] || { echo "Gateway install-marker release gate requires root" >&2; exit 1; }

TRANSACTIONS=/var/lib/gateway-vpn-privileged/install-transactions
ACTION=${1:-}
shift || true

validate_field_count() {
  [[ $1 == 14 || $1 == 16 || $1 == 18 || $1 == 20 || $1 == 21 ]]
}

latest_completed_marker() {
  local marker
  [[ -d $TRANSACTIONS && ! -L $TRANSACTIONS && $(stat -c '%u:%g:%a' "$TRANSACTIONS") == 0:0:700 ]] || {
    echo "Gateway install transaction directory is unsafe" >&2
    return 1
  }
  marker=$(find "$TRANSACTIONS" -maxdepth 1 -type f -name 'completed-*' -printf '%T@ %p\n' |
    sort -nr | awk 'NR==1 {sub(/^[^ ]+ /, ""); print}')
  [[ -n $marker && -f $marker && ! -L $marker && $(stat -c '%u:%g:%a' "$marker") == 0:0:600 ]] || {
    echo "Latest completed Gateway install marker is unavailable or unsafe" >&2
    return 1
  }
  printf '%s\n' "$marker"
}

rewrite_marker() {
  local requested=$1 marker temporary actual
  validate_field_count "$requested" || { echo "Unsupported marker field count: $requested" >&2; return 1; }
  marker=$(latest_completed_marker)
  [[ $(wc -l <"$marker") == 21 ]] || { echo "Synthetic compatibility rewrite requires a current 21-field marker" >&2; return 1; }
  [[ $(grep -c '^old_ipv4_src_valid_mark=' "$marker") == 1 ]] || { echo "Current marker lacks source-mark state" >&2; return 1; }
  temporary="$TRANSACTIONS/.release-gate-marker.tmp"
  [[ ! -e $temporary && ! -L $temporary ]] || { echo "Temporary release-gate marker already exists" >&2; return 1; }
  awk -v requested="$requested" '
    requested < 21 && /^old_ipv4_src_valid_mark=/ { next }
    requested < 20 && /^(ssh_socket_was_enabled|ssh_socket_was_active)=/ { next }
    requested < 18 && /^(log_reader_user|log_reader_was_member)=/ { next }
    requested < 16 && /^(boot_network_policy|grub_policy)=/ { next }
    { print }
  ' "$marker" >"$temporary"
  chmod 0600 "$temporary"
  actual=$(wc -l <"$temporary")
  [[ $actual == "$requested" ]] || { rm -f -- "$temporary"; echo "Synthetic marker has $actual fields, expected $requested" >&2; return 1; }
  sync -f "$temporary"
  mv -T "$temporary" "$marker"
  sync -f "$TRANSACTIONS"
  printf '%s\n' "$marker"
}

case "$ACTION" in
  marker)
    VERSION=${1:-}
    EXPECTED_COUNT=${2:-}
    EXPECTED_SOURCE=${3:-}
    [[ $# == 3 ]] || usage
    [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?(\+[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || usage
    validate_field_count "$EXPECTED_COUNT" || usage
    [[ $EXPECTED_SOURCE == 0 || $EXPECTED_SOURCE == 1 || $EXPECTED_SOURCE == absent ]] || usage
    MARKER=$(latest_completed_marker)
    [[ $(wc -l <"$MARKER") == "$EXPECTED_COUNT" ]]
    [[ $(sed -n 's/^version=//p' "$MARKER") == "$VERSION" ]]
    [[ $(grep -c '^version=' "$MARKER") == 1 ]]
    if [[ $EXPECTED_SOURCE == absent ]]; then
      if grep -q '^old_ipv4_src_valid_mark=' "$MARKER"; then
        echo "Legacy marker unexpectedly contains source-mark state" >&2
        exit 1
      fi
    else
      [[ $(grep -c '^old_ipv4_src_valid_mark=' "$MARKER") == 1 ]]
      [[ $(sed -n 's/^old_ipv4_src_valid_mark=//p' "$MARKER") == "$EXPECTED_SOURCE" ]]
    fi
    [[ $(cat /proc/sys/net/ipv4/conf/all/src_valid_mark) == 1 ]]
    [[ -f /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf && ! -L /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf ]]
    grep -Fxq 'net.ipv4.conf.all.src_valid_mark = 1' /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf
    echo "GATEWAY_INSTALL_MARKER_PASS version=$VERSION fields=$EXPECTED_COUNT old_source_mark=$EXPECTED_SOURCE"
    ;;
  rewrite)
    [[ $# == 1 ]] || usage
    rewrite_marker "$1" >/dev/null
    echo "GATEWAY_INSTALL_MARKER_REWRITE_PASS fields=$1"
    ;;
  activate)
    [[ $# == 1 ]] || usage
    MARKER=$(rewrite_marker "$1")
    [[ ! -e $TRANSACTIONS/active && ! -L $TRANSACTIONS/active ]]
    mv -T "$MARKER" "$TRANSACTIONS/active"
    sync -f "$TRANSACTIONS"
    [[ -f $TRANSACTIONS/active && ! -L $TRANSACTIONS/active && $(wc -l <"$TRANSACTIONS/active") == "$1" ]]
    echo "GATEWAY_INSTALL_MARKER_ACTIVATE_PASS fields=$1"
    ;;
  cleaned)
    KIND=${1:-}
    EXPECTED_SOURCE=${2:-}
    [[ $# == 2 && ($KIND == recovery || $KIND == uninstall) && ($EXPECTED_SOURCE == 0 || $EXPECTED_SOURCE == 1) ]] || usage
    [[ $(cat /proc/sys/net/ipv4/conf/all/src_valid_mark) == "$EXPECTED_SOURCE" ]]
    [[ ! -e /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf && ! -L /etc/sysctl.d/90-gateway-vpn-ipv4-forwarding.conf ]]
    [[ ! -e /etc/gateway-vpn && ! -L /etc/gateway-vpn ]]
    [[ ! -e /opt/gateway-vpn/current && ! -L /opt/gateway-vpn/current ]]
    [[ ! -e /opt/gateway-vpn/recovery && ! -L /opt/gateway-vpn/recovery ]]
    if [[ -d /opt/gateway-vpn/releases && ! -L /opt/gateway-vpn/releases ]]; then
      if find /opt/gateway-vpn/releases -mindepth 1 -maxdepth 1 -type d -name 'v*' -print -quit | grep -q .; then
        echo "Gateway release directory remains after cleanup" >&2
        exit 1
      fi
    fi
    [[ ! -e /etc/systemd/system/gateway-vpn.service && ! -L /etc/systemd/system/gateway-vpn.service ]]
    if nft list table inet gateway_vpn >/dev/null 2>&1; then
      echo "Gateway nftables table remains after cleanup" >&2
      exit 1
    fi
    if [[ $KIND == recovery ]]; then
      [[ ! -e /var/lib/gateway-vpn && ! -L /var/lib/gateway-vpn ]]
      [[ ! -e $TRANSACTIONS/active && ! -L $TRANSACTIONS/active ]]
      find "$TRANSACTIONS" -maxdepth 1 -type f -name 'rolled-back-*' -print -quit | grep -q .
    else
      [[ -f /var/lib/gateway-vpn/state.db && ! -L /var/lib/gateway-vpn/state.db ]]
    fi
    echo "GATEWAY_INSTALL_MARKER_CLEANUP_PASS kind=$KIND source_mark=$EXPECTED_SOURCE"
    ;;
  *)
    usage
    ;;
esac
