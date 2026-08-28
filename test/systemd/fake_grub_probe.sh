#!/usr/bin/env bash
set -euo pipefail

# Docker's overlay root cannot be inspected by the real grub-probe. This
# deterministic test double models a plain ext4 partition only for exercising
# Ubuntu's real update-grub/grub-mkconfig and grub-script-check pipeline.
target=""
while (($#)); do
  case "$1" in
    --target=*) target=${1#--target=} ;;
    --target|-t)
      shift
      target=${1:-}
      ;;
  esac
  shift
done

case "$target" in
  "") exit 0 ;;
  device) echo /dev/sda1 ;;
  fs) echo ext2 ;;
  partmap) echo msdos ;;
  abstraction|cryptodisk_uuid) exit 0 ;;
  compatibility_hint|drive) echo '(hd0,msdos1)' ;;
  fs_uuid|partuuid|hints_string|fs_label) exit 1 ;;
  *) exit 1 ;;
esac
