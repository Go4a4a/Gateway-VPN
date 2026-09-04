#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

ROOT=$(git rev-parse --show-toplevel)
[[ -n $ROOT && -d $ROOT/.git ]] || { echo "Gateway VPN pre-commit guard requires a Git worktree" >&2; exit 2; }

if ! command -v gitleaks >/dev/null 2>&1; then
  cat >&2 <<'EOF'
Gateway VPN pre-commit secret guard requires gitleaks in PATH.
Install the reviewed gitleaks 8.29.0 binary, or disable this opt-in hook with:
  git config --unset core.hooksPath
The server-side GitHub full-history secret gate remains mandatory and authoritative.
EOF
  exit 2
fi

# Scan only the staged snapshot. Gitleaks reads the repository .gitleaksignore,
# which contains six reviewed exact historical fixture fingerprints; whole
# test/fixtures directories are intentionally never excluded.
exec gitleaks protect --staged --redact --no-banner
