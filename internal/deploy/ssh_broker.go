package deploy

import (
	"fmt"
	"strings"
)

const windowsSSHProtocol = "GVR1"

func windowsSSHFrameLimit(outputLimit int) int {
	encoded := ((outputLimit + 2) / 3) * 4
	return encoded*2 + 1024
}

// windowsSSHBrokerCommand is executed by the target's normal SSH shell once.
// Subsequent phase commands arrive as base64 framed stdin records, while
// stdout/stderr/exit status return in one bounded authenticated SSH channel.
func windowsSSHBrokerCommand(outputLimit int) string {
	blocks := (outputLimit+511)/512 + 16
	script := fmt.Sprintf(`set -u; umask 077; command -v base64 >/dev/null 2>&1 || exit 126; root=$(mktemp -d /tmp/gateway-vpn-deploy-session.XXXXXX) || exit 126; cleanup(){ rm -rf -- "$root"; }; trap cleanup EXIT HUP INT TERM; printf 'GVR1\tREADY\n'; while IFS=$'\t' read -r request_id encoded extra; do case "$request_id" in ''|*[!0-9]*) exit 125;; esac; test -z "${extra:-}" || exit 125; printf '%%s' "$encoded" | base64 --decode >"$root/command" 2>/dev/null || exit 125; test "$(wc -c <"$root/command")" -le 131072 || exit 125; command_text=$(cat "$root/command"); : >"$root/stdout"; : >"$root/stderr"; (ulimit -f %d; /usr/bin/bash --norc -c "$command_text") >"$root/stdout" 2>"$root/stderr"; status=$?; stdout_bytes=$(wc -c <"$root/stdout"); stderr_bytes=$(wc -c <"$root/stderr"); if test "$stdout_bytes" -gt %d || test "$stderr_bytes" -gt %d; then message=$(printf 'remote output exceeded bounded limit' | base64 --wrap=0); printf 'GVR1\t%%s\t125\t\t%%s\n' "$request_id" "$message"; continue; fi; stdout_b64=$(base64 --wrap=0 <"$root/stdout"); stderr_b64=$(base64 --wrap=0 <"$root/stderr"); printf 'GVR1\t%%s\t%%s\t%%s\t%%s\n' "$request_id" "$status" "$stdout_b64" "$stderr_b64"; done`, blocks, outputLimit, outputLimit)
	return "/usr/bin/bash --norc -c " + posixShellQuote(script)
}

func posixShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
