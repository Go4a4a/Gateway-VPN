# Gateway VPN release-gate helpers

This directory contains source-only helpers for destructive checks against an
isolated Linux/systemd release-gate host. They are not installed, packaged, or
called by Gateway VPN production code.

Every mutating helper requires all of the following:

1. `GATEWAY_VPN_RELEASE_GATE=1` in its environment;
2. the explicit `--release-gate-only` flag;
3. absolute, caller-supplied paths and the exact expected update or release
   identity;
4. the state contract expected by that helper.

Build them from a clean checkout with the same pinned Go toolchain and module
cache used by the release gate. Do not copy the binaries to a real Gateway.

## `force-update-deadline`

This helper changes only the `stability_deadline` and `updated_at` fields of
one exact `STABILIZING` transaction, then persists both journal copies through
the production `update.JournalStore`. It exists solely to exercise the exact
production finalizer without waiting 24 wall-clock hours. A successful run is
not evidence that a real 24-hour stability window elapsed.

The caller must provide the absolute `update-transactions` root and the exact
observed update ID. The helper refuses terminal, rollback, or non-stabilizing
transactions and reloads the checksummed journal before returning success.

## `stage-signed-update`

This helper invokes the production signed-release stager without going through
the Web UI. It loads the exact strict production config and derives the state
directory and read-only live DB from that config, then derives the compatibility
policy from the DB and exact trusted current release. Signature, signer,
manifest, host contract, schema, config, OS, and architecture checks remain
production checks.

It is used only to prepare a candidate before a controlled systemd interruption
test. Actual apply/recovery/finalization must still be performed by the exact
production systemd units.

## `validate_gateway_systemd.sh`

This read-only validator checks an already installed or rebooted release. It
requires the exact version, schema, an explicitly supplied sqlite3 binary, LAN
identity, and firewall generation. It verifies release signatures, SQLite
integrity, canonical blocked runtime state, watchdog evidence, systemd units
and restart counters, HTTPS security headers, SSH/DNS/DHCP listeners, IPv6
policy, empty direct/TUN gates, install report, and current-boot failure
signatures. It does not install packages or change host state.

## `validate_gateway_install_marker_lifecycle.sh`

This helper validates the current 21-field completed install marker, creates
explicit 14/16/18/20-field compatibility fixtures from that already validated
marker, and checks recovery or uninstall cleanup. It is intentionally
destructive, requires the release-gate environment and flag, and must run only
inside a disposable Ubuntu/systemd host. The surrounding gate still invokes
the signed production installer, host upgrader, recovery helper, and
uninstaller; this helper only prepares the historical marker shape and asserts
the resulting host state.

The required matrix is: fresh 21-field install with an original
`src_valid_mark=0`, interrupted recovery and normal uninstall restoring `0`,
21→21 upgrade retaining the original `0`, 20→21 upgrade capturing the
already-installed value, and 14/16/18 compatibility without inventing unknown
source-mark or `ssh.socket` state.

## Evidence boundary

These helpers may shorten a release-gate setup step, but they never prove
physical power-loss behavior, real hardware compatibility, an elapsed
stability/endurance window, or production readiness. Record the exact commit,
artifact hashes, container/host identity, injected state, and resulting
production-unit evidence in `docs/PROJECT_STATUS.md`.
