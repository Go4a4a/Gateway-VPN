package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	updatepkg "gateway-vpn/internal/update"
)

const releaseGateEnvironment = "GATEWAY_VPN_RELEASE_GATE"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, time.Now, os.Stdout, os.Stderr))
}

func run(arguments []string, getenv func(string) string, now func() time.Time, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("force-update-deadline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "absolute update-transactions directory")
	expectedID := flags.String("expected-update-id", "", "exact update transaction allowed for this gate")
	confirmed := flags.Bool("release-gate-only", false, "confirm isolated release-gate use")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}

	if getenv(releaseGateEnvironment) != "1" || !*confirmed {
		return fail(stderr, "release-gate environment and explicit confirmation are required")
	}
	if !filepath.IsAbs(*root) || filepath.Base(filepath.Clean(*root)) != "update-transactions" {
		return fail(stderr, "an absolute update-transactions root is required")
	}
	if *expectedID == "" {
		return fail(stderr, "an exact expected update ID is required")
	}

	store := updatepkg.JournalStore{Root: filepath.Clean(*root)}
	journal, exists, err := store.LoadActive()
	if err != nil {
		return fail(stderr, "load active journal: %v", err)
	}
	if !exists {
		return fail(stderr, "no active update journal exists")
	}
	if journal.UpdateID != *expectedID {
		return fail(stderr, "active update ID %q does not match expected %q", journal.UpdateID, *expectedID)
	}
	if journal.State != updatepkg.StateStabilizing {
		return fail(stderr, "update %s is %s, not STABILIZING", journal.UpdateID, journal.State)
	}

	startedAt, err := time.Parse(time.RFC3339Nano, journal.StartedAt)
	if err != nil {
		return fail(stderr, "parse started_at: %v", err)
	}
	previousUpdatedAt, err := time.Parse(time.RFC3339Nano, journal.UpdatedAt)
	if err != nil {
		return fail(stderr, "parse updated_at: %v", err)
	}
	gateNow := now().UTC()
	updatedAt := gateNow.Add(-2 * time.Second)
	deadline := gateNow.Add(-time.Second)
	if !updatedAt.After(startedAt) || !updatedAt.After(previousUpdatedAt) {
		return fail(stderr, "release-gate clock has not advanced beyond the journal timestamps")
	}

	journal.UpdatedAt = updatedAt.Format(time.RFC3339Nano)
	journal.StabilityDeadline = deadline.Format(time.RFC3339Nano)
	if err := store.Save(journal); err != nil {
		return fail(stderr, "save checksummed journal: %v", err)
	}

	reloaded, exists, err := store.LoadActive()
	if err != nil || !exists {
		return fail(stderr, "reload checksummed journal: exists=%t err=%v", exists, err)
	}
	if reloaded.UpdateID != *expectedID || reloaded.State != updatepkg.StateStabilizing || reloaded.StabilityDeadline != journal.StabilityDeadline {
		return fail(stderr, "saved journal did not round-trip exactly")
	}
	fmt.Fprintf(stdout, "release-gate deadline moved for %s: %s\n", reloaded.UpdateID, reloaded.StabilityDeadline)
	return 0
}

func fail(stderr io.Writer, format string, arguments ...any) int {
	fmt.Fprintf(stderr, format+"\n", arguments...)
	return 1
}
