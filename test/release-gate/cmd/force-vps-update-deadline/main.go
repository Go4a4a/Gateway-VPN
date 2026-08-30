package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"gateway-vpn/internal/vpsupdate"
)

const releaseGateEnvironment = "GATEWAY_VPN_RELEASE_GATE"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, time.Now, os.Stdout, os.Stderr))
}

func run(arguments []string, getenv func(string) string, now func() time.Time, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("force-vps-update-deadline", flag.ContinueOnError)
	flags.SetOutput(stderr)
	expectedID := flags.String("expected-update-id", "", "exact VPS update transaction allowed for this gate")
	confirmed := flags.Bool("release-gate-only", false, "confirm isolated release-gate use")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	if getenv(releaseGateEnvironment) != "1" || !*confirmed || *expectedID == "" {
		return fail(stderr, "release-gate environment, exact update ID, and explicit confirmation are required")
	}
	store := vpsupdate.JournalStore{Root: "/var/lib/gateway-vpn-vps-privileged/update-transactions"}
	journal, exists, err := store.LoadActive()
	if err != nil || !exists || journal.UpdateID != *expectedID || journal.State != vpsupdate.StateStabilizing {
		return fail(stderr, "exact STABILIZING VPS journal is required: exists=%t err=%v", exists, err)
	}
	started, startErr := time.Parse(time.RFC3339Nano, journal.StartedAt)
	updated, updateErr := time.Parse(time.RFC3339Nano, journal.UpdatedAt)
	gateNow := now().UTC()
	newUpdated := gateNow.Add(-2 * time.Second)
	if startErr != nil || updateErr != nil || !newUpdated.After(started) || !newUpdated.After(updated) {
		return fail(stderr, "release-gate clock has not advanced beyond VPS journal timestamps")
	}
	journal.UpdatedAt = newUpdated.Format(time.RFC3339Nano)
	journal.StabilityDeadline = gateNow.Add(-time.Second).Format(time.RFC3339Nano)
	if err := store.Save(journal); err != nil {
		return fail(stderr, "save VPS release-gate deadline: %v", err)
	}
	fmt.Fprintf(stdout, "%s\n", journal.StabilityDeadline)
	return 0
}

func fail(stderr io.Writer, format string, arguments ...any) int {
	fmt.Fprintf(stderr, format+"\n", arguments...)
	return 1
}
