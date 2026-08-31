package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	updatepkg "gateway-vpn/internal/update"
)

func TestRunRequiresBothReleaseGateConfirmations(t *testing.T) {
	for _, test := range []struct {
		name      string
		env       string
		confirmed bool
	}{
		{name: "neither"},
		{name: "environment only", env: "1"},
		{name: "flag only", confirmed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			arguments := []string{"--root", filepath.Join(t.TempDir(), "update-transactions"), "--expected-update-id", testUpdateID}
			if test.confirmed {
				arguments = append(arguments, "--release-gate-only")
			}
			var stderr bytes.Buffer
			code := run(arguments, func(string) string { return test.env }, time.Now, &bytes.Buffer{}, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), "environment and explicit confirmation") {
				t.Fatalf("run() = %d, %q", code, stderr.String())
			}
		})
	}
}

func TestRunMovesOnlyExactStabilizingJournal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update-transactions")
	store := updatepkg.JournalStore{Root: root}
	started := time.Date(2026, 8, 28, 1, 0, 0, 0, time.UTC)
	journal := testJournal(started)
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}

	arguments := []string{
		"--root", root,
		"--expected-update-id", journal.UpdateID,
		"--release-gate-only",
	}
	gateNow := started.Add(time.Hour)
	var stdout, stderr bytes.Buffer
	code := run(arguments, func(string) string { return "1" }, func() time.Time { return gateNow }, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, stderr=%q", code, stderr.String())
	}

	reloaded, exists, err := store.LoadActive()
	if err != nil || !exists {
		t.Fatalf("LoadActive() = exists %t, err %v", exists, err)
	}
	if reloaded.State != updatepkg.StateStabilizing || reloaded.StabilityDeadline != gateNow.Add(-time.Second).Format(time.RFC3339Nano) || reloaded.UpdatedAt != gateNow.Add(-2*time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("unexpected reloaded journal: %+v", reloaded)
	}
	if !strings.Contains(stdout.String(), journal.UpdateID) {
		t.Fatalf("stdout does not identify transaction: %q", stdout.String())
	}
}

func TestRunRejectsWrongIdentityAndTerminalState(t *testing.T) {
	for _, test := range []struct {
		name       string
		expectedID string
		state      updatepkg.TransactionState
		want       string
	}{
		{name: "wrong identity", expectedID: "update-20260828T020000Z-ffffffffffffffffffffffff", state: updatepkg.StateStabilizing, want: "does not match expected"},
		{name: "terminal state", expectedID: testUpdateID, state: updatepkg.StateFinalized, want: "not STABILIZING"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "update-transactions")
			journal := testJournal(time.Date(2026, 8, 28, 1, 0, 0, 0, time.UTC))
			journal.State = test.state
			if test.state == updatepkg.StateFinalized {
				journal.UpdatedAt = time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
				journal.StabilityDeadline = time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
			}
			if err := (updatepkg.JournalStore{Root: root}).Save(journal); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			code := run([]string{"--root", root, "--expected-update-id", test.expectedID, "--release-gate-only"}, func(string) string { return "1" }, time.Now, &bytes.Buffer{}, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("run() = %d, %q", code, stderr.String())
			}
		})
	}
}

const testUpdateID = "update-20260828T010000Z-0123456789abcdef01234567"

func testJournal(started time.Time) updatepkg.Journal {
	return updatepkg.Journal{
		FormatVersion:              updatepkg.JournalFormatVersion,
		UpdateID:                   testUpdateID,
		State:                      updatepkg.StateStabilizing,
		StartedAt:                  started.Format(time.RFC3339Nano),
		UpdatedAt:                  started.Add(time.Second).Format(time.RFC3339Nano),
		OldVersion:                 "0.1.0-old",
		NewVersion:                 "0.1.0-new",
		OldCurrentTarget:           "releases/v0.1.0-old",
		NewCurrentTarget:           "releases/v0.1.0-new",
		PreUpdateSnapshotID:        "20260828T010000.000000000Z-0123456789abcdef01234567",
		RestorePointID:             "point-20260828T010000Z-0123456789abcdef01234567",
		OldSchemaVersion:           13,
		NewSchemaVersion:           16,
		CandidateDBSHA256:          strings.Repeat("a", 64),
		DatabaseReplacementStarted: true,
		StabilityDeadline:          started.Add(24 * time.Hour).Format(time.RFC3339Nano),
	}
}
