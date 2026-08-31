package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	updatepkg "gateway-vpn/internal/update"
)

func TestUpdateLifecycleInspectionDistinguishesLiveAndTerminalJournal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update-transactions")
	store := updatepkg.JournalStore{Root: root}
	now := time.Date(2026, 8, 31, 18, 0, 0, 0, time.UTC)
	journal := updatepkg.Journal{
		FormatVersion:    updatepkg.JournalFormatVersion,
		OperationKind:    updatepkg.TransactionSignedUpdate,
		UpdateID:         "update-20260831T180000Z-0123456789abcdef01234567",
		State:            updatepkg.StatePrepared,
		StartedAt:        now.Format(time.RFC3339Nano),
		UpdatedAt:        now.Format(time.RFC3339Nano),
		OldVersion:       "1.0.0",
		NewVersion:       "1.1.0",
		OldCurrentTarget: "releases/v1.0.0",
		NewCurrentTarget: "releases/v1.1.0",
	}
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	active, exists, err := inspectUpdateLifecycle(root)
	if err != nil || !exists || !active.InProgress() {
		t.Fatalf("live lifecycle = %+v,%t,%v", active, exists, err)
	}
	journal.State = updatepkg.StateRolledBack
	journal.UpdatedAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	terminal, exists, err := inspectUpdateLifecycle(root)
	if err != nil || !exists || terminal.InProgress() {
		t.Fatalf("terminal lifecycle = %+v,%t,%v", terminal, exists, err)
	}
}

func TestUpdateLifecycleInspectionFailsClosedForCorruptJournal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update-transactions")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "active.json"), []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectUpdateLifecycle(root); err == nil {
		t.Fatal("corrupt update lifecycle was reported idle")
	}
}

func TestUpdateRecoveryDiscardsStaleRollbackRequest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update-rollback")
	store := updatepkg.RollbackRequestStore{Root: root}
	const pointID = "point-20260831T010000Z-0123456789abcdef01234567"
	if _, err := store.Write(pointID); err != nil {
		t.Fatal(err)
	}
	if err := discardRollbackRequestAfterRecovery(store); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "pending.json")); !os.IsNotExist(err) {
		t.Fatalf("recovery left a valid stale rollback request: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "pending.json"), []byte("corrupted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := discardRollbackRequestAfterRecovery(store); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "pending.json")); !os.IsNotExist(err) {
		t.Fatalf("recovery left a corrupted stale rollback request: %v", err)
	}
}
