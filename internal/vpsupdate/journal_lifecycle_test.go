package vpsupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJournalInProgressMatchesOnlyDurableTerminalStates(t *testing.T) {
	terminal := map[State]bool{
		StateRolledBack: true,
		StateFinalized:  true,
	}
	states := []State{
		StatePrepared,
		StateQuiesced,
		StateCandidateReady,
		StateDBSwitching,
		StateDBSwitched,
		StateReleaseSwitch,
		StateHealthChecking,
		StateStabilizing,
		StateRollingBack,
		StateRolledBack,
		StateRollbackFailed,
		StateFinalized,
	}
	for _, state := range states {
		if got := (Journal{State: state}).InProgress(); got == terminal[state] {
			t.Errorf("state %s InProgress() = %t", state, got)
		}
	}
}

func TestLoadActiveDoesNotCreateMissingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gateway-vpn-vps-privileged", "update-transactions")
	if _, exists, err := (JournalStore{Root: root}).LoadActive(); err != nil || exists {
		t.Fatalf("LoadActive() exists=%t err=%v", exists, err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only lifecycle inspection created state: %v", err)
	}
}

func TestRecoverLockedClearsTerminalPointerWithoutRollback(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gateway-vpn-vps-privileged", "update-transactions")
	store := JournalStore{Root: root}
	journal := validJournal(time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC))
	journal.State = StateRolledBack
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{}
	recovered, err := (&Engine{Store: store, Runtime: runtime}).recoverLocked(context.Background(), true)
	if err != nil || recovered {
		t.Fatalf("recoverLocked() = %t, %v", recovered, err)
	}
	if len(runtime.started) != 0 || len(runtime.scheduled) != 0 {
		t.Fatalf("terminal journal caused runtime mutation: started=%v scheduled=%v", runtime.started, runtime.scheduled)
	}
	if _, err := os.Lstat(filepath.Join(root, "active.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminal active pointer was not cleared: %v", err)
	}
}

func TestLoadActivePrefersNewRecoverableTransactionOverOldTerminalPointer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gateway-vpn-vps-privileged", "update-transactions")
	store := JournalStore{Root: root}
	stamp := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	terminal := validJournal(stamp)
	terminal.State = StateFinalized
	if err := store.Save(terminal); err != nil {
		t.Fatal(err)
	}
	newer := validJournal(stamp.Add(time.Minute))
	newer.UpdateID = "vps-update-20260831T120100Z-fedcba9876543210fedcba98"
	newer.OldVersion = "1.2.0"
	newer.NewVersion = "1.3.0"
	newer.OldCurrentTarget = "releases/v1.2.0"
	newer.NewCurrentTarget = "releases/v1.3.0"
	if err := store.Save(newer); err != nil {
		t.Fatal(err)
	}
	// Model a crash after the new per-transaction copy was synced but before
	// active.json was replaced: the old terminal pointer is still valid.
	if err := writeAtomicJSON(filepath.Join(root, "active.json"), terminal, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := store.LoadActive()
	if err != nil || !exists || loaded.UpdateID != newer.UpdateID || !loaded.InProgress() {
		t.Fatalf("LoadActive() = %#v, %t, %v", loaded, exists, err)
	}
}
