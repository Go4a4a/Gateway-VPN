package update

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	testRollbackPointOne = "point-20260831T010000Z-0123456789abcdef01234567"
	testRollbackPointTwo = "point-20260831T020000Z-fedcba9876543210fedcba98"
)

func TestRollbackRequestStoreIsIdempotentAndRejectsConflict(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update-rollback")
	store := RollbackRequestStore{Root: root, Now: func() time.Time {
		return time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	}}
	first, err := store.Write(testRollbackPointOne)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := store.Write(testRollbackPointOne)
	if err != nil || repeated != first {
		t.Fatalf("idempotent Write() = %+v,%v; want %+v", repeated, err, first)
	}
	if _, err := store.Write(testRollbackPointTwo); err == nil {
		t.Fatal("conflicting pending rollback request was accepted")
	}
	loaded, exists, err := store.Load()
	if err != nil || !exists || loaded != first {
		t.Fatalf("Load() after conflict = %+v,%t,%v", loaded, exists, err)
	}
}

func TestRollbackRequestStoreRejectsTamperingAndRecoveryDiscardsMarker(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update-rollback")
	store := RollbackRequestStore{Root: root}
	if _, err := store.Write(testRollbackPointOne); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.filename(), []byte("{\"request\":{},\"sha256\":\"tampered\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(); err == nil {
		t.Fatal("tampered rollback request was accepted")
	}
	if err := store.DiscardPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(store.filename()); !os.IsNotExist(err) {
		t.Fatalf("stale rollback marker still exists: %v", err)
	}
	if err := store.DiscardPending(); err != nil {
		t.Fatalf("idempotent DiscardPending() = %v", err)
	}
}

func TestRollbackRequestStoreWillNotRemoveDirectoryMarker(t *testing.T) {
	root := filepath.Join(t.TempDir(), "update-rollback")
	if err := os.MkdirAll(filepath.Join(root, "pending.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	store := RollbackRequestStore{Root: root}
	if err := store.DiscardPending(); err == nil {
		t.Fatal("directory rollback marker was removed")
	}
	if info, err := os.Lstat(store.filename()); err != nil || !info.IsDir() {
		t.Fatalf("unsafe marker changed: info=%v error=%v", info, err)
	}
}
