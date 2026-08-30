package vpsfabric

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchdogStatusRejectsStaleCorruptAndUnsafeFiles(t *testing.T) {
	now := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), WatchdogStatusFilename)
	status := NewWatchdogStatus("PENDING", "RUNTIME_PROJECTION_DRIFT", false, true, now)
	content := []byte(`{"format_version":2,"state":"PENDING","healthy":false,"reconcile_scheduled":true,"reason":"RUNTIME_PROJECTION_DRIFT","checked_at":"2026-08-30T14:00:00Z","desired_generation":4,"applied_generation":3,"relay_count":1,"relay_rule_count":5,"relay_packets":12,"relay_bytes":2048}`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadWatchdogStatus(path, now.Add(time.Minute), 3*time.Minute)
	if err != nil || loaded.Reason != status.Reason || !loaded.ReconcileScheduled {
		t.Fatalf("valid watchdog status rejected: %#v %v", loaded, err)
	}
	if _, err := ReadWatchdogStatus(path, now.Add(10*time.Minute), 3*time.Minute); err == nil {
		t.Fatal("stale watchdog status accepted")
	}
	if err := os.WriteFile(path, []byte(`{"format_version":1,"state":"HEALTHY","healthy":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWatchdogStatus(path, now, 3*time.Minute); err == nil {
		t.Fatal("incoherent watchdog status accepted")
	}
	unsafe := filepath.Join(filepath.Dir(path), "unsafe.json")
	if _, err := ReadWatchdogStatus(unsafe, now, 3*time.Minute); err == nil {
		t.Fatal("non-canonical watchdog status path accepted")
	}
}
