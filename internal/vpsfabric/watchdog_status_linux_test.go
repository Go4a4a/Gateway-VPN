//go:build linux

package vpsfabric

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteWatchdogStatusIsAtomicAndReadable(t *testing.T) {
	now := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), WatchdogStatusFilename)
	status := NewWatchdogStatus("HEALTHY", "HEALTHY", true, false, now)
	if err := WriteWatchdogStatus(path, status, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadWatchdogStatus(path, now, 3*time.Minute)
	if err != nil || loaded != status {
		t.Fatalf("written watchdog status differs: %#v %#v %v", status, loaded, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("watchdog status mode=%v err=%v", info.Mode(), err)
	}
}
