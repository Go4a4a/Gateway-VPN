package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordFilePreflightValidatesBeforeInstallation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--check-password-file", path}); code != 0 {
		t.Fatalf("valid password preflight exit code = %d", code)
	}
	if err := os.WriteFile(path, []byte("too-short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--check-password-file", path}); code == 0 {
		t.Fatal("short VPS Hub password was accepted")
	}
}

func TestRestoreTriggerIsDurableAndRejectsUnsafeExistingPath(t *testing.T) {
	directory := t.TempDir()
	trigger := systemdRestoreTrigger{path: filepath.Join(directory, "restore.trigger")}
	if err := trigger.ApplyPendingVPSRestore(t.Context()); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(trigger.path)
	if err != nil || string(content) != "apply\n" {
		t.Fatalf("restore trigger = %q, %v", content, err)
	}
	if err := trigger.ApplyPendingVPSRestore(t.Context()); err != nil {
		t.Fatalf("idempotent restore trigger failed: %v", err)
	}
	if err := os.Remove(trigger.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "missing"), trigger.path); err != nil {
		t.Skipf("symlink test unavailable: %v", err)
	}
	if err := trigger.ApplyPendingVPSRestore(t.Context()); err == nil {
		t.Fatal("unsafe existing restore trigger was accepted")
	}
}
