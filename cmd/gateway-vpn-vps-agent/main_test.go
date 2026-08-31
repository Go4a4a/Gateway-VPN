package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gateway-vpn/internal/vpsupdate"
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

func TestFabricTriggerUsesSeparateFixedPath(t *testing.T) {
	directory := t.TempDir()
	trigger := systemdFabricTrigger{path: filepath.Join(directory, "fabric.trigger")}
	if err := trigger.ApplyVPSFabric(t.Context()); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(trigger.path)
	if err != nil || string(content) != "apply\n" {
		t.Fatalf("fabric trigger = %q, %v", content, err)
	}
	wrong := systemdFabricTrigger{path: filepath.Join(directory, "restore.trigger")}
	if err := wrong.ApplyVPSFabric(t.Context()); err == nil {
		t.Fatal("fabric trigger accepted restore path")
	}
}

func TestVPSUpdateLifecycleInspectionDistinguishesTerminalJournal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gateway-vpn-vps-privileged", "update-transactions")
	stamp := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	journal := vpsupdate.Journal{
		FormatVersion:    vpsupdate.JournalFormatVersion,
		UpdateID:         "vps-update-20260831T120000Z-0123456789abcdef01234567",
		State:            vpsupdate.StateFinalized,
		StartedAt:        stamp,
		UpdatedAt:        stamp,
		OldVersion:       "1.1.0",
		NewVersion:       "1.2.0",
		OldSchema:        4,
		NewSchema:        4,
		OldCurrentTarget: "releases/v1.1.0",
		NewCurrentTarget: "releases/v1.2.0",
	}
	if err := (vpsupdate.JournalStore{Root: root}).Save(journal); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := inspectVPSUpdateLifecycle(root)
	if err != nil || !exists || loaded.InProgress() {
		t.Fatalf("inspectVPSUpdateLifecycle() = %#v, %t, %v", loaded, exists, err)
	}
	if err := os.WriteFile(filepath.Join(root, "active.json"), []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectVPSUpdateLifecycle(root); err == nil {
		t.Fatal("corrupt VPS lifecycle journal was accepted")
	}
}
