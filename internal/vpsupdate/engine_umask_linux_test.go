//go:build linux

package vpsupdate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"gateway-vpn/internal/vpsrelease"
)

func TestInstallReleaseNormalizesModesUnderRestrictiveUmask(t *testing.T) {
	fixture := newEngineFixture(t)
	stagedRoot, err := fixture.stager.PendingReleaseRoot(fixture.operation.UpdateID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := vpsrelease.VerifyRelease(stagedRoot, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	previous := syscall.Umask(0o077)
	installed, installErr := fixture.engine.installRelease(verified, fixture.policy)
	syscall.Umask(previous)
	if installErr != nil {
		t.Fatal(installErr)
	}
	if err := filepath.WalkDir(installed, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if entry.IsDir() && info.Mode().Perm() != 0o755 {
			t.Errorf("directory %s mode = %04o, want 0755", path, info.Mode().Perm())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := vpsrelease.VerifyRelease(installed, fixture.policy); err != nil {
		t.Fatalf("normalized release does not verify: %v", err)
	}
}
