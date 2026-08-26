//go:build linux

package update

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInstallReleaseNormalizesModesUnderRestrictiveUmask(t *testing.T) {
	fixture := newEngineFixture(t)
	stagedRoot, err := fixture.stager.ReleaseRoot(fixture.operation.UpdateID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRelease(stagedRoot, fixture.stager.Policy)
	if err != nil {
		t.Fatal(err)
	}

	previousUmask := syscall.Umask(0o077)
	defer syscall.Umask(previousUmask)
	installed, installErr := fixture.engine.installRelease(verified)
	syscall.Umask(previousUmask)
	if installErr != nil {
		t.Fatal(installErr)
	}

	if _, err := VerifyRelease(installed, fixture.stager.Policy); err != nil {
		t.Fatalf("installed release does not verify: %v", err)
	}
	if err := filepath.WalkDir(installed, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if got := info.Mode().Perm(); got != 0o755 {
				t.Errorf("directory %s mode = %04o, want 0755", path, got)
			}
			return nil
		}
		relative, err := filepath.Rel(installed, path)
		if err != nil {
			return err
		}
		want := os.FileMode(0o644)
		if record := findRecord(verified.Manifest.Files, filepath.ToSlash(relative)); record != nil && record.Executable {
			want = 0o755
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("file %s mode = %04o, want %04o", path, got, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
