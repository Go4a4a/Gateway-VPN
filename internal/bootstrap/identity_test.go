package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureModemIdentitySaltIsStableAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	first, err := EnsureModemIdentitySalt(root)
	if err != nil || len(first) < 32 {
		t.Fatalf("EnsureModemIdentitySalt(first) = %d, %v", len(first), err)
	}
	second, err := EnsureModemIdentitySalt(root)
	if err != nil || string(second) != string(first) {
		t.Fatalf("EnsureModemIdentitySalt(second) stable = %v, %v", string(second) == string(first), err)
	}
	filename := filepath.Join(root, "secrets", modemIdentitySaltFilename)
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filename); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := EnsureModemIdentitySalt(root); err == nil {
		t.Fatal("EnsureModemIdentitySalt(symlink) error = nil")
	}
}
