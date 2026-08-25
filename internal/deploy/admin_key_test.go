package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminIdentityCreatesLocalConfigAndResumes(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "admin.conf")
	identity, err := PrepareAdminIdentity(filename)
	if err != nil || !validPublicKey(identity.PublicKey) {
		t.Fatalf("prepare admin identity: %+v %v", identity, err)
	}
	if _, err := os.Lstat(filename + ".pending"); err != nil {
		t.Fatal("pending private identity was not persisted locally")
	}
	if err := identity.Finalize(testPublicKey(9), "1.1.1.1:51821"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "Address = 10.80.0.10/32") || !strings.Contains(string(content), "PublicKey = "+testPublicKey(9)) || strings.Contains(string(content), identity.PublicKey) {
		t.Fatal("administrator config content is incomplete or contains the public identity in the private field")
	}
	if _, err := os.Lstat(filename + ".pending"); !os.IsNotExist(err) {
		t.Fatal("pending identity was not removed after durable config")
	}
	repeated, err := PrepareAdminIdentity(filename)
	if err != nil || repeated.PublicKey != identity.PublicKey {
		t.Fatalf("admin identity did not resume: %+v %v", repeated, err)
	}
	if err := repeated.Finalize(testPublicKey(9), "1.1.1.1:51821"); err != nil {
		t.Fatalf("idempotent finalize failed: %v", err)
	}
	if err := repeated.Finalize(testPublicKey(10), "1.1.1.1:51821"); err == nil {
		t.Fatal("existing administrator config was silently replaced")
	}
}

func TestAdminIdentityRejectsSymlinkConfig(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("unsafe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "admin.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := PrepareAdminIdentity(link); err == nil {
		t.Fatal("symlink administrator config accepted")
	}
}
