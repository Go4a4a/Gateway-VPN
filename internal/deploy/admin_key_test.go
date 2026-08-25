package deploy

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestAdminIdentityCreatesMissingProtectedDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, ".config", "gateway-vpn")
	identity, err := PrepareAdminIdentity(filepath.Join(directory, "admin.conf"))
	if err != nil || !validPublicKey(identity.PublicKey) {
		t.Fatalf("prepare admin identity in missing directory: %+v %v", identity, err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("administrator config directory was not created as a real directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("administrator config directory mode = %o, want 700", info.Mode().Perm())
	}
}

func TestAdminIdentityRejectsUnsafeDirectoryBoundary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory permission boundary")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareAdminIdentity(filepath.Join(root, "gateway-vpn", "admin.conf")); err == nil {
		t.Fatal("world-writable administrator config ancestor accepted")
	}
	protected := filepath.Join(t.TempDir(), "gateway-vpn")
	if err := os.Mkdir(protected, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareAdminIdentity(filepath.Join(protected, "admin.conf")); err == nil {
		t.Fatal("non-private final administrator config directory accepted")
	}
}

func TestAdminIdentityRejectsSymlinkDirectoryComponent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "config-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := PrepareAdminIdentity(filepath.Join(link, "gateway-vpn", "admin.conf")); err == nil {
		t.Fatal("symlink administrator config directory component accepted")
	}
	if _, err := os.Lstat(filepath.Join(target, "gateway-vpn")); !os.IsNotExist(err) {
		t.Fatal("symlink target was mutated before rejection")
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
