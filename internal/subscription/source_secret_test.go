package subscription

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFileSourceURLReaderReadsOnlySecureConfinedRegularFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(filepath.Join(root, "subscriptions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "subscriptions", "sub-a.url")
	if err := os.WriteFile(secret, []byte("https://provider.example/sub?token=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o600); err != nil {
		t.Fatal(err)
	}
	reader := FileSourceURLReader{Root: root}
	for _, reference := range []string{"subscriptions/sub-a.url", secret} {
		value, err := reader.ReadURL(context.Background(), reference)
		if err != nil || value != "https://provider.example/sub?token=secret" {
			t.Fatalf("ReadURL(%q) = %q, %v", reference, value, err)
		}
	}
	if _, err := reader.ReadURL(context.Background(), filepath.Join(root, "..", "outside")); err == nil {
		t.Fatal("ReadURL(outside) error = nil")
	}
}

func TestFileSourceURLReaderRejectsSymlinkAndOversizedSecret(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("https://outside.example/sub"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(outside, link); err == nil {
		if _, err := (FileSourceURLReader{Root: root}).ReadURL(context.Background(), link); err == nil {
			t.Fatal("ReadURL(symlink) error = nil")
		}
	} else if runtime.GOOS != "windows" {
		t.Fatalf("create symlink: %v", err)
	}
	large := filepath.Join(root, "large")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxSourceSecretBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(large, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileSourceURLReader{Root: root}).ReadURL(context.Background(), large); err == nil {
		t.Fatal("ReadURL(large) error = nil")
	}
}

func TestFileSourceURLReaderRejectsBroadUnixPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs are validated by the installer, not Unix mode bits")
	}
	root := filepath.Join(t.TempDir(), "secrets")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "sub.url")
	if err := os.WriteFile(secret, []byte("https://provider.example/sub"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileSourceURLReader{Root: root}).ReadURL(context.Background(), secret); err == nil {
		t.Fatal("ReadURL(0644) error = nil")
	}
}

func TestSaveAndDeleteURLSecretAreAtomicConfinedAndValidated(t *testing.T) {
	root := filepath.Join(t.TempDir(), "subscriptions")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	reference := filepath.Join(root, "sub-a.url")
	value := "https://provider.example/subscription?token=secret"
	if err := SaveURLSecret(root, reference, value); err != nil {
		t.Fatalf("SaveURLSecret() error = %v", err)
	}
	stored, err := (FileSourceURLReader{Root: root}).ReadURL(context.Background(), reference)
	if err != nil || stored != value {
		t.Fatalf("ReadURL(saved) = %q, %v", stored, err)
	}
	if matches, _ := filepath.Glob(filepath.Join(root, ".subscription-url-*.tmp")); len(matches) != 0 {
		t.Fatalf("temporary URL secrets remain: %v", matches)
	}
	for _, invalid := range []string{"http://provider.example/sub", "https://127.0.0.1/sub", "https://user:password@provider.example/sub"} {
		if err := SaveURLSecret(root, reference, invalid); err == nil {
			t.Fatalf("SaveURLSecret(%q) error = nil", invalid)
		}
	}
	if err := SaveURLSecret(root, filepath.Join(root, "nested", "sub.url"), value); err == nil {
		t.Fatal("SaveURLSecret(nested) error = nil")
	}
	if err := DeleteURLSecret(root, reference); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(reference); !os.IsNotExist(err) {
		t.Fatalf("deleted URL secret still exists: %v", err)
	}
}
