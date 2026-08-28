package backup

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestPortableBackupEncryptsSecretsAuthenticatesChunksAndContainsVerifiedManifest(t *testing.T) {
	ctx, database, snapshots := snapshotTestManager(t)
	stateDirectory := filepath.Dir(snapshots.DatabasePath)
	configurationDirectory := t.TempDir()
	configurationPath := filepath.Join(configurationDirectory, "config.yaml")
	files := map[string]string{
		configurationPath: "version: 1\nsystem:\n  state_dir: /var/lib/gateway-vpn\n",
		filepath.Join(stateDirectory, "secrets", "subscriptions", "sub-a.url"):                "https://subscription.example/private?token=subscription-secret",
		filepath.Join(stateDirectory, "secrets", "wireguard.yaml"):                            "private_key: wireguard-private-secret",
		filepath.Join(stateDirectory, "secrets", "mihomo-api-secret"):                         "mihomo-api-secret-value",
		filepath.Join(stateDirectory, "subscriptions", "version-a", "nodes.json"):             `{"uuid":"proxy-private-secret"}`,
		filepath.Join(stateDirectory, "tls", "key.pem"):                                       "tls-private-secret",
		filepath.Join(stateDirectory, "tls", "cert.pem"):                                      "safe-certificate",
		filepath.Join(stateDirectory, "mihomo", "generations", "generation-a", "config.yaml"): "password: mihomo-private-secret",
		filepath.Join(stateDirectory, "mihomo", "state", "lkg-generation"):                    "generation-a\n",
	}
	for filename, content := range files {
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES('2026-08-24T14:00:00Z','INFO','PORTABLE_SOURCE','{}')`); err != nil {
		t.Fatal(err)
	}
	manager, err := NewPortableManager(snapshots, stateDirectory, configurationPath, "gateway-vpn test")
	if err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return time.Date(2026, 8, 24, 14, 30, 0, 0, time.UTC) }
	passphrase := "correct horse battery staple"
	artifact, err := manager.Build(ctx, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !portableNamePattern.MatchString(artifact.Filename) || artifact.Bytes <= 0 || artifact.Bytes > MaximumPortableBackupBytes || len(artifact.SHA256) != 64 || artifact.SnapshotID == "" || !artifact.Manifest.SecretsIncluded {
		t.Fatalf("portable artifact = %+v", artifact)
	}
	encrypted, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"subscription-secret", "wireguard-private-secret", "proxy-private-secret", "tls-private-secret", "mihomo-private-secret"} {
		if bytes.Contains(encrypted, []byte(secret)) {
			t.Fatalf("encrypted artifact contains plaintext %q", secret)
		}
	}

	decryptedPath := filepath.Join(t.TempDir(), "portable.zip")
	plainBytes, err := DecryptToZIP(ctx, artifact.Path, decryptedPath, passphrase)
	if err != nil || plainBytes <= 0 || plainBytes > MaximumPortablePlainBytes {
		t.Fatalf("DecryptToZIP() = %d, %v", plainBytes, err)
	}
	archive, err := zip.OpenReader(decryptedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	contents := map[string][]byte{}
	for _, item := range archive.File {
		if !safePortablePath(item.Name) || item.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe ZIP entry %q mode %o", item.Name, item.Mode().Perm())
		}
		reader, err := item.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(io.LimitReader(reader, MaximumPortablePlainBytes+1))
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		contents[item.Name] = content
	}
	for _, name := range []string{
		"manifest.json", "database/state.db", "config/config.yaml",
		"state/secrets/subscriptions/sub-a.url", "state/secrets/wireguard.yaml",
		"state/subscriptions/version-a/nodes.json", "state/tls/key.pem", "state/tls/cert.pem",
		"state/mihomo/generations/generation-a/config.yaml", "state/mihomo/state/lkg-generation",
	} {
		if _, exists := contents[name]; !exists {
			t.Fatalf("portable backup missing %s", name)
		}
	}
	var manifest PortableManifest
	if err := json.Unmarshal(contents["manifest.json"], &manifest); err != nil || !manifest.SecretsIncluded || manifest.SnapshotID != artifact.SnapshotID || manifest.SchemaVersion != 17 || len(manifest.Files) != len(contents)-1 {
		t.Fatalf("portable manifest = %+v, %v", manifest, err)
	}
	extractedDatabase := filepath.Join(t.TempDir(), "state.db")
	if err := os.WriteFile(extractedDatabase, contents["database/state.db"], 0o600); err != nil {
		t.Fatal(err)
	}
	verifiedDatabase, err := databasepkg.OpenImmutable(ctx, extractedDatabase)
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.IntegrityCheck(ctx, verifiedDatabase); err != nil {
		verifiedDatabase.Close()
		t.Fatal(err)
	}
	verifiedDatabase.Close()

	wrongDestination := filepath.Join(t.TempDir(), "wrong.zip")
	if _, err := DecryptToZIP(ctx, artifact.Path, wrongDestination, "wrong passphrase long enough"); err == nil || !strings.Contains(err.Error(), "passphrase or artifact") {
		t.Fatalf("wrong passphrase error = %v", err)
	}
	if _, err := os.Stat(wrongDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong-passphrase plaintext remains: %v", err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered.gvpn")
	tampered := append([]byte(nil), encrypted...)
	tampered[len(tampered)-8] ^= 0x80
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptToZIP(ctx, tamperedPath, filepath.Join(t.TempDir(), "tampered.zip"), passphrase); err == nil {
		t.Fatal("tampered encrypted backup was accepted")
	}
	truncatedPath := filepath.Join(t.TempDir(), "truncated.gvpn")
	if err := os.WriteFile(truncatedPath, encrypted[:len(encrypted)-5], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptToZIP(ctx, truncatedPath, filepath.Join(t.TempDir(), "truncated.zip"), passphrase); err == nil {
		t.Fatal("backup without authenticated final record was accepted")
	}
	if err := manager.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(artifact.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("served portable artifact remains: %v", err)
	}
}

func TestPortableBackupRejectsWeakPassphraseAndSymlinkedSecret(t *testing.T) {
	ctx, _, snapshots := snapshotTestManager(t)
	stateDirectory := filepath.Dir(snapshots.DatabasePath)
	configurationPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configurationPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewPortableManager(snapshots, stateDirectory, configurationPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Build(ctx, "short"); err == nil {
		t.Fatal("weak portable backup passphrase was accepted")
	}
	secretDirectory := filepath.Join(stateDirectory, "secrets")
	if err := os.MkdirAll(secretDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(target, []byte("must-not-follow"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(secretDirectory, "linked-secret")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := manager.Build(ctx, "correct horse battery staple"); err == nil {
		t.Fatal("symlinked secret was accepted")
	}
}
