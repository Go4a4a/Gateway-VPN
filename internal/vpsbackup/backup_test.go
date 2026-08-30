package vpsbackup

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/backup"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

func TestBuildProducesRoleSeparatedVerifiedSanitizedVPSBackup(t *testing.T) {
	ctx := context.Background()
	manager, database, stateDirectory := vpsBackupFixture(t)
	passphrase := "correct horse battery staple"
	ephemeral := "ephemeral-vps-session-secret-must-not-survive"
	if _, err := database.ExecContext(ctx, "INSERT INTO users(id,username,password_hash,enabled,must_change_password,created_at,updated_at) VALUES('user:test','test','hash',1,0,'now','now')"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "INSERT INTO sessions(id_hash,user_id,csrf_hash,created_at,expires_at,last_seen_at,client_key_hash) VALUES(?,'user:test','csrf','now','later','now','client')", ephemeral); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "INSERT INTO audit_events(occurred_at,severity,event_type,details_json) VALUES('now','INFO','TEST',?)", `{"secret":"`+ephemeral+`"}`); err != nil {
		t.Fatal(err)
	}

	artifact, err := manager.Build(ctx, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(artifact.Filename) != ".gvpn-vps" || !filenamePattern.MatchString(artifact.Filename) || artifact.Bytes <= 0 || !digestPattern.MatchString(artifact.SHA256) {
		t.Fatalf("artifact = %+v", artifact)
	}
	if artifact.Manifest.Role != "vps" || artifact.Manifest.SourceVPSID != "vps:primary" || artifact.Manifest.SchemaVersion != vpsagent.SchemaVersion || !artifact.Manifest.SecretsIncluded || !backupIDPattern.MatchString(artifact.Manifest.BackupID) {
		t.Fatalf("manifest = %+v", artifact.Manifest)
	}
	encrypted, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"vps-wireguard-private-secret", "vps-update-identity-secret", "vps-tls-private-secret", ephemeral} {
		if bytes.Contains(encrypted, []byte(secret)) {
			t.Fatalf("encrypted VPS backup contains plaintext %q", secret)
		}
	}
	if _, err := backup.DecryptToZIP(ctx, artifact.Path, filepath.Join(t.TempDir(), "wrong-role.zip"), passphrase); err == nil {
		t.Fatal("Gateway decryptor accepted a VPS backup")
	}

	decryptedPath := filepath.Join(t.TempDir(), "vps.zip")
	if _, err := backup.DecryptVPSBackupToZIP(ctx, artifact.Path, decryptedPath, passphrase); err != nil {
		t.Fatal(err)
	}
	contents := readVPSArchive(t, decryptedPath)
	for _, required := range []string{
		"manifest.json", "database/state.db", "config/config.yaml",
		"state/secrets/wireguard/server.key", "state/secrets/update/identity.key",
		"state/tls/cert.pem", "state/tls/key.pem",
	} {
		if _, exists := contents[required]; !exists {
			t.Fatalf("VPS backup is missing %s", required)
		}
	}
	var manifest Manifest
	if err := json.Unmarshal(contents["manifest.json"], &manifest); err != nil || manifest.Role != "vps" || len(manifest.Files) != len(contents)-1 {
		t.Fatalf("archived manifest = %+v, %v", manifest, err)
	}
	for _, record := range manifest.Files {
		content, exists := contents[record.Path]
		if !exists || int64(len(content)) != record.Bytes || sha256Hex(content) != record.SHA256 || record.Mode != 0o600 {
			t.Fatalf("invalid file record %+v", record)
		}
	}
	portableDatabase := filepath.Join(t.TempDir(), "portable.db")
	if err := os.WriteFile(portableDatabase, contents["database/state.db"], 0o600); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents["database/state.db"], []byte(ephemeral)) {
		t.Fatal("sanitized VPS database retained ephemeral secret bytes")
	}
	verified, err := vpsagent.Open(ctx, portableDatabase)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	for _, table := range []string{"sessions", "pairing_invitations", "events", "audit_events", "operations", "login_attempts"} {
		var count int
		if err := verified.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("portable table %s count = %d, %v", table, count, err)
		}
	}
	if identity, err := vpsagent.ReadIdentity(ctx, verified); err != nil || identity.VPSID != "vps:primary" {
		t.Fatalf("portable identity = %+v, %v", identity, err)
	}

	reader, err := manager.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	served, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(served, encrypted) {
		t.Fatal("managed VPS artifact download changed bytes")
	}
	if err := manager.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(artifact.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("served VPS artifact remains: %v", err)
	}
	_ = stateDirectory
}

func TestVPSBackupRejectsWrongPassphraseTamperingTruncationAndUnsafeSources(t *testing.T) {
	ctx := context.Background()
	manager, _, stateDirectory := vpsBackupFixture(t)
	passphrase := "correct horse battery staple"
	artifact, err := manager.Build(ctx, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		content    []byte
		passphrase string
	}{
		{name: "wrong passphrase", content: encrypted, passphrase: "wrong passphrase long enough"},
		{name: "tampered", content: mutateVPSBackup(encrypted), passphrase: passphrase},
		{name: "truncated", content: encrypted[:len(encrypted)-5], passphrase: passphrase},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.gvpn-vps")
			if err := os.WriteFile(path, test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(t.TempDir(), "plain.zip")
			if _, err := backup.DecryptVPSBackupToZIP(ctx, path, destination, test.passphrase); err == nil {
				t.Fatal("invalid VPS backup was accepted")
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("plaintext staging remains: %v", err)
			}
		})
	}
	if _, err := manager.Build(ctx, "short"); err == nil {
		t.Fatal("weak VPS backup passphrase was accepted")
	}

	target := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(stateDirectory, "secrets", "linked-secret")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := manager.Build(ctx, passphrase); err == nil {
		t.Fatal("symlinked VPS secret was accepted")
	}
}

func TestVPSBackupIncludesOnlyUndeliveredManagedAdministratorKeys(t *testing.T) {
	ctx := context.Background()
	manager, database, stateDirectory := vpsBackupFixture(t)
	repository := vpsagent.HubRepository{Database: database, Now: manager.Now}
	pairGatewayForBackup(t, repository)
	adminKeys, err := vpsagent.NewAdminKeyManager(database, stateDirectory, manager.Now)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := adminKeys.Create(ctx, "Ноутбук", "10.81.0.10")
	if err != nil {
		t.Fatal(err)
	}
	var reference string
	if err := database.QueryRowContext(ctx, "SELECT private_key_secret_ref FROM admin_peers WHERE id=?", admin.ID).Scan(&reference); err != nil {
		t.Fatal(err)
	}
	archivePath := "state/" + strings.TrimPrefix(reference, "/var/lib/gateway-vpn-vps/agent/")
	artifact, err := manager.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	decrypted := filepath.Join(t.TempDir(), "before-download.zip")
	if _, err := backup.DecryptVPSBackupToZIP(ctx, artifact.Path, decrypted, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, exists := readVPSArchive(t, decrypted)[archivePath]; !exists {
		t.Fatalf("undelivered managed administrator key %s is missing", archivePath)
	}
	if _, err := adminKeys.Export(ctx, admin.ID, "vps.example:51820"); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(stateDirectory, "secrets", "administrators", "peers", "managed-admin-orphan.key")
	if err := os.MkdirAll(filepath.Dir(orphan), 0o700); err != nil {
		t.Fatal(err)
	}
	orphanPair, _ := wgingress.GenerateKeyPair()
	if err := os.WriteFile(orphan, []byte(orphanPair.Private+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err = manager.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	decrypted = filepath.Join(t.TempDir(), "after-download.zip")
	if _, err := backup.DecryptVPSBackupToZIP(ctx, artifact.Path, decrypted, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	for path := range readVPSArchive(t, decrypted) {
		if strings.HasPrefix(path, "state/secrets/administrators/") {
			t.Fatalf("consumed or orphaned managed administrator key survived backup: %s", path)
		}
	}
}

func pairGatewayForBackup(t *testing.T, repository vpsagent.HubRepository) {
	t.Helper()
	bundle, err := repository.CreatePairing(context.Background(), vpsagent.PairingCreateInput{GatewayName: "Gateway", Endpoint: "vps.example:51820", Subnet: "10.82.0.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CompletePairing(context.Background(), vpsagent.PairingCompletion{InvitationID: bundle.InvitationID, Token: bundle.Token, SiteID: "site:backup", DisplayName: "Gateway", PublicKey: pair.Public}); err != nil {
		t.Fatal(err)
	}
}

func vpsBackupFixture(t *testing.T) (*Manager, *sql.DB, string) {
	t.Helper()
	ctx := context.Background()
	stateDirectory := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := vpsagent.Open(ctx, filepath.Join(stateDirectory, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	identity := vpsagent.IdentityInput{
		VPSID: "vps:primary", DisplayName: "Primary VPS",
		IdentityFingerprint: strings.Repeat("a", 64), PublicKey: pair.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key",
		UpdateIdentityRef:   "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}
	if _, err := vpsagent.InitializeIdentity(ctx, database, identity, time.Date(2026, 8, 30, 18, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	configurationPath := filepath.Join(t.TempDir(), "vps-agent.yaml")
	files := map[string]string{
		configurationPath: "version: 1\nlisten: 127.0.0.1:9443\n",
		filepath.Join(stateDirectory, "secrets", "wireguard", "server.key"): "vps-wireguard-private-secret",
		filepath.Join(stateDirectory, "secrets", "update", "identity.key"):  "vps-update-identity-secret",
		filepath.Join(stateDirectory, "tls", "cert.pem"):                    "vps-tls-certificate",
		filepath.Join(stateDirectory, "tls", "key.pem"):                     "vps-tls-private-secret",
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := NewManager(database, stateDirectory, configurationPath, "gateway-vpn-vps test")
	if err != nil {
		t.Fatal(err)
	}
	manager.Now = func() time.Time { return time.Date(2026, 8, 30, 18, 30, 0, 0, time.UTC) }
	return manager, database, stateDirectory
}

func readVPSArchive(t *testing.T, filename string) map[string][]byte {
	t.Helper()
	archive, err := zip.OpenReader(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	contents := make(map[string][]byte, len(archive.File))
	for _, item := range archive.File {
		if !safePath(item.Name) || item.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe VPS ZIP entry %q mode %o", item.Name, item.Mode().Perm())
		}
		reader, err := item.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(io.LimitReader(reader, backup.MaximumPortablePlainBytes+1))
		reader.Close()
		if err != nil || int64(len(content)) > backup.MaximumPortablePlainBytes {
			t.Fatalf("read VPS ZIP entry %q: %v", item.Name, err)
		}
		if _, exists := contents[item.Name]; exists {
			t.Fatalf("duplicate VPS ZIP entry %q", item.Name)
		}
		contents[item.Name] = content
	}
	return contents
}

func mutateVPSBackup(content []byte) []byte {
	result := append([]byte(nil), content...)
	result[len(result)-8] ^= 0x80
	return result
}
