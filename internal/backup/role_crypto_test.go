package backup

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVPSAndGatewayEncryptedBackupRolesCannotBeCrossRestored(t *testing.T) {
	passphrase := "correct horse battery staple"
	vpsPath := filepath.Join(t.TempDir(), "settings.gvpn-vps")
	file, err := os.OpenFile(vpsPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := NewVPSArchiveEncryptWriter(file, passphrase)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	archive := zip.NewWriter(encrypted)
	entry, err := archive.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(`{"role":"vps"}`)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	vpsZIP := filepath.Join(t.TempDir(), "vps.zip")
	if _, err := DecryptVPSBackupToZIP(context.Background(), vpsPath, vpsZIP, passphrase); err != nil {
		t.Fatalf("VPS role decrypt failed: %v", err)
	}
	wrongGatewayZIP := filepath.Join(t.TempDir(), "wrong-gateway.zip")
	if _, err := DecryptToZIP(context.Background(), vpsPath, wrongGatewayZIP, passphrase); err == nil {
		t.Fatal("VPS backup was accepted by Gateway decryptor")
	}
	if _, err := os.Stat(wrongGatewayZIP); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cross-role Gateway plaintext remains: %v", err)
	}

	// Rebuild a minimal Gateway stream through the existing writer to prove
	// the inverse role boundary without depending on a full system fixture.
	gatewayPath := filepath.Join(t.TempDir(), "settings.gvpn")
	gatewayFile, err := os.OpenFile(gatewayPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	gatewayEncrypted, err := newChunkEncryptWriter(gatewayFile, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gatewayEncrypted.Write([]byte(strings.Repeat("G", 64))); err != nil {
		t.Fatal(err)
	}
	if err := gatewayEncrypted.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gatewayFile.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := gatewayFile.Close(); err != nil {
		t.Fatal(err)
	}
	wrongVPSZIP := filepath.Join(t.TempDir(), "wrong-vps.zip")
	if _, err := DecryptVPSBackupToZIP(context.Background(), gatewayPath, wrongVPSZIP, passphrase); err == nil {
		t.Fatal("Gateway backup was accepted by VPS decryptor")
	}
	if _, err := os.Stat(wrongVPSZIP); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cross-role VPS plaintext remains: %v", err)
	}
}
