package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	updatepkg "gateway-vpn/internal/update"
)

func TestEncryptedKeyfileCommandsOnTrustedLinuxHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("encrypted private-key CLI operations are intentionally Linux-only")
	}
	primaryDirectory := commandSecureDirectory(t)
	backupDirectory := commandSecureDirectory(t)
	unlockDirectory := commandSecureDirectory(t)
	passphraseDirectory := commandSecureDirectory(t)
	passphraseFile := filepath.Join(passphraseDirectory, "passphrase")
	passphrase := []byte("six calm words protect this signing identity")
	if err := os.WriteFile(passphraseFile, passphrase, 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(primaryDirectory, "production.gvkey")
	backupFile := filepath.Join(backupDirectory, "production.gvkey")
	if code := runReleaseKeyfileCreate([]string{"--key-file", keyFile, "--passphrase-file", passphraseFile, "--json"}); code != 0 {
		t.Fatalf("release-keyfile-create code=%d", code)
	}
	if code := runReleaseKeyfileVerify([]string{"--key-file", keyFile, "--passphrase-file", passphraseFile, "--json"}); code != 0 {
		t.Fatalf("release-keyfile-verify code=%d", code)
	}
	if code := runReleaseKeyfileBackup([]string{"--key-file", keyFile, "--backup-key-file", backupFile, "--passphrase-file", passphraseFile, "--json"}); code != 0 {
		t.Fatalf("release-keyfile-backup code=%d", code)
	}
	if code := runReleaseKeyfileBackup([]string{"--key-file", keyFile, "--backup-key-file", backupFile, "--passphrase-file", passphraseFile}); code != 1 {
		t.Fatalf("repeat release-keyfile-backup code=%d want=1", code)
	}
	privateKey := filepath.Join(unlockDirectory, "release-signing.pem")
	publicKey := filepath.Join(unlockDirectory, "update-signing.pub")
	if code := runReleaseKeyfileUnlock([]string{"--key-file", backupFile, "--private-key", privateKey, "--public-key", publicKey, "--passphrase-file", passphraseFile, "--json"}); code != 0 {
		t.Fatalf("release-keyfile-unlock code=%d", code)
	}
	if fingerprint, err := updatepkg.VerifyKeyPair(privateKey, publicKey); err != nil || fingerprint == "" {
		t.Fatalf("unlocked CLI key pair fingerprint=%q err=%v", fingerprint, err)
	}

	wrongPassphraseFile := filepath.Join(passphraseDirectory, "wrong-passphrase")
	if err := os.WriteFile(wrongPassphraseFile, []byte("different strong passphrase for this identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runReleaseKeyfileVerify([]string{"--key-file", keyFile, "--passphrase-file", wrongPassphraseFile}); code != 1 {
		t.Fatalf("wrong-passphrase verify code=%d want=1", code)
	}
	if err := os.Chmod(passphraseFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := runReleaseKeyfileVerify([]string{"--key-file", keyFile, "--passphrase-file", passphraseFile}); code != 1 {
		t.Fatalf("insecure passphrase-file verify code=%d want=1", code)
	}
}

func commandSecureDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
