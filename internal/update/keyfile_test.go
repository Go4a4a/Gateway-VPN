package update

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEncryptedKeyFileCreateVerifyBackupAndUnlock(t *testing.T) {
	passphrase := []byte("six calm words protect this signing identity")
	primaryDirectory := secureTestDirectory(t)
	backupDirectory := secureTestDirectory(t)
	primary := filepath.Join(primaryDirectory, "gateway-vpn-production.gvkey")
	created, err := CreateEncryptedKeyFile(primary, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if created.Fingerprint == "" || len(created.SHA256) != 64 || created.Bytes <= 0 || created.Bytes > MaximumEncryptedKeyFileBytes {
		t.Fatalf("created encrypted key info = %+v", created)
	}
	verified, err := VerifyEncryptedKeyFile(primary, passphrase)
	if err != nil || verified != created {
		t.Fatalf("VerifyEncryptedKeyFile() = %+v err=%v want=%+v", verified, err, created)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(primary)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("encrypted key mode=%v err=%v", info.Mode().Perm(), err)
		}
	}

	backup := filepath.Join(backupDirectory, "gateway-vpn-production.gvkey")
	backedUp, err := BackupEncryptedKeyFile(primary, backup, passphrase)
	if err != nil || backedUp != created {
		t.Fatalf("BackupEncryptedKeyFile() = %+v err=%v want=%+v", backedUp, err, created)
	}
	primaryContent, err := os.ReadFile(primary)
	if err != nil {
		t.Fatal(err)
	}
	backupContent, err := os.ReadFile(backup)
	if err != nil || !bytes.Equal(primaryContent, backupContent) {
		t.Fatalf("encrypted backup differs err=%v", err)
	}
	if bytes.Contains(primaryContent, passphrase) || bytes.Contains(primaryContent, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("encrypted key file contains plaintext passphrase or PEM marker")
	}
	if _, err := BackupEncryptedKeyFile(primary, backup, passphrase); err == nil {
		t.Fatal("existing encrypted key backup was overwritten")
	}
	afterRepeat, err := os.ReadFile(backup)
	if err != nil || !bytes.Equal(backupContent, afterRepeat) {
		t.Fatal("failed repeat backup changed the existing encrypted key file")
	}

	unlockDirectory := secureTestDirectory(t)
	privatePath := filepath.Join(unlockDirectory, "release-signing.pem")
	publicPath := filepath.Join(unlockDirectory, "update-signing.pub")
	fingerprint, err := UnlockEncryptedKeyFile(primary, passphrase, privatePath, publicPath)
	if err != nil || fingerprint != created.Fingerprint {
		t.Fatalf("UnlockEncryptedKeyFile() fingerprint=%q err=%v", fingerprint, err)
	}
	if verifiedFingerprint, err := VerifyKeyPair(privatePath, publicPath); err != nil || verifiedFingerprint != fingerprint {
		t.Fatalf("unlocked key pair fingerprint=%q err=%v", verifiedFingerprint, err)
	}
	privatePEM, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(primaryContent, privatePEM) {
		t.Fatal("encrypted key file contains the unlocked private key")
	}
	if _, err := UnlockEncryptedKeyFile(primary, passphrase, privatePath, publicPath); err == nil {
		t.Fatal("unlock overwrote an existing temporary key pair")
	}
}

func TestEncryptedKeyFileRejectsWrongPassphraseTamperAndUnsafePaths(t *testing.T) {
	passphrase := []byte("six calm words protect this signing identity")
	directory := secureTestDirectory(t)
	primary := filepath.Join(directory, "production.gvkey")
	created, err := CreateEncryptedKeyFile(primary, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	wrongPassphrase := []byte("different strong passphrase for this identity")
	if _, err := VerifyEncryptedKeyFile(primary, wrongPassphrase); err == nil {
		t.Fatal("wrong encrypted-key passphrase was accepted")
	}
	if _, err := CreateEncryptedKeyFile(filepath.Join(directory, "weak.gvkey"), []byte("too short")); err == nil {
		t.Fatal("weak encrypted-key passphrase was accepted")
	}
	if _, err := CreateEncryptedKeyFile(filepath.Join(directory, "wrong.pem"), passphrase); err == nil {
		t.Fatal("encrypted key destination without .gvkey extension was accepted")
	}
	if _, err := CreateEncryptedKeyFile("relative.gvkey", passphrase); err == nil {
		t.Fatal("relative encrypted key destination was accepted")
	}
	if _, err := CreateEncryptedKeyFile(primary, passphrase); err == nil {
		t.Fatal("existing encrypted key file was overwritten")
	}

	content, err := os.ReadFile(primary)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), content...)
	tampered[len(tampered)-1] ^= 0x80
	tamperedPath := filepath.Join(directory, "tampered.gvkey")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEncryptedKeyFile(tamperedPath, passphrase); err == nil {
		t.Fatal("tampered encrypted key file was accepted")
	}
	truncatedPath := filepath.Join(directory, "truncated.gvkey")
	if err := os.WriteFile(truncatedPath, content[:len(content)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEncryptedKeyFile(truncatedPath, passphrase); err == nil {
		t.Fatal("truncated encrypted key file was accepted")
	}

	headerTampered := tamperEncryptedKeyHeader(t, content, func(header *encryptedKeyHeader) {
		header.KDFMemoryKiB = ^uint32(0)
	})
	headerPath := filepath.Join(directory, "hostile-kdf.gvkey")
	if err := os.WriteFile(headerPath, headerTampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEncryptedKeyFile(headerPath, passphrase); err == nil {
		t.Fatal("encrypted key file with attacker-controlled KDF cost was accepted")
	}

	sameDirectoryBackup := filepath.Join(directory, "backup.gvkey")
	if _, err := BackupEncryptedKeyFile(primary, sameDirectoryBackup, passphrase); err == nil {
		t.Fatal("same-directory encrypted backup was accepted")
	}
	wrongBackupDirectory := secureTestDirectory(t)
	wrongBackup := filepath.Join(wrongBackupDirectory, "backup.gvkey")
	if _, err := BackupEncryptedKeyFile(primary, wrongBackup, wrongPassphrase); err == nil {
		t.Fatal("encrypted backup accepted a wrong passphrase")
	}
	if _, err := os.Stat(wrongBackup); !os.IsNotExist(err) {
		t.Fatalf("failed encrypted backup left destination err=%v", err)
	}

	gitRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(gitRoot, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateEncryptedKeyFile(filepath.Join(gitRoot, "inside.gvkey"), passphrase); err == nil {
		t.Fatal("encrypted key file inside Git worktree was accepted")
	}
	if runtime.GOOS != "windows" {
		symlinkRoot := t.TempDir()
		alias := filepath.Join(symlinkRoot, "alias")
		if err := os.Symlink(directory, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyEncryptedKeyFile(filepath.Join(alias, filepath.Base(primary)), passphrase); err == nil {
			t.Fatal("symlinked encrypted key path was accepted")
		}
	}
	if created.Fingerprint == "" {
		t.Fatal("created fingerprint is empty")
	}
}

func TestValidateEncryptedKeyPassphrase(t *testing.T) {
	for _, invalid := range [][]byte{
		nil,
		[]byte("too short"),
		[]byte("123456789"),
		[]byte("пароль123"),
		[]byte(" leading whitespace passphrase"),
		[]byte("trailing whitespace passphrase "),
		[]byte("valid length but\nline break"),
		append([]byte("valid length prefix"), 0),
		bytes.Repeat([]byte{'x'}, 257),
		{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0xef, 0xee, 0xed, 0xec},
	} {
		if err := ValidateEncryptedKeyPassphrase(invalid); err == nil {
			t.Fatalf("invalid passphrase %q was accepted", invalid)
		}
	}
	if err := ValidateEncryptedKeyPassphrase([]byte("correct horse battery staple")); err != nil {
		t.Fatalf("valid passphrase rejected: %v", err)
	}
	if err := ValidateEncryptedKeyPassphrase([]byte("1234567890")); err != nil {
		t.Fatalf("ten-character passphrase rejected: %v", err)
	}
	if err := ValidateEncryptedKeyPassphrase([]byte("пароль1234")); err != nil {
		t.Fatalf("ten-character Unicode passphrase rejected: %v", err)
	}
}

func secureTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func tamperEncryptedKeyHeader(t *testing.T, content []byte, mutate func(*encryptedKeyHeader)) []byte {
	t.Helper()
	headerOffset := len(encryptedKeyMagic) + 4
	if len(content) <= headerOffset {
		t.Fatal("encrypted key fixture is too short")
	}
	headerLength := int(binary.BigEndian.Uint32(content[len(encryptedKeyMagic):headerOffset]))
	if headerLength <= 0 || headerOffset+headerLength >= len(content) {
		t.Fatal("encrypted key fixture header is invalid")
	}
	var header encryptedKeyHeader
	if err := json.Unmarshal(content[headerOffset:headerOffset+headerLength], &header); err != nil {
		t.Fatal(err)
	}
	mutate(&header)
	headerContent, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	result := append([]byte(nil), encryptedKeyMagic[:]...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(headerContent)))
	result = append(result, length...)
	result = append(result, headerContent...)
	result = append(result, content[headerOffset+headerLength:]...)
	return result
}
