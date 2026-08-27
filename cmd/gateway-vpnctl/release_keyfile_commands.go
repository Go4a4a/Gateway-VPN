package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	updatepkg "gateway-vpn/internal/update"
)

func runReleaseKeyfileCreate(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl release-keyfile-create", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	keyFile := flags.String("key-file", "", "new encrypted .gvkey release key file")
	passphraseFile := flags.String("passphrase-file", "", "absolute 0600 passphrase file; use - for bounded stdin")
	jsonOutput := flags.Bool("json", false, "emit bounded JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *keyFile == "" || *passphraseFile == "" {
		return 2
	}
	if !requireTrustedLinuxKeyOperation() {
		return 1
	}
	passphrase, err := readReleaseKeyPassphrase(*passphraseFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read encrypted release key passphrase failed")
		return 1
	}
	defer clearSecret(passphrase)
	info, err := updatepkg.CreateEncryptedKeyFile(*keyFile, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create encrypted release signing identity: %v\n", err)
		return 1
	}
	writeEncryptedKeyInfo(info, *jsonOutput, "created")
	return 0
}

func runReleaseKeyfileVerify(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl release-keyfile-verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	keyFile := flags.String("key-file", "", "encrypted .gvkey release key file")
	passphraseFile := flags.String("passphrase-file", "", "absolute 0600 passphrase file; use - for bounded stdin")
	jsonOutput := flags.Bool("json", false, "emit bounded JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *keyFile == "" || *passphraseFile == "" {
		return 2
	}
	if !requireTrustedLinuxKeyOperation() {
		return 1
	}
	passphrase, err := readReleaseKeyPassphrase(*passphraseFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read encrypted release key passphrase failed")
		return 1
	}
	defer clearSecret(passphrase)
	info, err := updatepkg.VerifyEncryptedKeyFile(*keyFile, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify encrypted release signing identity failed")
		return 1
	}
	writeEncryptedKeyInfo(info, *jsonOutput, "verified")
	return 0
}

func runReleaseKeyfileBackup(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl release-keyfile-backup", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	keyFile := flags.String("key-file", "", "source encrypted .gvkey release key file")
	backupKeyFile := flags.String("backup-key-file", "", "new encrypted .gvkey backup file in another directory")
	passphraseFile := flags.String("passphrase-file", "", "absolute 0600 passphrase file; use - for bounded stdin")
	jsonOutput := flags.Bool("json", false, "emit bounded JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *keyFile == "" || *backupKeyFile == "" || *passphraseFile == "" {
		return 2
	}
	if !requireTrustedLinuxKeyOperation() {
		return 1
	}
	passphrase, err := readReleaseKeyPassphrase(*passphraseFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read encrypted release key passphrase failed")
		return 1
	}
	defer clearSecret(passphrase)
	info, err := updatepkg.BackupEncryptedKeyFile(*keyFile, *backupKeyFile, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup encrypted release signing identity failed")
		return 1
	}
	writeEncryptedKeyInfo(info, *jsonOutput, "backup_verified")
	return 0
}

func runReleaseKeyfileUnlock(args []string) int {
	flags := flag.NewFlagSet("gateway-vpnctl release-keyfile-unlock", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	keyFile := flags.String("key-file", "", "encrypted .gvkey release key file")
	passphraseFile := flags.String("passphrase-file", "", "absolute 0600 passphrase file; use - for bounded stdin")
	privateKey := flags.String("private-key", "", "new temporary PKCS#8 Ed25519 private key path")
	publicKey := flags.String("public-key", "", "new temporary PKIX Ed25519 public key path")
	jsonOutput := flags.Bool("json", false, "emit bounded JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *keyFile == "" || *passphraseFile == "" || *privateKey == "" || *publicKey == "" {
		return 2
	}
	if !requireTrustedLinuxKeyOperation() {
		return 1
	}
	passphrase, err := readReleaseKeyPassphrase(*passphraseFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read encrypted release key passphrase failed")
		return 1
	}
	defer clearSecret(passphrase)
	fingerprint, err := updatepkg.UnlockEncryptedKeyFile(*keyFile, passphrase, *privateKey, *publicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unlock encrypted release signing identity failed")
		return 1
	}
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"signer_key_sha256": fingerprint, "unlocked": true})
	} else {
		fmt.Printf("Encrypted Ed25519 release signing identity unlocked in temporary secure storage; public key SHA-256=%s\n", fingerprint)
	}
	return 0
}

func writeEncryptedKeyInfo(info updatepkg.EncryptedKeyFileInfo, jsonOutput bool, state string) {
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"signer_key_sha256": info.Fingerprint,
			"file_sha256":       info.SHA256,
			"bytes":             info.Bytes,
			state:               true,
		})
		return
	}
	fmt.Printf("Encrypted Ed25519 release signing identity %s; public key SHA-256=%s file SHA-256=%s bytes=%d\n", state, info.Fingerprint, info.SHA256, info.Bytes)
}

func readReleaseKeyPassphrase(source string) ([]byte, error) {
	const maximumInputBytes = 258
	var raw []byte
	var err error
	if source == "-" {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, maximumInputBytes+1))
	} else {
		if !filepath.IsAbs(source) {
			return nil, errors.New("absolute passphrase file path is required")
		}
		source = filepath.Clean(source)
		info, statErr := os.Lstat(source)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumInputBytes {
			return nil, errors.New("passphrase source must be a bounded regular non-symlink file")
		}
		if runtime.GOOS != "windows" {
			resolved, resolveErr := filepath.EvalSymlinks(source)
			if resolveErr != nil || resolved != source || info.Mode().Perm()&0o077 != 0 {
				return nil, errors.New("passphrase file must use a real private path and mode 0600")
			}
			parentInfo, parentErr := os.Lstat(filepath.Dir(source))
			if parentErr != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0 {
				return nil, errors.New("passphrase file parent directory must not be accessible to group or others")
			}
		}
		raw, err = os.ReadFile(source)
	}
	if err != nil || len(raw) == 0 || len(raw) > maximumInputBytes {
		clearSecret(raw)
		return nil, errors.New("read bounded passphrase failed")
	}
	defer clearSecret(raw)
	content := raw
	content = bytes.TrimSuffix(content, []byte{'\n'})
	content = bytes.TrimSuffix(content, []byte{'\r'})
	if err := updatepkg.ValidateEncryptedKeyPassphrase(content); err != nil {
		return nil, err
	}
	return append([]byte(nil), content...), nil
}

func clearSecret(content []byte) {
	for index := range content {
		content[index] = 0
	}
}
