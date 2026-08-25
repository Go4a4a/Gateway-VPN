package bootstrap

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const modemIdentitySaltFilename = "modem-identity-salt"

func EnsureModemIdentitySalt(stateDirectory string) ([]byte, error) {
	filename := filepath.Join(stateDirectory, "secrets", modemIdentitySaltFilename)
	salt, err := readModemIdentitySalt(filename)
	if err == nil {
		return salt, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	raw := make([]byte, 48)
	if _, err := rand.Read(raw); err != nil {
		return nil, errors.New("generate modem identity salt failed")
	}
	encoded := base64.RawStdEncoding.EncodeToString(raw)
	if err := writeSecretAtomic(filename, []byte(encoded+"\n")); err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

func readModemIdentitySalt(filename string) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 32 || info.Size() > 256 {
		return nil, errors.New("modem identity salt must be a bounded regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("modem identity salt permissions are too broad")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	encoded := strings.TrimSpace(string(content))
	raw, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != 48 {
		return nil, errors.New("modem identity salt is invalid")
	}
	return []byte(encoded), nil
}
