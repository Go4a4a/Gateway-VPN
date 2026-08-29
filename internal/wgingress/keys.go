package wgingress

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type KeyPair struct {
	Private string
	Public  string
}

type KeyStore struct {
	Root string
}

func GenerateKeyPair() (KeyPair, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, errors.New("generate WireGuard X25519 key failed")
	}
	return KeyPair{
		Private: base64.StdEncoding.EncodeToString(private.Bytes()),
		Public:  base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()),
	}, nil
}

func GeneratePresharedKey() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate WireGuard preshared key failed")
	}
	return base64.StdEncoding.EncodeToString(value), nil
}

func ValidKey(value string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
	return err == nil && len(decoded) == 32
}

func PublicKey(private string) (string, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(private))
	if err != nil || len(raw) != 32 {
		return "", errors.New("WireGuard private key is invalid")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", errors.New("derive WireGuard public key failed")
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func (store KeyStore) ServerPrivatePath(serverID string) (string, error) {
	if !safeIdentifier.MatchString(serverID) {
		return "", errors.New("safe WireGuard server id is required")
	}
	return store.path("servers", serverID+".key")
}

func (store KeyStore) PeerPrivatePath(peerID string) (string, error) {
	if !safeIdentifier.MatchString(peerID) {
		return "", errors.New("safe WireGuard peer id is required")
	}
	return store.path("peers", peerID+".key")
}

func (store KeyStore) PeerPresharedPath(peerID string) (string, error) {
	if !safeIdentifier.MatchString(peerID) {
		return "", errors.New("safe WireGuard peer id is required")
	}
	return store.path("peers", peerID+".psk")
}

func (store KeyStore) Write(path, key string) error {
	if !ValidKey(key) {
		return errors.New("valid WireGuard key is required")
	}
	if err := store.validateOwnedPath(path); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := secureDirectory(directory); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("WireGuard secret destination has an unsafe type")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect WireGuard secret destination failed")
	}
	temporary, err := os.CreateTemp(directory, ".wireguard-secret-*.tmp")
	if err != nil {
		return errors.New("create temporary WireGuard secret failed")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("protect temporary WireGuard secret failed")
	}
	if _, err := temporary.WriteString(strings.TrimSpace(key) + "\n"); err != nil {
		temporary.Close()
		return errors.New("write temporary WireGuard secret failed")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync temporary WireGuard secret failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close temporary WireGuard secret failed")
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return errors.New("activate WireGuard secret failed")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return errors.New("protect WireGuard secret failed")
	}
	return syncDirectory(directory)
}

func (store KeyStore) Read(path string) (string, error) {
	if err := store.validateOwnedPath(path); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128 {
		return "", errors.New("WireGuard secret must be a bounded regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return "", errors.New("WireGuard secret permissions must be 0600")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("read WireGuard secret failed")
	}
	value := strings.TrimSpace(string(content))
	if !ValidKey(value) {
		return "", errors.New("stored WireGuard secret is invalid")
	}
	return value, nil
}

func (store KeyStore) Remove(path string) error {
	if err := store.validateOwnedPath(path); err != nil {
		return err
	}
	if _, err := store.Read(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(path); err != nil {
		return errors.New("remove WireGuard secret failed")
	}
	return syncDirectory(filepath.Dir(path))
}

func (store KeyStore) path(kind, name string) (string, error) {
	if !filepath.IsAbs(store.Root) {
		return "", errors.New("absolute WireGuard ingress secret root is required")
	}
	return filepath.Join(filepath.Clean(store.Root), kind, name), nil
}

func (store KeyStore) validateOwnedPath(path string) error {
	if !filepath.IsAbs(store.Root) || !filepath.IsAbs(path) {
		return errors.New("absolute WireGuard secret root and path are required")
	}
	root := filepath.Clean(store.Root)
	clean := filepath.Clean(path)
	relative, err := filepath.Rel(root, clean)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("WireGuard secret path escapes the fixed root")
	}
	return nil
}

func secureDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("create WireGuard secret directory failed")
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("WireGuard secret directory has an unsafe type")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return errors.New("protect WireGuard secret directory failed")
	}
	return nil
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open WireGuard secret directory for sync: %w", err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return errors.New("sync WireGuard secret directory failed")
	}
	return nil
}
