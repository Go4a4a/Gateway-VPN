package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const MaximumDeployKeyBytes = 256

type DeployKeyState struct {
	State     string `json:"state"`
	PublicKey string `json:"public_key"`
}

type DeployFinalizeOptions struct {
	ConfigPath       string
	PendingKeyPath   string
	PeerPublicKey    string
	Endpoint         string
	KeepaliveSeconds int
	HandshakeSeconds int
}

// InspectDeployKey is strictly read-only. It supports deployment resume by
// exposing only the public identity of an existing configured or pending key.
func InspectDeployKey(configPath, pendingKeyPath string) (DeployKeyState, error) {
	if err := validateDeployPaths(configPath, pendingKeyPath); err != nil {
		return DeployKeyState{}, err
	}
	if _, err := os.Lstat(configPath); err == nil {
		configuration, loadErr := LoadConfig(configPath)
		if loadErr != nil {
			return DeployKeyState{}, errors.New("existing WireGuard config is unsafe or invalid")
		}
		publicKey, deriveErr := derivePublicKey(configuration.PrivateKey)
		if deriveErr != nil {
			return DeployKeyState{}, deriveErr
		}
		return DeployKeyState{State: "CONFIGURED", PublicKey: publicKey}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return DeployKeyState{}, errors.New("inspect existing WireGuard config failed")
	}
	privateKey, err := loadPendingDeployKey(pendingKeyPath)
	if errors.Is(err, os.ErrNotExist) {
		return DeployKeyState{State: "UNCONFIGURED"}, nil
	}
	if err != nil {
		return DeployKeyState{}, err
	}
	publicKey, err := derivePublicKey(privateKey)
	if err != nil {
		return DeployKeyState{}, err
	}
	return DeployKeyState{State: "PENDING", PublicKey: publicKey}, nil
}

// PrepareDeployKey returns an existing Gateway public key or creates a
// protected pending private key on the Gateway. The private key never leaves
// the host and is not returned to the caller.
func PrepareDeployKey(configPath, pendingKeyPath string) (DeployKeyState, error) {
	if err := validateDeployPaths(configPath, pendingKeyPath); err != nil {
		return DeployKeyState{}, err
	}
	if _, err := os.Lstat(configPath); err == nil {
		configuration, loadErr := LoadConfig(configPath)
		if loadErr != nil {
			return DeployKeyState{}, errors.New("existing WireGuard config is unsafe or invalid")
		}
		publicKey, deriveErr := derivePublicKey(configuration.PrivateKey)
		if deriveErr != nil {
			return DeployKeyState{}, deriveErr
		}
		return DeployKeyState{State: "CONFIGURED", PublicKey: publicKey}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return DeployKeyState{}, errors.New("inspect existing WireGuard config failed")
	}

	privateKey, err := loadPendingDeployKey(pendingKeyPath)
	if errors.Is(err, os.ErrNotExist) {
		privateKey, err = createPendingDeployKey(pendingKeyPath)
		if errors.Is(err, os.ErrExist) {
			privateKey, err = loadPendingDeployKey(pendingKeyPath)
		}
	}
	if err != nil {
		return DeployKeyState{}, err
	}
	publicKey, err := derivePublicKey(privateKey)
	if err != nil {
		return DeployKeyState{}, err
	}
	return DeployKeyState{State: "PENDING", PublicKey: publicKey}, nil
}

// FinalizeDeployKey atomically creates wireguard.yaml from the local pending
// key. Existing configuration is accepted only when it is exactly compatible;
// deploy never silently rotates or overwrites operator-owned key material.
func FinalizeDeployKey(options DeployFinalizeOptions) (DeployKeyState, error) {
	if err := validateDeployPaths(options.ConfigPath, options.PendingKeyPath); err != nil {
		return DeployKeyState{}, err
	}
	desired := Config{
		InterfaceName: "wg-mgmt", Address: "10.80.0.2/32",
		PeerPublicKey: options.PeerPublicKey, Endpoint: options.Endpoint,
		AllowedIPs: []string{"10.80.0.0/24"}, PersistentKeepalive: options.KeepaliveSeconds,
		HandshakeTimeout: options.HandshakeSeconds,
	}
	if _, err := os.Lstat(options.ConfigPath); err == nil {
		existing, loadErr := LoadConfig(options.ConfigPath)
		if loadErr != nil {
			return DeployKeyState{}, errors.New("existing WireGuard config is unsafe or invalid")
		}
		desired.PrivateKey = existing.PrivateKey
		if err := ValidateConfig(desired); err != nil || !sameConfig(existing, desired) {
			return DeployKeyState{}, errors.New("existing WireGuard config differs from the requested deployment")
		}
		publicKey, deriveErr := derivePublicKey(existing.PrivateKey)
		if deriveErr != nil {
			return DeployKeyState{}, deriveErr
		}
		if removeErr := removePendingDeployKey(options.PendingKeyPath); removeErr != nil {
			return DeployKeyState{}, removeErr
		}
		return DeployKeyState{State: "CONFIGURED", PublicKey: publicKey}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return DeployKeyState{}, errors.New("inspect existing WireGuard config failed")
	}

	privateKey, err := loadPendingDeployKey(options.PendingKeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DeployKeyState{}, errors.New("pending Gateway WireGuard key is missing")
		}
		return DeployKeyState{}, err
	}
	desired.PrivateKey = privateKey
	if err := SaveConfig(options.ConfigPath, desired); err != nil {
		return DeployKeyState{}, err
	}
	publicKey, err := derivePublicKey(privateKey)
	if err != nil {
		return DeployKeyState{}, err
	}
	if err := removePendingDeployKey(options.PendingKeyPath); err != nil {
		return DeployKeyState{}, err
	}
	return DeployKeyState{State: "CONFIGURED", PublicKey: publicKey}, nil
}

func validateDeployPaths(configPath, pendingKeyPath string) error {
	if !filepath.IsAbs(configPath) || !filepath.IsAbs(pendingKeyPath) || filepath.Dir(configPath) != filepath.Dir(pendingKeyPath) || configPath == pendingKeyPath {
		return errors.New("absolute distinct deploy key paths in one secrets directory are required")
	}
	directoryInfo, err := os.Lstat(filepath.Dir(configPath))
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return errors.New("deploy secrets directory must be a real existing directory")
	}
	if runtime.GOOS != "windows" && directoryInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("deploy secrets directory permissions are too broad")
	}
	return nil
}

func createPendingDeployKey(filename string) (string, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", errors.New("generate Gateway WireGuard private key failed")
	}
	encoded := base64.StdEncoding.EncodeToString(privateKey.Bytes()) + "\n"
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	written, writeErr := io.WriteString(file, encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(encoded) {
		_ = os.Remove(filename)
		return "", errors.New("durably write pending Gateway WireGuard key failed")
	}
	if err := syncDeployDirectory(filepath.Dir(filename)); err != nil {
		_ = os.Remove(filename)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(privateKey.Bytes()), nil
}

func loadPendingDeployKey(filename string) (string, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaximumDeployKeyBytes || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return "", errors.New("pending Gateway WireGuard key is unsafe")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", errors.New("read pending Gateway WireGuard key failed")
	}
	privateKey := string(content)
	for len(privateKey) > 0 && (privateKey[len(privateKey)-1] == '\n' || privateKey[len(privateKey)-1] == '\r') {
		privateKey = privateKey[:len(privateKey)-1]
	}
	if !validKey(privateKey) {
		return "", errors.New("pending Gateway WireGuard key is invalid")
	}
	return privateKey, nil
}

func removePendingDeployKey(filename string) error {
	if _, err := os.Lstat(filename); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("inspect pending Gateway WireGuard key failed")
	}
	if _, err := loadPendingDeployKey(filename); err != nil {
		return err
	}
	if err := os.Remove(filename); err != nil {
		return errors.New("remove pending Gateway WireGuard key failed")
	}
	return syncDeployDirectory(filepath.Dir(filename))
}

func derivePublicKey(encodedPrivateKey string) (string, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(encodedPrivateKey)
	if err != nil || len(raw) != 32 {
		return "", errors.New("Gateway WireGuard private key is invalid")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", errors.New("derive Gateway WireGuard public key failed")
	}
	return base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()), nil
}

func syncDeployDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return errors.New("open deploy secrets directory for sync failed")
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return errors.New("sync deploy secrets directory failed")
	}
	return nil
}

func sameConfig(left, right Config) bool {
	return left.InterfaceName == right.InterfaceName && left.Address == right.Address &&
		left.PrivateKey == right.PrivateKey && left.PeerPublicKey == right.PeerPublicKey &&
		left.Endpoint == right.Endpoint && len(left.AllowedIPs) == 1 && len(right.AllowedIPs) == 1 &&
		left.AllowedIPs[0] == right.AllowedIPs[0] && left.PersistentKeepalive == right.PersistentKeepalive &&
		left.HandshakeTimeout == right.HandshakeTimeout
}
