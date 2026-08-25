package subscription

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"go.yaml.in/yaml/v3"
)

const normalizedPayloadFilename = "payload.yaml"

// WriteNormalizedPayload writes an immutable, sanitized Clash payload. Proxy
// credentials remain outside SQLite and are protected with directory 0700 and
// file 0600 permissions.
func WriteNormalizedPayload(root, subscriptionID, versionID string, imported ImportResult) (string, error) {
	if root == "" || !safePayloadSegment(subscriptionID) || !safePayloadSegment(versionID) || len(imported.Nodes) == 0 {
		return "", errors.New("payload root, safe subscription/version ids, and nodes are required")
	}
	payload := struct {
		Proxies []map[string]any `yaml:"proxies"`
	}{Proxies: make([]map[string]any, 0, len(imported.Nodes))}
	for _, node := range imported.Nodes {
		if len(node.Config) == 0 {
			return "", errors.New("normalized node config is empty")
		}
		payload.Proxies = append(payload.Proxies, cloneProxyConfig(node.Config))
	}
	encoded, err := yaml.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode normalized subscription payload: %w", err)
	}
	if len(encoded) > MaxPayloadBytes {
		return "", errors.New("normalized subscription payload exceeds size limit")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create subscription payload root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", fmt.Errorf("secure subscription payload root: %w", err)
	}
	subscriptionDirectory := filepath.Join(root, subscriptionID)
	if err := os.MkdirAll(subscriptionDirectory, 0o700); err != nil {
		return "", fmt.Errorf("create subscription payload directory: %w", err)
	}
	if err := os.Chmod(subscriptionDirectory, 0o700); err != nil {
		return "", fmt.Errorf("secure subscription payload directory: %w", err)
	}
	destination := filepath.Join(subscriptionDirectory, versionID)
	if _, err := os.Lstat(destination); err == nil {
		return "", errors.New("subscription payload version already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect subscription payload destination: %w", err)
	}
	temporary, err := os.MkdirTemp(subscriptionDirectory, ".payload-")
	if err != nil {
		return "", fmt.Errorf("create temporary subscription payload: %w", err)
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return "", fmt.Errorf("secure temporary subscription payload: %w", err)
	}
	filename := filepath.Join(temporary, normalizedPayloadFilename)
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create normalized subscription payload: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		return "", fmt.Errorf("write normalized subscription payload: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", fmt.Errorf("sync normalized subscription payload: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close normalized subscription payload: %w", err)
	}
	if err := syncPayloadDirectory(temporary); err != nil {
		return "", fmt.Errorf("sync temporary subscription payload directory: %w", err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return "", fmt.Errorf("publish normalized subscription payload: %w", err)
	}
	if err := syncPayloadDirectory(subscriptionDirectory); err != nil {
		return "", fmt.Errorf("sync subscription payload directory: %w", err)
	}
	return filepath.Join(destination, normalizedPayloadFilename), nil
}

func LoadNormalizedPayload(root, subscriptionID, versionID string) (ImportResult, error) {
	content, err := readNormalizedPayload(root, subscriptionID, versionID)
	if err != nil {
		return ImportResult{}, err
	}
	result, err := Import(content)
	if err != nil {
		return ImportResult{}, fmt.Errorf("validate stored normalized subscription payload: %w", err)
	}
	return result, nil
}

func readNormalizedPayload(root, subscriptionID, versionID string) ([]byte, error) {
	if root == "" || !safePayloadSegment(subscriptionID) || !safePayloadSegment(versionID) {
		return nil, errors.New("payload root and safe subscription/version ids are required")
	}
	filename := filepath.Join(root, subscriptionID, versionID, normalizedPayloadFilename)
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, fmt.Errorf("inspect normalized subscription payload: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("normalized subscription payload must be a regular non-symlink file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open normalized subscription payload: %w", err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, MaxPayloadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read normalized subscription payload: %w", err)
	}
	if len(content) > MaxPayloadBytes {
		return nil, errors.New("normalized subscription payload exceeds size limit")
	}
	return content, nil
}

func DeleteSubscriptionPayloads(root, subscriptionID string) error {
	if root == "" || !safePayloadSegment(subscriptionID) {
		return errors.New("payload root and safe subscription id are required")
	}
	destination := filepath.Join(root, subscriptionID)
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("subscription payload directory is unsafe")
	}
	if err := os.RemoveAll(destination); err != nil {
		return fmt.Errorf("delete subscription payload directory: %w", err)
	}
	return syncPayloadDirectory(root)
}

func safePayloadSegment(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		if !strings.ContainsRune("._-", char) {
			return false
		}
	}
	return true
}

func cloneProxyConfig(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func syncPayloadDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
