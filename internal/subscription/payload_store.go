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

type PayloadRef struct {
	SubscriptionID string
	VersionID      string
}

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

// DeleteVersionPayload removes one immutable version after its database row
// has been pruned. It never follows symlinks and is idempotent so a later
// retention pass can finish filesystem cleanup after a power loss.
func DeleteVersionPayload(root, subscriptionID, versionID string) (bool, error) {
	if root == "" || !safePayloadSegment(subscriptionID) || !safePayloadSegment(versionID) {
		return false, errors.New("payload root and safe subscription/version ids are required")
	}
	subscriptionDirectory := filepath.Join(root, subscriptionID)
	if err := requirePayloadDirectory(subscriptionDirectory); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	destination := filepath.Join(subscriptionDirectory, versionID)
	if err := requirePayloadDirectory(destination); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := os.RemoveAll(destination); err != nil {
		return false, fmt.Errorf("delete subscription version payload: %w", err)
	}
	if err := syncPayloadDirectory(subscriptionDirectory); err != nil {
		// Removal already happened. Report that fact even when the directory
		// durability barrier failed so callers do not publish a false count.
		// The idempotent orphan scan will verify the final state on a later pass.
		return true, fmt.Errorf("sync subscription payload directory after deletion: %w", err)
	}
	return true, nil
}

// ListVersionPayloads returns only published version directories. Temporary
// .payload-* directories are skipped because an in-flight refresh may own
// them; their crash recovery is a separate age-based concern.
func ListVersionPayloads(root string, limit int) ([]PayloadRef, error) {
	if root == "" || limit < 1 || limit > 4096 {
		return nil, errors.New("payload root and bounded list limit are required")
	}
	if err := requirePayloadDirectory(root); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	subscriptions, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("list subscription payload root: %w", err)
	}
	result := make([]PayloadRef, 0, limit)
	for _, subscriptionEntry := range subscriptions {
		if len(result) == limit {
			break
		}
		if !safePayloadSegment(subscriptionEntry.Name()) || subscriptionEntry.Type()&os.ModeSymlink != 0 || !subscriptionEntry.IsDir() {
			return nil, errors.New("subscription payload root contains an unsafe entry")
		}
		subscriptionDirectory := filepath.Join(root, subscriptionEntry.Name())
		if err := requirePayloadDirectory(subscriptionDirectory); err != nil {
			return nil, err
		}
		versions, err := os.ReadDir(subscriptionDirectory)
		if err != nil {
			return nil, fmt.Errorf("list subscription version payloads: %w", err)
		}
		for _, versionEntry := range versions {
			if len(result) == limit {
				break
			}
			if strings.HasPrefix(versionEntry.Name(), ".payload-") {
				continue
			}
			if !safePayloadSegment(versionEntry.Name()) || versionEntry.Type()&os.ModeSymlink != 0 || !versionEntry.IsDir() {
				return nil, errors.New("subscription directory contains an unsafe version payload")
			}
			if err := requirePayloadDirectory(filepath.Join(subscriptionDirectory, versionEntry.Name())); err != nil {
				return nil, err
			}
			result = append(result, PayloadRef{SubscriptionID: subscriptionEntry.Name(), VersionID: versionEntry.Name()})
		}
	}
	return result, nil
}

func requirePayloadDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("subscription payload path is not a regular directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		return errors.New("subscription payload directory mode is unsafe")
	}
	return nil
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
