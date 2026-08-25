//go:build linux

package mihomoruntime

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// AtomicSymlinkSwitcher publishes root/active as one relative symlink rename.
// It never accepts a caller-selected path outside root/generations/generation.
type AtomicSymlinkSwitcher struct{}

func (AtomicSymlinkSwitcher) Activate(root, generation, generationDirectory string) error {
	if err := validateGenerationDirectory(root, generation, generationDirectory); err != nil {
		return err
	}
	active := filepath.Join(root, "active")
	if info, err := os.Lstat(active); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return errors.New("Mihomo active path exists and is not a symlink")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Mihomo active link: %w", err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("allocate Mihomo active link name: %w", err)
	}
	temporary := filepath.Join(root, ".active-"+hex.EncodeToString(nonce[:]))
	defer os.Remove(temporary)
	relativeTarget := filepath.Join("generations", generation)
	if err := os.Symlink(relativeTarget, temporary); err != nil {
		return fmt.Errorf("create Mihomo active link: %w", err)
	}
	if err := os.Rename(temporary, active); err != nil {
		return fmt.Errorf("publish Mihomo active link: %w", err)
	}
	return syncDirectory(root)
}

func (AtomicSymlinkSwitcher) Current(root string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", errors.New("absolute Mihomo root is required")
	}
	target, err := os.Readlink(filepath.Join(root, "active"))
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(target) {
		return "", errors.New("Mihomo active link must be relative")
	}
	clean := filepath.Clean(target)
	if filepath.Dir(clean) != "generations" {
		return "", errors.New("Mihomo active link escapes generations directory")
	}
	generation := filepath.Base(clean)
	if !safeGenerationID(generation) || clean != filepath.Join("generations", generation) {
		return "", errors.New("Mihomo active link has an unsafe generation")
	}
	return generation, nil
}

func (AtomicSymlinkSwitcher) Remove(root string) error {
	if !filepath.IsAbs(root) {
		return errors.New("absolute Mihomo root is required")
	}
	active := filepath.Join(root, "active")
	info, err := os.Lstat(active)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return errors.New("refusing to remove non-symlink Mihomo active path")
	}
	if err := os.Remove(active); err != nil {
		return err
	}
	return syncDirectory(root)
}

func validateGenerationDirectory(root, generation, generationDirectory string) error {
	if !filepath.IsAbs(root) || !safeGenerationID(generation) || !filepath.IsAbs(generationDirectory) {
		return errors.New("absolute Mihomo root, safe generation, and absolute directory are required")
	}
	for _, directory := range []string{root, filepath.Join(root, "generations"), generationDirectory} {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect Mihomo generation directory: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("Mihomo generation path must contain only real directories")
		}
	}
	expected := filepath.Join(root, "generations", generation)
	if filepath.Clean(generationDirectory) != filepath.Clean(expected) {
		return errors.New("Mihomo generation directory does not match root and generation")
	}
	config := filepath.Join(generationDirectory, "config.yaml")
	info, err := os.Lstat(config)
	if err != nil {
		return fmt.Errorf("inspect Mihomo generation config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("Mihomo generation config must be a regular non-symlink file")
	}
	return nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
