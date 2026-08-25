package mihomo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// WriteCandidate persists a generated bundle in a new generation directory.
// The directory becomes visible only after all files have been written and
// synced.
func WriteCandidate(destination string, bundle Bundle) error {
	if destination == "" || len(bundle.Main) == 0 {
		return errors.New("candidate destination and main config are required")
	}
	if _, err := os.Stat(destination); err == nil {
		return errors.New("candidate destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat candidate destination: %w", err)
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return fmt.Errorf("create candidate parent: %w", err)
	}
	if err := os.Chmod(parent, 0o750); err != nil {
		return fmt.Errorf("secure candidate parent: %w", err)
	}
	temporary, err := os.MkdirTemp(parent, ".candidate-")
	if err != nil {
		return fmt.Errorf("create temporary candidate: %w", err)
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o750); err != nil {
		return fmt.Errorf("secure temporary candidate: %w", err)
	}
	if err := writeSyncedFile(filepath.Join(temporary, "config.yaml"), bundle.Main); err != nil {
		return err
	}
	directories := map[string]struct{}{temporary: {}}
	for relative, content := range bundle.Providers {
		clean, err := safeRelativePath(relative)
		if err != nil {
			return err
		}
		filename := filepath.Join(temporary, filepath.FromSlash(clean))
		directory := filepath.Dir(filename)
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return fmt.Errorf("create provider directory: %w", err)
		}
		if err := os.Chmod(directory, 0o750); err != nil {
			return fmt.Errorf("secure provider directory: %w", err)
		}
		directories[directory] = struct{}{}
		if err := writeSyncedFile(filename, content); err != nil {
			return err
		}
	}
	for directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return fmt.Errorf("sync candidate directory: %w", err)
		}
	}
	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("publish candidate: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("sync candidate parent: %w", err)
	}
	return nil
}

func writeSyncedFile(filename string, content []byte) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return fmt.Errorf("create %s: %w", filename, err)
	}
	if err := file.Chmod(0o640); err != nil {
		file.Close()
		return fmt.Errorf("secure %s: %w", filename, err)
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", filename, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync %s: %w", filename, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filename, err)
	}
	return nil
}

func safeRelativePath(value string) (string, error) {
	if value == "" || strings.Contains(value, "\\") || filepath.IsAbs(value) {
		return "", errors.New("provider path must be a non-empty slash-separated relative path")
	}
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("provider path escapes candidate directory")
	}
	return clean, nil
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
