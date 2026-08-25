package subscription

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const maxSourceSecretBytes = 8193

type SourceURLReader interface {
	ReadURL(context.Context, string) (string, error)
}

// FileSourceURLReader confines subscription URL secrets to Root. os.Root keeps
// path traversal and concurrent symlink replacement from escaping that tree.
type FileSourceURLReader struct {
	Root string
}

func SaveURLSecret(rootPath, reference, value string) error {
	value = strings.TrimSpace(value)
	fetcher, err := NewFetcher(nil, nil)
	if err != nil {
		return err
	}
	if _, err := fetcher.validateURL(value); err != nil {
		return err
	}
	absoluteRoot, relative, err := confinedSecretPath(rootPath, reference)
	if err != nil {
		return err
	}
	if strings.Contains(relative, "/") {
		return errors.New("subscription URL secret must be a direct child of the secret root")
	}
	rootInfo, err := os.Lstat(absoluteRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("subscription secret root is unavailable or unsafe")
	}
	if runtime.GOOS != "windows" && rootInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("subscription secret root permissions are too broad")
	}
	target := filepath.Join(absoluteRoot, filepath.FromSlash(relative))
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("existing subscription URL secret is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect existing subscription URL secret failed")
	}
	temporary, err := os.CreateTemp(absoluteRoot, ".subscription-url-*.tmp")
	if err != nil {
		return errors.New("create temporary subscription URL secret failed")
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("protect subscription URL secret failed")
	}
	if _, err := temporary.WriteString(value + "\n"); err != nil {
		temporary.Close()
		return errors.New("write subscription URL secret failed")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync subscription URL secret failed")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close subscription URL secret failed")
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return errors.New("activate subscription URL secret failed")
	}
	return syncSecretDirectory(absoluteRoot)
}

func DeleteURLSecret(rootPath, reference string) error {
	absoluteRoot, relative, err := confinedSecretPath(rootPath, reference)
	if err != nil {
		return err
	}
	if strings.Contains(relative, "/") {
		return errors.New("subscription URL secret must be a direct child of the secret root")
	}
	target := filepath.Join(absoluteRoot, filepath.FromSlash(relative))
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("subscription URL secret is unsafe")
	}
	if err := os.Remove(target); err != nil {
		return errors.New("delete subscription URL secret failed")
	}
	return syncSecretDirectory(absoluteRoot)
}

func syncSecretDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(directory)
	if err != nil {
		return errors.New("open subscription secret directory failed")
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return errors.New("sync subscription secret directory failed")
	}
	return nil
}

func (reader FileSourceURLReader) ReadURL(ctx context.Context, reference string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	rootPath, relative, err := confinedSecretPath(reader.Root, reference)
	if err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("subscription secret root is unavailable or unsafe")
	}
	if runtime.GOOS != "windows" && rootInfo.Mode().Perm()&0o077 != 0 {
		return "", errors.New("subscription secret root permissions are too broad")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", errors.New("open subscription secret root failed")
	}
	defer root.Close()
	if err := rejectSecretSymlinks(root, relative); err != nil {
		return "", err
	}
	file, err := root.Open(relative)
	if err != nil {
		return "", errors.New("open subscription URL secret failed")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSourceSecretBytes {
		return "", errors.New("subscription URL secret is not a bounded regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("subscription URL secret permissions are too broad")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSourceSecretBytes+1))
	if err != nil || len(content) > maxSourceSecretBytes {
		return "", errors.New("read subscription URL secret failed")
	}
	value := strings.TrimSpace(string(content))
	if value == "" {
		return "", errors.New("subscription URL secret is empty")
	}
	return value, nil
}

func confinedSecretPath(rootPath, reference string) (string, string, error) {
	if strings.TrimSpace(rootPath) == "" || strings.TrimSpace(reference) == "" || strings.ContainsRune(reference, '\x00') {
		return "", "", errors.New("subscription secret root and reference are required")
	}
	absoluteRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return "", "", errors.New("resolve subscription secret root failed")
	}
	target := reference
	if !filepath.IsAbs(target) {
		target = filepath.Join(absoluteRoot, target)
	}
	absoluteTarget, err := filepath.Abs(target)
	if err != nil {
		return "", "", errors.New("resolve subscription secret reference failed")
	}
	relative, err := filepath.Rel(absoluteRoot, absoluteTarget)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", "", errors.New("subscription secret reference escapes the secret root")
	}
	return absoluteRoot, filepath.ToSlash(relative), nil
}

func rejectSecretSymlinks(root *os.Root, relative string) error {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	current := ""
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return errors.New("subscription secret reference is invalid")
		}
		if current == "" {
			current = part
		} else {
			current += "/" + part
		}
		info, err := root.Lstat(current)
		if err != nil {
			return errors.New("inspect subscription secret path failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("subscription secret path must not contain symbolic links")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("subscription secret path component is not a directory")
		}
	}
	return nil
}
