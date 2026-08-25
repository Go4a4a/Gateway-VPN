// Package bootstrap creates first-run secrets without exposing them in logs.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gateway-vpn/internal/auth"
)

const bootstrapPasswordFilename = "bootstrap-admin-password"

type AdminResult struct {
	Created      bool
	PasswordFile string
}

func EnsureAdmin(ctx context.Context, service auth.Service, stateDirectory string) (AdminResult, error) {
	hasUsers, err := service.HasUsers(ctx)
	if err != nil {
		return AdminResult{}, err
	}
	passwordPath := filepath.Join(stateDirectory, "secrets", bootstrapPasswordFilename)
	if hasUsers {
		return AdminResult{PasswordFile: passwordPath}, nil
	}
	password, err := readBootstrapPassword(passwordPath)
	if errors.Is(err, os.ErrNotExist) {
		password, err = auth.GenerateBootstrapPassword()
		if err != nil {
			return AdminResult{}, err
		}
		if err := writeSecretAtomic(passwordPath, []byte(password+"\n")); err != nil {
			return AdminResult{}, err
		}
	} else if err != nil {
		return AdminResult{}, err
	}
	created, err := service.CreateBootstrapAdmin(ctx, password)
	if err != nil {
		return AdminResult{}, err
	}
	if !created {
		return AdminResult{}, errors.New("bootstrap admin race detected")
	}
	return AdminResult{Created: true, PasswordFile: passwordPath}, nil
}

func readBootstrapPassword(filename string) (string, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 2048 {
		return "", errors.New("bootstrap password must be a small regular non-symlink file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("bootstrap password permissions must be 0600 or stricter")
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	password := strings.TrimSpace(string(content))
	if len(password) < 12 {
		return "", errors.New("bootstrap password file is invalid")
	}
	return password, nil
}

func writeSecretAtomic(filename string, content []byte) error {
	directory := filepath.Dir(filename)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create bootstrap secret directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure bootstrap secret directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".bootstrap-")
	if err != nil {
		return fmt.Errorf("create bootstrap secret: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("publish bootstrap secret: %w", err)
	}
	return nil
}
