//go:build linux

package update

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func acquireTransactionLock(root string) (func(), error) {
	if err := secureRealDirectory(root, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(root, "update.lock")
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return nil, errors.New("update transaction lock is unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect update transaction lock failed")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("open update transaction lock failed")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, errors.New("secure update transaction lock failed")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrUpdateInProgress
		}
		return nil, errors.New("lock update transaction failed")
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
