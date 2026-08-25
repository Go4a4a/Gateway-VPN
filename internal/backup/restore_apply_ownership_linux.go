//go:build linux

package backup

import (
	"errors"
	"os"
	"syscall"
)

func validateRestoreTransactionOwnership(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("restore transaction root must be owned by root")
	}
	return nil
}
