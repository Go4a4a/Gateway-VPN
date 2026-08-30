//go:build linux

package gatewayfabric

import (
	"errors"
	"os"
	"syscall"
)

func validateRootOwned(info os.FileInfo, mode os.FileMode) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm() != mode {
		return errors.New("path must have exact root ownership and mode")
	}
	return nil
}
