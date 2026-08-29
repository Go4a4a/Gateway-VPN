//go:build linux

package removal

import (
	"os"
	"syscall"
)

func isRootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0
}

func hasSecureMode(info os.FileInfo, expected os.FileMode) bool {
	return info.Mode().Perm() == expected
}
