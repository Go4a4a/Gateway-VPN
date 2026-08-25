//go:build !linux

package update

import (
	"errors"
	"os"
)

// Non-Linux support exists only for synthetic development tests. Production is
// Linux and uses atomic POSIX rename replacement.
func replaceFile(source, destination string) error {
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}
