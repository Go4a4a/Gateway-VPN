//go:build linux

package update

import "os"

// POSIX rename replaces the destination atomically when both names are on the
// same filesystem. All production candidates are created beside their target.
func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
