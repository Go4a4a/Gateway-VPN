//go:build linux

package update

import (
	"errors"
	"os"
)

func readCurrentLink(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("current is not a symlink")
	}
	return os.Readlink(path)
}

func createCurrentLink(path, target string) error {
	return os.Symlink(target, path)
}
