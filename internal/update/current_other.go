//go:build !linux

package update

import (
	"os"
	"strings"
)

// Non-Linux uses a bounded regular-file pointer only so Windows synthetic tests
// can exercise transaction ordering. Production Linux accepts only symlinks.
func readCurrentLink(path string) (string, error) {
	content, err := readBoundedRegular(path, 4096)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(content)), nil
}

func createCurrentLink(path, target string) error {
	return os.WriteFile(path, []byte(target+"\n"), 0o600)
}
