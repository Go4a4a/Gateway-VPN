// Package hostboot reads the Linux boot identity used to distinguish a host
// reboot from an ordinary Gateway VPN process restart.
package hostboot

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const LinuxBootIDPath = "/proc/sys/kernel/random/boot_id"

// Read returns one canonical Linux UUID without exposing its source path in
// errors. An alternate absolute path is accepted only for isolated tests.
func Read(path string) (string, error) {
	if path == "" {
		path = LinuxBootIDPath
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("boot id path must be absolute")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > 128 {
		return "", errors.New("boot id source is unavailable or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("open boot id source failed")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return "", errors.New("boot id source changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil || len(content) > 128 {
		return "", errors.New("read boot id failed")
	}
	value := strings.ToLower(strings.TrimSpace(string(content)))
	if !canonicalUUID(value) {
		return "", errors.New("boot id is not a canonical UUID")
	}
	return value, nil
}

func canonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, current := range value {
		switch index {
		case 8, 13, 18, 23:
			if current != '-' {
				return false
			}
		default:
			if !(current >= '0' && current <= '9' || current >= 'a' && current <= 'f') {
				return false
			}
		}
	}
	return true
}
