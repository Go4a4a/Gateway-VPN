//go:build !linux

package mihomoruntime

import "errors"

type AtomicSymlinkSwitcher struct{}

func (AtomicSymlinkSwitcher) Activate(string, string, string) error {
	return errors.New("atomic Mihomo generation switching is supported only on Linux")
}

func (AtomicSymlinkSwitcher) Current(string) (string, error) {
	return "", errors.New("atomic Mihomo generation switching is supported only on Linux")
}

func (AtomicSymlinkSwitcher) Remove(string) error {
	return errors.New("atomic Mihomo generation switching is supported only on Linux")
}
