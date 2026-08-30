//go:build !linux

package vpsupdate

import (
	"errors"
	"os"
)

func replacePath(source, destination string) error {
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}
