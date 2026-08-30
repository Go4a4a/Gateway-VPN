//go:build linux

package vpsupdate

import "os"

func replacePath(source, destination string) error { return os.Rename(source, destination) }
