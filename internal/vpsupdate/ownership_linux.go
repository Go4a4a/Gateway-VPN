//go:build linux

package vpsupdate

import "os"

func chownPath(path string, uid, gid int) error { return os.Chown(path, uid, gid) }
