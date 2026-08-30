//go:build linux

package vpsops

import "os"

func chownFile(file *os.File, uid, gid int) error { return file.Chown(uid, gid) }
