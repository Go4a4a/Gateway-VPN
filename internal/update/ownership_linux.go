//go:build linux

package update

import "os"

func setFileOwnership(path string, uid, gid int) error {
	return os.Chown(path, uid, gid)
}
