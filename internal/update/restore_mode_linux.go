//go:build linux

package update

import "os"

func validRestoreStateRootMode(actual os.FileMode) bool {
	return actual == 0o700 || actual == 0o710
}

func validRestoreTreeParentMode(actual, expected os.FileMode) bool {
	return actual == expected
}
