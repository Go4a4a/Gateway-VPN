//go:build !linux

package update

import "os"

// Restore-point mutation is a Linux/root-only operation. Portable unit tests
// still exercise the transaction state machine, but Windows and other hosts do
// not expose trustworthy Unix directory mode semantics through os.FileMode.
func validRestoreStateRootMode(os.FileMode) bool {
	return true
}

func validRestoreTreeParentMode(os.FileMode, os.FileMode) bool {
	return true
}
