//go:build !linux

package backup

import "os"

func validateRestoreTransactionOwnership(os.FileInfo) error {
	return nil
}
