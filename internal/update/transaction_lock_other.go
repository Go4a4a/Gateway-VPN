//go:build !linux

package update

import (
	"path/filepath"
	"sync"
)

var syntheticTransactionLocks sync.Map

func acquireTransactionLock(root string) (func(), error) {
	if err := secureRealDirectory(root, 0o700); err != nil {
		return nil, err
	}
	value, _ := syntheticTransactionLocks.LoadOrStore(filepath.Clean(root), &sync.Mutex{})
	lock := value.(*sync.Mutex)
	if !lock.TryLock() {
		return nil, ErrUpdateInProgress
	}
	return lock.Unlock, nil
}
