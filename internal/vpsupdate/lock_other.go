//go:build !linux

package vpsupdate

import "sync"

var processLocks sync.Map

func acquireLock(root string) (func(), error) {
	if err := (JournalStore{Root: root}).prepare(); err != nil {
		return nil, err
	}
	value, _ := processLocks.LoadOrStore(root, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	if !lock.TryLock() {
		return nil, ErrUpdateInProgress
	}
	return lock.Unlock, nil
}
