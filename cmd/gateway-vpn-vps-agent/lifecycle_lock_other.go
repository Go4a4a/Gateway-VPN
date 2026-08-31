//go:build !linux

package main

import "sync"

var syntheticVPSLifecycleLock sync.Mutex

func acquireVPSLifecycleLock(_, _, _ string, _ bool) (func(), error) {
	if !syntheticVPSLifecycleLock.TryLock() {
		return nil, errVPSLifecycleActive
	}
	return syntheticVPSLifecycleLock.Unlock, nil
}

func createVPSUpdateLiveMarker() (func(), error) { return func() {}, nil }
