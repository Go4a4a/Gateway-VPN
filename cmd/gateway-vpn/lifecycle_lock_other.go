//go:build !linux

package main

import "sync"

var syntheticGatewayLifecycleLock sync.Mutex

func acquireGatewayLifecycleLock(_, _, _ string, _ bool) (func(), error) {
	if !syntheticGatewayLifecycleLock.TryLock() {
		return nil, errGatewayLifecycleActive
	}
	return syntheticGatewayLifecycleLock.Unlock, nil
}
