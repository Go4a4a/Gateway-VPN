//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func acquireGatewayLifecycleLock(lockPath, installMarker, authorizationMarker string, allowInstallOwner bool) (func(), error) {
	return acquireGatewayLifecycleLockForUID(lockPath, installMarker, authorizationMarker, allowInstallOwner, 0)
}

func acquireGatewayLifecycleLockForUID(lockPath, installMarker, authorizationMarker string, allowInstallOwner bool, expectedUID uint32) (func(), error) {
	if !filepath.IsAbs(lockPath) || filepath.Base(lockPath) != "gateway-vpn-install.lock" {
		return nil, errors.New("fixed absolute Gateway lifecycle lock is required")
	}
	directory := filepath.Dir(filepath.Clean(lockPath))
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("open Gateway lifecycle lock directory failed")
	}
	defer unix.Close(directoryFD)
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil || directoryStat.Uid != expectedUID || directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New("Gateway lifecycle lock directory is unsafe")
	}
	lockFD, err := unix.Openat(directoryFD, filepath.Base(lockPath), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, errors.New("open Gateway lifecycle lock failed")
	}
	file := os.NewFile(uintptr(lockFD), lockPath)
	if file == nil {
		unix.Close(lockFD)
		return nil, errors.New("open Gateway lifecycle lock failed")
	}
	closeFile := func() { _ = file.Close() }
	var lockStat unix.Stat_t
	if err := unix.Fstat(lockFD, &lockStat); err != nil || lockStat.Uid != expectedUID || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&0o777 != 0o600 || lockStat.Nlink != 1 {
		closeFile()
		return nil, errors.New("Gateway lifecycle lock is unsafe")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if (errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN)) && allowInstallOwner &&
			secureLifecycleMarker(installMarker, expectedUID, false) && secureLifecycleMarker(authorizationMarker, expectedUID, true) {
			closeFile()
			return func() {}, nil
		}
		closeFile()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errGatewayLifecycleActive
		}
		return nil, errors.New("lock Gateway lifecycle transaction failed")
	}
	return func() {
		_ = unix.Flock(lockFD, unix.LOCK_UN)
		closeFile()
	}, nil
}

func secureLifecycleMarker(path string, expectedUID uint32, empty bool) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil || stat.Uid != expectedUID || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
		return false
	}
	if empty {
		return stat.Size == 0
	}
	return stat.Size > 0 && stat.Size <= 4096
}
