//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func acquireVPSLifecycleLock(lockPath, installMarker, authorizationMarker string, allowInstallOwner bool) (func(), error) {
	return acquireVPSLifecycleLockForUID(lockPath, installMarker, authorizationMarker, allowInstallOwner, 0)
}

func acquireVPSLifecycleLockForUID(lockPath, installMarker, authorizationMarker string, allowInstallOwner bool, expectedUID uint32) (func(), error) {
	if !filepath.IsAbs(lockPath) || filepath.Base(lockPath) != "gateway-vpn-vps-install.lock" {
		return nil, errors.New("fixed absolute VPS lifecycle lock is required")
	}
	directoryFD, err := unix.Open(filepath.Dir(filepath.Clean(lockPath)), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("open VPS lifecycle lock directory failed")
	}
	defer unix.Close(directoryFD)
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil || directoryStat.Uid != expectedUID || directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New("VPS lifecycle lock directory is unsafe")
	}
	lockFD, err := unix.Openat(directoryFD, filepath.Base(lockPath), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, errors.New("open VPS lifecycle lock failed")
	}
	file := os.NewFile(uintptr(lockFD), lockPath)
	if file == nil {
		unix.Close(lockFD)
		return nil, errors.New("open VPS lifecycle lock failed")
	}
	closeFile := func() { _ = file.Close() }
	var lockStat unix.Stat_t
	if err := unix.Fstat(lockFD, &lockStat); err != nil || lockStat.Uid != expectedUID || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&0o777 != 0o600 || lockStat.Nlink != 1 {
		closeFile()
		return nil, errors.New("VPS lifecycle lock is unsafe")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if (errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN)) && allowInstallOwner &&
			secureVPSLifecycleMarker(installMarker, expectedUID, false) && secureVPSLifecycleMarker(authorizationMarker, expectedUID, true) {
			closeFile()
			return func() {}, nil
		}
		closeFile()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errVPSLifecycleActive
		}
		return nil, errors.New("lock VPS lifecycle transaction failed")
	}
	return func() {
		_ = unix.Flock(lockFD, unix.LOCK_UN)
		closeFile()
	}, nil
}

func secureVPSLifecycleMarker(path string, expectedUID uint32, empty bool) bool {
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

func createVPSUpdateLiveMarker() (func(), error) {
	return createVPSUpdateLiveMarkerAt(vpsUpdateLiveMarker, 0)
}

func createVPSUpdateLiveMarkerAt(path string, expectedUID uint32) (func(), error) {
	if !filepath.IsAbs(path) || filepath.Base(path) != "gateway-vpn-vps-update-live" {
		return nil, errors.New("fixed absolute VPS update marker is required")
	}
	directoryFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("open VPS update marker directory failed")
	}
	defer unix.Close(directoryFD)
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil || directoryStat.Uid != expectedUID || directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New("VPS update marker directory is unsafe")
	}
	markerFD, err := unix.Openat(directoryFD, filepath.Base(path), unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, errors.New("create exclusive VPS update marker failed")
	}
	var markerStat unix.Stat_t
	statErr := unix.Fstat(markerFD, &markerStat)
	closeErr := unix.Close(markerFD)
	if statErr != nil || closeErr != nil || markerStat.Uid != expectedUID || markerStat.Mode&unix.S_IFMT != unix.S_IFREG || markerStat.Mode&0o777 != 0o600 || markerStat.Nlink != 1 || markerStat.Size != 0 {
		_ = unix.Unlinkat(directoryFD, filepath.Base(path), 0)
		return nil, errors.New("VPS update marker is unsafe")
	}
	return func() { _ = os.Remove(path) }, nil
}
