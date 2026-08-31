//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVPSLifecycleLockRejectsConcurrentOwner(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, "gateway-vpn-vps-install.lock")
	uid := uint32(os.Geteuid())
	unlock, err := acquireVPSLifecycleLockForUID(lockPath, filepath.Join(root, "active"), filepath.Join(root, "authorized"), false, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := acquireVPSLifecycleLockForUID(lockPath, filepath.Join(root, "active"), filepath.Join(root, "authorized"), false, uid); !errors.Is(err, errVPSLifecycleActive) {
		t.Fatalf("second lock error = %v", err)
	}
}

func TestVPSLifecycleLockInstallOwnerBypassRequiresBothSafeMarkers(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, "gateway-vpn-vps-install.lock")
	active := filepath.Join(root, "active")
	authorized := filepath.Join(root, "authorized")
	uid := uint32(os.Geteuid())
	unlock, err := acquireVPSLifecycleLockForUID(lockPath, active, authorized, false, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := os.WriteFile(active, []byte("transaction\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireVPSLifecycleLockForUID(lockPath, active, authorized, true, uid); !errors.Is(err, errVPSLifecycleActive) {
		t.Fatalf("single marker bypass error = %v", err)
	}
	if err := os.WriteFile(authorized, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	bypassUnlock, err := acquireVPSLifecycleLockForUID(lockPath, active, authorized, true, uid)
	if err != nil {
		t.Fatalf("verified install-owner bypass failed: %v", err)
	}
	bypassUnlock()
}

func TestVPSUpdateLiveMarkerIsExclusiveAndSymlinkSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway-vpn-vps-update-live")
	uid := uint32(os.Geteuid())
	remove, err := createVPSUpdateLiveMarkerAt(path, uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := createVPSUpdateLiveMarkerAt(path, uid); err == nil {
		t.Fatal("second VPS update live marker was accepted")
	}
	remove()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("live marker cleanup error = %v", err)
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(path), "target"), path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := createVPSUpdateLiveMarkerAt(path, uid); err == nil {
		t.Fatal("symlink VPS update live marker was accepted")
	}
}
