//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGatewayLifecycleLockSerializesRootOperations(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, "gateway-vpn-install.lock")
	uid := uint32(os.Geteuid())
	unlock, err := acquireGatewayLifecycleLockForUID(lockPath, filepath.Join(root, "install-active"), filepath.Join(root, "install-authorized"), false, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := acquireGatewayLifecycleLockForUID(lockPath, filepath.Join(root, "install-active"), filepath.Join(root, "install-authorized"), false, uid); !errors.Is(err, errGatewayLifecycleActive) {
		t.Fatalf("concurrent lifecycle lock error = %v", err)
	}
}

func TestGatewayLifecycleLockAllowsOnlyVerifiedInstallOwnedRecovery(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, "gateway-vpn-install.lock")
	installMarker := filepath.Join(root, "install-active")
	authorizationMarker := filepath.Join(root, "install-authorized")
	uid := uint32(os.Geteuid())
	unlock, err := acquireGatewayLifecycleLockForUID(lockPath, installMarker, authorizationMarker, false, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := acquireGatewayLifecycleLockForUID(lockPath, installMarker, authorizationMarker, true, uid); !errors.Is(err, errGatewayLifecycleActive) {
		t.Fatalf("recovery bypassed lock without install markers: %v", err)
	}
	if err := os.WriteFile(installMarker, []byte("active\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authorizationMarker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := acquireGatewayLifecycleLockForUID(lockPath, installMarker, authorizationMarker, true, uid)
	if err != nil {
		t.Fatalf("verified install-owned recovery lock = %v", err)
	}
	release()
	if err := os.Chmod(authorizationMarker, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireGatewayLifecycleLockForUID(lockPath, installMarker, authorizationMarker, true, uid); !errors.Is(err, errGatewayLifecycleActive) {
		t.Fatalf("unsafe install authorization bypassed lifecycle lock: %v", err)
	}
}
