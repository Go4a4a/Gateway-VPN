package main

import "errors"

const (
	vpsLifecycleLockPath       = "/run/lock/gateway-vpn-vps-install.lock"
	vpsInstallActiveMarker     = "/var/lib/gateway-vpn-vps/install-transactions/active"
	vpsInstallAuthorizedMarker = "/run/gateway-vpn-vps-install-authorized"
	vpsUpdateLiveMarker        = "/run/gateway-vpn-vps-update-live"
)

var errVPSLifecycleActive = errors.New("another Gateway VPN VPS lifecycle transaction is active")

func acquireVPSUpdateRootLifecycle(allowInstallOwner bool) (func(), error) {
	return acquireVPSLifecycleLock(vpsLifecycleLockPath, vpsInstallActiveMarker, vpsInstallAuthorizedMarker, allowInstallOwner)
}
