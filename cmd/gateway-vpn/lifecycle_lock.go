package main

import "errors"

const (
	gatewayLifecycleLockPath       = "/run/lock/gateway-vpn-install.lock"
	gatewayInstallActiveMarker     = "/var/lib/gateway-vpn-privileged/install-transactions/active"
	gatewayInstallAuthorizedMarker = "/run/gateway-vpn-install-authorized"
)

var errGatewayLifecycleActive = errors.New("another Gateway VPN lifecycle transaction is active")

func acquireUpdateRootLifecycle(allowInstallOwner bool) (func(), error) {
	return acquireGatewayLifecycleLock(gatewayLifecycleLockPath, gatewayInstallActiveMarker, gatewayInstallAuthorizedMarker, allowInstallOwner)
}
