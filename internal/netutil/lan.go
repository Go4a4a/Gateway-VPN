// Package netutil contains shared, mutation-free network input validation.
package netutil

import "net/netip"

var wireGuardManagement = netip.MustParsePrefix("10.80.0.0/24")

// ParsePrivateLAN accepts only an RFC1918 IPv4 host address with a /16../30
// prefix. Network and broadcast addresses are rejected.
func ParsePrivateLAN(value string) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Bits() < 16 || prefix.Bits() > 30 {
		return netip.Prefix{}, false
	}
	network := prefix.Masked()
	addressValue := ipv4Value(prefix.Addr())
	networkValue := ipv4Value(network.Addr())
	hostMask := uint32(1)<<(32-prefix.Bits()) - 1
	if addressValue == networkValue || addressValue == networkValue|hostMask {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// ParseGatewayLAN additionally reserves the fixed WireGuard management
// subnet so every external Gateway LAN entry point enforces the same contract.
func ParseGatewayLAN(value string) (netip.Prefix, bool) {
	prefix, ok := ParsePrivateLAN(value)
	if !ok || prefix.Masked().Overlaps(wireGuardManagement) {
		return netip.Prefix{}, false
	}
	return prefix, true
}

func ValidGatewayLAN(value string) bool {
	_, ok := ParseGatewayLAN(value)
	return ok
}

func ipv4Value(address netip.Addr) uint32 {
	bytes := address.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}
