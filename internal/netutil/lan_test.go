package netutil

import (
	"net/netip"
	"testing"
)

func TestParseGatewayLAN(t *testing.T) {
	for _, value := range []string{"192.168.200.1/24", "10.42.0.254/16", "172.20.4.1/30"} {
		if _, ok := ParseGatewayLAN(value); !ok {
			t.Errorf("ParseGatewayLAN(%q) rejected a valid LAN", value)
		}
	}
	for _, value := range []string{
		"8.8.8.8/24", "100.64.1.1/24", "192.168.1.1/15", "192.168.1.1/31",
		"192.168.1.0/24", "192.168.1.255/24", "10.80.0.2/24", "not-a-prefix",
	} {
		if _, ok := ParseGatewayLAN(value); ok {
			t.Errorf("ParseGatewayLAN(%q) accepted an unsafe LAN", value)
		}
	}
}

func TestIsUsableIPv4HostRejectsNetworkAndBroadcast(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.10/24")
	for _, raw := range []string{"198.51.100.1", "198.51.100.10", "198.51.100.254"} {
		if !IsUsableIPv4Host(prefix, netip.MustParseAddr(raw)) {
			t.Errorf("usable host %s was rejected", raw)
		}
	}
	for _, raw := range []string{"198.51.100.0", "198.51.100.255", "203.0.113.1", "0.0.0.0"} {
		if IsUsableIPv4Host(prefix, netip.MustParseAddr(raw)) {
			t.Errorf("unusable host %s was accepted", raw)
		}
	}
	pointToPoint := netip.MustParsePrefix("198.51.100.10/31")
	if !IsUsableIPv4Host(pointToPoint, netip.MustParseAddr("198.51.100.10")) || !IsUsableIPv4Host(pointToPoint, netip.MustParseAddr("198.51.100.11")) {
		t.Fatal("valid /31 point-to-point hosts were rejected")
	}
}
