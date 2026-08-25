package netutil

import "testing"

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
