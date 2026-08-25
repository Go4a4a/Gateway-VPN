package hilink

import (
	"strings"
	"testing"
)

func TestParseLeaseAndNetworkdConfigNeverAcceptDefaultRoute(t *testing.T) {
	lease, err := ParseNetworkdLease([]byte("ADDRESS=192.168.8.100\nPREFIXLEN=24\nROUTER=192.168.8.1\nDNS=192.168.8.1 1.1.1.1\n"), "enxone", 1500)
	if err != nil {
		t.Fatal(err)
	}
	if lease.ManagementPrefix.String() != "192.168.8.0/24" || lease.Gateway.String() != "192.168.8.1" || len(lease.DNS) != 2 {
		t.Fatalf("lease = %+v", lease)
	}
	configuration, err := RenderNetworkdConfig("enxone")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"DHCP=ipv4", "UseRoutes=no", "UseGateway=no", "UseDNS=no", "IPv6AcceptRA=no"} {
		if !strings.Contains(configuration, expected) {
			t.Errorf("networkd config missing %q", expected)
		}
	}
	if strings.Contains(configuration, "\nGateway=") || strings.Contains(configuration, "DefaultRouteOnDevice=yes") {
		t.Fatal("networkd config can install an uncontrolled default route")
	}
}

func TestParseLeaseRejectsInjectedOrConflictingRouter(t *testing.T) {
	for _, content := range []string{
		"ADDRESS=192.168.8.100\nPREFIXLEN=24\nROUTER=10.0.0.1\n",
		"ADDRESS=192.168.8.100\nPREFIXLEN=24\nROUTER=192.168.8.1 192.168.8.2\n",
		"ADDRESS=192.168.8.100\nADDRESS=192.168.8.101\nPREFIXLEN=24\nROUTER=192.168.8.1\n",
	} {
		if _, err := ParseNetworkdLease([]byte(content), "enxone", 1500); err == nil {
			t.Errorf("ParseNetworkdLease(%q) error = nil", content)
		}
	}
}
