package main

import (
	"testing"

	"gateway-vpn/internal/dataplane"
	"gateway-vpn/internal/wgingress"
)

func TestTopologyRuntimeContextKeepsIngressReservedPrefixesModeAware(t *testing.T) {
	firewall := &dataplane.FirewallBackend{}
	routing := &dataplane.RoutingBackend{}
	ingress := &wgingress.Backend{}
	runtime := topologyRuntimeContext{firewall: firewall, routing: routing, ingress: ingress}

	if err := runtime.SetTopologyNetwork("wg-ingress", "10.90.0.1/24"); err != nil {
		t.Fatal(err)
	}
	if firewall.LANName != "wg-ingress" || routing.LANPrefix != "10.90.0.1/24" || len(ingress.Repository.ReservedPrefixes) != 0 {
		t.Fatalf("one-arm runtime context = %q / %q / %+v", firewall.LANName, routing.LANPrefix, ingress.Repository.ReservedPrefixes)
	}

	if err := runtime.SetTopologyNetwork("gateway-vpn-lan", "192.168.210.1/24"); err != nil {
		t.Fatal(err)
	}
	if len(ingress.Repository.ReservedPrefixes) != 1 || ingress.Repository.ReservedPrefixes[0].String() != "192.168.210.0/24" {
		t.Fatalf("routed ingress reservation = %+v", ingress.Repository.ReservedPrefixes)
	}
}
