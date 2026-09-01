package managementfabric

import (
	"reflect"
	"testing"
)

func TestRenderFabricProducesOwnedTypedRoutesAliasesAndACL(t *testing.T) {
	spec := renderFixture(t)
	plan, err := RenderFabric(spec)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RouteProtocol != OwnedRouteProtocol || len(plan.Peers) != 1 || len(plan.Routes) != 3 || len(plan.Aliases) != 1 || len(plan.ACL) != 1 {
		t.Fatalf("rendered fabric = %+v", plan)
	}
	peer := plan.Peers[0]
	if peer.InterfaceName != "gvm1" || peer.LocalAddress != "10.80.0.2/32" || !reflect.DeepEqual(peer.AllowedSources, []string{"10.80.0.1/32", "10.81.0.10/32"}) {
		t.Fatalf("rendered peer = %+v", peer)
	}
	for _, route := range plan.Routes {
		if route.Owner != "gateway-vpn" || route.Protocol != OwnedRouteProtocol || route.Destination == "0.0.0.0/0" {
			t.Fatalf("unsafe rendered route = %+v", route)
		}
	}
	alias := plan.Aliases[0]
	if alias.PublishedAlias != "10.96.1.10/32" || alias.LocalDestination != "192.168.50.10" || alias.InterfaceName != "gvm1" || alias.ResourceKind != ResourceLocalHost || alias.AccessProfile != ProfileDedicatedLAN {
		t.Fatalf("rendered alias = %+v", alias)
	}
	rule := plan.ACL[0]
	if rule.InputInterface != "gvm1" || rule.Source != "10.81.0.10/32" || rule.ResourceKind != ResourceLocalHost || rule.AccessProfile != ProfileDedicatedLAN || rule.Protocol != ProtocolTCP || rule.PortStart != 443 || rule.PortEnd != 443 {
		t.Fatalf("rendered ACL = %+v", rule)
	}
}

func TestRenderFabricIsDeterministicAndRejectsNegativeFixtures(t *testing.T) {
	base := renderFixture(t)
	first, err := RenderFabric(base)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderFabric(base)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("renderer is not deterministic: equal=%v error=%v", reflect.DeepEqual(first, second), err)
	}

	tests := []struct {
		name   string
		mutate func(*FabricSpec)
	}{
		{"default route alias", func(spec *FabricSpec) { spec.Publications[0].PublishedAlias = "0.0.0.0/0" }},
		{"wrong interface slot", func(spec *FabricSpec) { spec.Links[0].InterfaceName = "wg0" }},
		{"duplicate local key", func(spec *FabricSpec) {
			duplicate := spec.Links[0]
			duplicate.ID = "link:b"
			duplicate.VPSID = "vps:b"
			duplicate.Slot = 2
			duplicate.InterfaceName = "gvm2"
			duplicate.ManagementSubnet = "10.82.0.0/24"
			duplicate.LocalAddress = "10.82.0.2"
			duplicate.RemoteAddress = "10.82.0.1"
			spec.Links = append(spec.Links, duplicate)
		}},
		{"cross-site publication", func(spec *FabricSpec) { spec.Resources[0].SiteID = "site:b" }},
		{"arbitrary protocol", func(spec *FabricSpec) { spec.ACL[0].Protocol = "ALL" }},
		{"unbounded ports", func(spec *FabricSpec) { spec.ACL[0].PortStart = 0; spec.ACL[0].PortEnd = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneFabric(t, base)
			test.mutate(&candidate)
			if _, err := RenderFabric(candidate); err == nil {
				t.Fatal("unsafe renderer fixture was accepted")
			}
		})
	}
}

func TestRenderFabricTerminatesEndToEndAdministratorAtGateway(t *testing.T) {
	spec := renderEndToEndFixture(t)
	plan, err := RenderFabric(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Peers) != 1 || !reflect.DeepEqual(plan.Peers[0].AllowedSources, []string{"10.80.0.1/32"}) {
		t.Fatalf("outer Gateway peer contains end-to-end administrator source: %+v", plan.Peers)
	}
	for _, route := range plan.Routes {
		if route.Purpose == "ADMIN_PEER" || route.Destination == "10.81.0.10/32" || route.Destination == "10.83.0.10/32" {
			t.Fatalf("end-to-end administrator escaped into outer routes: %+v", route)
		}
	}
	if plan.AdminContour == nil || plan.AdminContour.InterfaceName != AdminInterfaceName ||
		plan.AdminContour.GatewayAddress != "10.83.0.1/32" || len(plan.AdminContour.Relays) != 1 || len(plan.AdminContour.Peers) != 1 {
		t.Fatalf("rendered administrator contour = %+v", plan.AdminContour)
	}
	relay := plan.AdminContour.Relays[0]
	if relay.InputInterface != "gvm1" || relay.OuterSource != "10.80.0.1/32" || relay.OuterDestination != "10.80.0.2/32" || relay.DestinationPort != AdminListenPort {
		t.Fatalf("rendered relay ingress = %+v", relay)
	}
	peer := plan.AdminContour.Peers[0]
	if peer.AssignedAddress != "10.83.0.10/32" || peer.LinkID != "link:a" || peer.RelayID != "relay:a" {
		t.Fatalf("rendered inner administrator peer = %+v", peer)
	}
	if len(plan.ACL) != 1 {
		t.Fatalf("rendered end-to-end ACL count = %d", len(plan.ACL))
	}
	rule := plan.ACL[0]
	if rule.TrustMode != TrustEndToEndRelay || rule.InputInterface != AdminInterfaceName ||
		rule.Source != "10.83.0.10/32" || rule.TunnelID != "tunnel:a" || rule.RelayID != "relay:a" {
		t.Fatalf("rendered end-to-end ACL = %+v", rule)
	}
}

func TestRenderFabricRejectsUnsafeEndToEndRelayBindings(t *testing.T) {
	base := renderEndToEndFixture(t)
	tests := []struct {
		name   string
		mutate func(*FabricSpec)
	}{
		{"outer WireGuard port reuse", func(spec *FabricSpec) { spec.AdminRelays[0].PublicUDPPort = 51821 }},
		{"contour subnet overlap", func(spec *FabricSpec) {
			spec.AdminContour.Subnet = "10.80.0.0/24"
			spec.AdminContour.GatewayAddress = "10.80.0.254"
		}},
		{"duplicate inner key and address", func(spec *FabricSpec) {
			duplicate := spec.AdminTunnels[0]
			duplicate.ID = "tunnel:b"
			spec.AdminTunnels = append(spec.AdminTunnels, duplicate)
		}},
		{"tunnel without end-to-end trust", func(spec *FabricSpec) { spec.Admins[0].TrustMode = TrustRoutedHub }},
		{"duplicate public relay port", func(spec *FabricSpec) {
			link := spec.Links[0]
			link.ID, link.VPSID, link.Slot, link.InterfaceName = "link:b", "vps:b", 2, "gvm2"
			link.ManagementSubnet, link.LocalAddress, link.RemoteAddress = "10.84.0.0/24", "10.84.0.2", "10.84.0.1"
			link.LocalPublicKey, link.RemotePublicKey = testPublicKey(t), testPublicKey(t)
			link.LocalPrivateKeySecretRef = "/var/lib/gateway-vpn/secrets/management/link:b.key"
			link.Endpoints = []EndpointSpec{{Host: "vps-b.example.net", Port: 51821}}
			spec.Links = append(spec.Links, link)
			relay := spec.AdminRelays[0]
			relay.ID, relay.LinkID = "relay:b", "link:b"
			spec.AdminRelays = append(spec.AdminRelays, relay)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneFabric(t, base)
			test.mutate(&candidate)
			if _, err := RenderFabric(candidate); err == nil {
				t.Fatal("unsafe end-to-end relay fixture was accepted")
			}
		})
	}
}

func renderFixture(t *testing.T) FabricSpec {
	t.Helper()
	return FabricSpec{
		ReservedPrefixes: []ReservedPrefix{{Owner: "gateway-lan", CIDR: "192.168.200.0/24"}},
		Links: []LinkSpec{{
			ID: "link:a", SiteID: "site:a", VPSID: "vps:a", Slot: 1, InterfaceName: "gvm1",
			ManagementSubnet: "10.80.0.0/24", LocalAddress: "10.80.0.2", RemoteAddress: "10.80.0.1",
			LocalPrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/link:a.key",
			LocalPublicKey:           testPublicKey(t), RemotePublicKey: testPublicKey(t),
			UplinkPolicy: UplinkAuto, PersistentKeepalive: 25,
			Endpoints: []EndpointSpec{{Host: "vps-a.example.net", Port: 51821}},
		}},
		Admins: []AdminSpec{{ID: "admin:a", VPSID: "vps:a", AssignedAddress: "10.81.0.10", TrustMode: TrustRoutedHub}},
		Resources: []ResourceSpec{{
			ID: "resource:host", SiteID: "site:a", Kind: ResourceLocalHost,
			AccessProfile: ProfileDedicatedLAN, LocalDestination: "192.168.50.10",
			Ports:          []ResourcePort{{Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443}},
			ProbeInterface: "mgmt0",
		}},
		Publications: []PublicationSpec{{
			ID: "publication:a", ResourceID: "resource:host", LinkID: "link:a",
			LocalDestination: "192.168.50.10", PublishedAlias: "10.96.1.10/32",
		}},
		ACL: []ACLSpec{{
			ID: "acl:a", AdminID: "admin:a", ResourceID: "resource:host",
			Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443,
		}},
	}
}

func renderEndToEndFixture(t *testing.T) FabricSpec {
	t.Helper()
	spec := renderFixture(t)
	spec.Admins[0].TrustMode = TrustEndToEndRelay
	spec.AdminContour = &AdminContourSpec{
		InterfaceName: AdminInterfaceName, PrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/wg-admin.key",
		PublicKey: testPublicKey(t), Subnet: "10.83.0.0/24", GatewayAddress: "10.83.0.1", ListenPort: AdminListenPort,
	}
	spec.AdminRelays = []AdminRelaySpec{{
		ID: "relay:a", LinkID: "link:a", PublicEndpointHost: "vps-a.example.net", PublicBindAddress: "203.0.113.10",
		PublicUDPPort: 51823, DestinationPort: AdminListenPort, RateLimitPerSecond: 100, BurstPackets: 200,
	}}
	spec.AdminTunnels = []AdminTunnelSpec{{
		ID: "tunnel:a", AdminID: "admin:a", RelayID: "relay:a", PublicKey: testPublicKey(t), AssignedAddress: "10.83.0.10",
	}}
	return spec
}
