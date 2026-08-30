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
	if plan.RouteProtocol != OwnedRouteProtocol || len(plan.Peers) != 1 || len(plan.Routes) != 2 || len(plan.Aliases) != 1 || len(plan.ACL) != 1 {
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
	if alias.PublishedAlias != "10.96.1.10/32" || alias.LocalDestination != "192.168.50.10" || alias.InterfaceName != "gvm1" {
		t.Fatalf("rendered alias = %+v", alias)
	}
	rule := plan.ACL[0]
	if rule.InputInterface != "gvm1" || rule.Source != "10.81.0.10/32" || rule.Protocol != ProtocolTCP || rule.PortStart != 443 || rule.PortEnd != 443 {
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
		Admins: []AdminSpec{{ID: "admin:a", VPSID: "vps:a", AssignedAddress: "10.81.0.10"}},
		Resources: []ResourceSpec{{
			ID: "resource:host", SiteID: "site:a", Kind: ResourceLocalHost,
			AccessProfile: ProfileDedicatedLAN, LocalDestination: "192.168.50.10",
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
