package gatewayfabric

import (
	"strings"
	"testing"

	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/wgingress"
)

func TestRenderFirewallTransactionIsExactOwnedAndDefaultDeny(t *testing.T) {
	plan := gatewayPlanFixture(t)
	payload, err := RenderFirewallTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{
		"flush chain inet gateway_vpn management_fabric_input",
		"flush set inet gateway_vpn management_fabric_generation",
		`add element inet gateway_vpn management_fabric_interfaces { "gvm1" }`,
		`"enx0001" . 0x00001101 . 203.0.113.10 . 51821`,
		"management_fabric_prerouting",
		"dnat ip to 192.168.200.1",
		"management_fabric_input",
		"ip saddr 10.81.0.10/32",
		"tcp dport 8443",
		"gateway-vpn management fabric generation 7 plan ",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("firewall transaction missing %q:\n%s", required, text)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "delete table", "flush table", "policy accept", "0.0.0.0/0", "masquerade"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("Gateway-only firewall transaction contains %q:\n%s", forbidden, text)
		}
	}
}

func TestRenderFirewallTransactionMapsForwardedSubnetAndMasqueradesReplies(t *testing.T) {
	plan := gatewayPlanFixture(t)
	plan.Aliases[0].ResourceKind = managementfabric.ResourceLocalSubnet
	plan.Aliases[0].AccessProfile = managementfabric.ProfileDedicatedLAN
	plan.Aliases[0].PublishedAlias = "10.96.1.0/24"
	plan.Aliases[0].LocalDestination = "192.168.50.0/24"
	plan.ACL[0].ResourceKind = managementfabric.ResourceLocalSubnet
	plan.ACL[0].AccessProfile = managementfabric.ProfileDedicatedLAN
	plan.ACL[0].PublishedAlias = "10.96.1.0/24"
	plan.ACL[0].LocalDestination = "192.168.50.0/24"
	payload, err := RenderFirewallTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{
		"dnat ip prefix to ip daddr map { 10.96.1.0/24 : 192.168.50.0/24 }",
		"management_fabric_forward",
		"iifname @management_fabric_interfaces ct state { established, related }",
		"oifname @management_fabric_interfaces ct state { established, related }",
		"ip daddr 192.168.50.0/24 ct state new tcp dport 8443 counter accept",
		"management_fabric_postrouting",
		"counter masquerade",
		"ct state { established, related }",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("forwarded subnet transaction missing %q:\n%s", required, text)
		}
	}
}

func TestRenderFirewallTransactionBindsRelayAndACLToInnerIdentity(t *testing.T) {
	plan := gatewayPlanFixture(t)
	innerGateway, _ := wgingress.GenerateKeyPair()
	innerAdmin, _ := wgingress.GenerateKeyPair()
	plan.Links[0].AllowedIPs = []string{"10.82.0.1/32"}
	plan.AdminContour = &managementfabric.RenderedAdminContour{
		InterfaceName:       managementfabric.AdminInterfaceName,
		PrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/wg-admin.key",
		PublicKey:           innerGateway.Public, Subnet: "10.83.0.0/24", GatewayAddress: "10.83.0.1/32",
		ListenPort: managementfabric.AdminListenPort,
		Relays: []managementfabric.RenderedAdminRelayIngress{{
			RelayID: "relay:a", LinkID: "link:a", InputInterface: "gvm1",
			OuterSource: "10.82.0.1/32", OuterDestination: "10.82.0.2/32",
			PublicEndpointHost: "vps-a.example.net", PublicBindAddress: "203.0.113.10", PublicUDPPort: 51823,
			DestinationPort: managementfabric.AdminListenPort, RateLimitPerSecond: 100, BurstPackets: 200,
		}},
		Peers: []managementfabric.RenderedAdminPeer{{
			TunnelID: "tunnel:a", AdminID: "admin:a", RelayID: "relay:a", LinkID: "link:a",
			PublicKey: innerAdmin.Public, AssignedAddress: "10.83.0.10/32",
		}},
	}
	plan.ACL[0].InputInterface = managementfabric.AdminInterfaceName
	plan.ACL[0].Source = "10.83.0.10/32"
	plan.ACL[0].TrustMode = managementfabric.TrustEndToEndRelay
	plan.ACL[0].TunnelID = "tunnel:a"
	plan.ACL[0].RelayID = "relay:a"
	payload, err := RenderFirewallTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{
		`add element inet gateway_vpn management_fabric_interfaces { "gvm1", "wg-admin" }`,
		`iifname "gvm1" ip saddr 10.82.0.1/32 ip daddr 10.82.0.2/32 udp dport 51822 limit rate 100/second burst 200 packets`,
		`iifname "wg-admin" ip saddr 10.83.0.10/32 ip daddr 10.96.1.1/32 tcp dport 8443`,
		`iifname "wg-admin" ip saddr 10.83.0.10/32 ip daddr 192.168.200.1/32 ct state new tcp dport 8443`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("end-to-end Gateway transaction missing %q:\n%s", required, text)
		}
	}
	for _, forbidden := range []string{"ip saddr 10.81.0.10/32", "0.0.0.0/0", "flush ruleset"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("end-to-end Gateway transaction contains unsafe scope %q:\n%s", forbidden, text)
		}
	}

	tampered := plan
	contour := *plan.AdminContour
	tampered.AdminContour = &contour
	tampered.AdminContour.Relays = append([]managementfabric.RenderedAdminRelayIngress(nil), plan.AdminContour.Relays...)
	tampered.AdminContour.Relays[0].OuterSource = "10.90.0.1/32"
	if _, err := RenderFirewallTransaction(tampered); err == nil {
		t.Fatal("Gateway renderer accepted a relay outside its authenticated outer link")
	}
}

func gatewayPlanFixture(t *testing.T) managementfabric.GatewayHostPlan {
	t.Helper()
	local, _ := wgingress.GenerateKeyPair()
	remote, _ := wgingress.GenerateKeyPair()
	return managementfabric.GatewayHostPlan{
		Generation: 7, RouteProtocol: managementfabric.OwnedRouteProtocol,
		Links: []managementfabric.GatewayHostLink{{
			LinkID: "link:a", VPSID: "vps:a", InterfaceName: "gvm1",
			LocalAddress: "10.82.0.2/32", ManagementSubnet: "10.82.0.0/24", RemoteAddress: "10.82.0.1/32",
			PrivateKeyRef:  "/var/lib/gateway-vpn/secrets/management/link:a.key",
			LocalPublicKey: local.Public, RemotePublicKey: remote.Public,
			AllowedIPs: []string{"10.81.0.10/32", "10.82.0.1/32"}, EndpointAddress: "203.0.113.10", EndpointPort: 51821,
			PersistentKeepalive: 25, UplinkID: "uplink:a", UplinkInterface: "enx0001", UplinkGateway: "192.168.8.1",
			UplinkTable: 1101, UplinkMark: 0x1101, UplinkGeneration: 1,
			Routes: []managementfabric.RenderedRoute{{Owner: "gateway-vpn", LinkID: "link:a", InterfaceName: "gvm1", Destination: "10.82.0.0/24", Purpose: "MANAGEMENT_LINK", Protocol: 186}},
		}},
		Aliases: []managementfabric.RenderedAlias{{
			PublicationID: "publication:a", ResourceID: "resource:a", LinkID: "link:a", InterfaceName: "gvm1",
			ResourceKind: managementfabric.ResourceGatewayService, AccessProfile: managementfabric.ProfileGatewayOnly,
			PublishedAlias: "10.96.1.1/32", LocalDestination: "192.168.200.1",
		}},
		ACL: []managementfabric.RenderedACLRule{{
			RuleID: "acl:a", AdminID: "admin:a", ResourceID: "resource:a", PublicationID: "publication:a", LinkID: "link:a", InputInterface: "gvm1",
			ResourceKind: managementfabric.ResourceGatewayService, AccessProfile: managementfabric.ProfileGatewayOnly,
			Source: "10.81.0.10/32", PublishedAlias: "10.96.1.1/32", LocalDestination: "192.168.200.1",
			Protocol: managementfabric.ProtocolTCP, PortStart: 8443, PortEnd: 8443, TrustMode: managementfabric.TrustRoutedHub,
		}},
	}
}
