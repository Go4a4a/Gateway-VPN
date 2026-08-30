package vpsfabric

import (
	"strings"
	"testing"

	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

func TestRenderOwnsOnlyGatewayVPNObjects(t *testing.T) {
	server, _ := wgingress.GenerateKeyPair()
	gateway, _ := wgingress.GenerateKeyPair()
	admin, _ := wgingress.GenerateKeyPair()
	plan := vpsagent.VPSHostPlan{
		Generation: 2, InterfaceName: "wg-mgmt", ListenPort: 51821, RouteProtocol: 186,
		InterfaceAddresses: []string{"10.80.0.1/24", "10.82.0.1/30"},
		Peers: []vpsagent.VPSHostPeer{
			{ID: "admin-1", Kind: "ADMIN", PublicKey: admin.Public, Address: "10.81.0.10/32", AllowedIPs: []string{"10.81.0.10/32"}},
			{ID: "gateway-1", Kind: "GATEWAY", PublicKey: gateway.Public, Address: "10.82.0.2/32", WebUIPort: 9444, AllowedIPs: []string{"10.82.0.2/32", "10.96.0.2/32"}},
		},
		ResourceRoutes:  []vpsagent.VPSHostRoute{{PublicationID: "publication-1", GatewayPeerID: "gateway-1", Destination: "10.96.0.2/32", Protocol: 186}},
		ACL:             []vpsagent.VPSHostACLRule{{ID: "acl-1", AdminPeerID: "admin-1", GatewayPeerID: "gateway-1", PublicationID: "publication-1", Source: "10.81.0.10/32", Destination: "10.96.0.2/32", Protocol: "TCP", PortStart: 443, PortEnd: 443}},
		HubAdminSources: []string{"10.81.0.10/32"},
	}
	wg, err := RenderWireGuard(plan, server.Private)
	if err != nil {
		t.Fatal(err)
	}
	firewall, err := RenderFirewall(plan)
	if err != nil {
		t.Fatal(err)
	}
	combined := string(wg) + string(firewall)
	for _, required := range []string{"Table = off", "10.80.0.1/24", "10.96.0.2/32", "table inet gateway_vpn_vps", "tcp dport { 22, 9443 }", "tcp dport { 22, 9444 }", "tcp dport 443", "deny other fabric ingress forwarding", "deny other fabric egress forwarding"} {
		if !strings.Contains(combined, required) {
			t.Fatalf("missing %q in %s", required, combined)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "0.0.0.0/0", "docker", "ufw", "amnezia", "systemctl"} {
		if strings.Contains(strings.ToLower(combined), forbidden) {
			t.Fatalf("foreign or unsafe token %q in renderer", forbidden)
		}
	}
}

func TestRenderFirewallUsesOnlyExactAdministratorRelayTuple(t *testing.T) {
	gateway, _ := wgingress.GenerateKeyPair()
	plan := vpsagent.VPSHostPlan{
		Generation: 3, InterfaceName: "wg-mgmt", ListenPort: 51821, RouteProtocol: 186,
		InterfaceAddresses: []string{"10.80.0.1/24", "10.82.0.1/30"},
		Peers: []vpsagent.VPSHostPeer{{
			ID: "gateway-1", Kind: "GATEWAY", PublicKey: gateway.Public,
			Address: "10.82.0.2/32", WebUIPort: 8443, AllowedIPs: []string{"10.82.0.2/32"},
		}},
		AdminRelays: []vpsagent.VPSHostAdminRelay{{
			ID: "relay-1", GatewayPeerID: "gateway-1", PublicEndpointHost: "vps.example.net",
			PublicBindAddress: "203.0.113.10", PublicUDPPort: 51823,
			GatewayAddress: "10.82.0.2", VPSSourceAddress: "10.82.0.1", DestinationPort: 51822,
			RateLimitPerSecond: 100, BurstPackets: 200,
		}},
	}
	payload, err := RenderFirewall(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{
		"ip daddr 203.0.113.10 udp dport 51823 limit rate over 100/second burst 200 packets",
		"dnat ip to 10.82.0.2:51822",
		`oifname "wg-mgmt" ip daddr 10.82.0.2 ct state { new, established } udp dport 51822`,
		`iifname "wg-mgmt" ip saddr 10.82.0.2 ct state established,related udp sport 51822`,
		"snat ip to 10.82.0.1",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("relay firewall missing %q:\n%s", required, text)
		}
	}
	for _, forbidden := range []string{"0.0.0.0/0", "iifname \"wg-mgmt\" ct state new udp", "flush ruleset", "table ip filter"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("relay firewall contains unsafe scope %q:\n%s", forbidden, text)
		}
	}

	tampered := plan
	tampered.AdminRelays = append([]vpsagent.VPSHostAdminRelay(nil), plan.AdminRelays...)
	tampered.AdminRelays[0].VPSSourceAddress = "10.90.0.1"
	if _, err := RenderFirewall(tampered); err == nil {
		t.Fatal("relay renderer accepted an unowned SNAT source")
	}
}

func TestRenderFirewallRemovingOneRelayKeepsTheOther(t *testing.T) {
	gatewayOne, _ := wgingress.GenerateKeyPair()
	gatewayTwo, _ := wgingress.GenerateKeyPair()
	plan := vpsagent.VPSHostPlan{
		Generation: 4, InterfaceName: "wg-mgmt", ListenPort: 51821, RouteProtocol: 186,
		InterfaceAddresses: []string{"10.80.0.1/24", "10.82.0.1/30", "10.84.0.1/30"},
		Peers: []vpsagent.VPSHostPeer{
			{ID: "gateway-1", Kind: "GATEWAY", PublicKey: gatewayOne.Public, Address: "10.82.0.2/32", WebUIPort: 8443, AllowedIPs: []string{"10.82.0.2/32"}},
			{ID: "gateway-2", Kind: "GATEWAY", PublicKey: gatewayTwo.Public, Address: "10.84.0.2/32", WebUIPort: 8443, AllowedIPs: []string{"10.84.0.2/32"}},
		},
		AdminRelays: []vpsagent.VPSHostAdminRelay{
			{ID: "relay-1", GatewayPeerID: "gateway-1", PublicEndpointHost: "vps.example.net", PublicBindAddress: "203.0.113.10", PublicUDPPort: 51823, GatewayAddress: "10.82.0.2", VPSSourceAddress: "10.82.0.1", DestinationPort: 51822, RateLimitPerSecond: 100, BurstPackets: 200},
			{ID: "relay-2", GatewayPeerID: "gateway-2", PublicEndpointHost: "vps.example.net", PublicBindAddress: "203.0.113.11", PublicUDPPort: 51824, GatewayAddress: "10.84.0.2", VPSSourceAddress: "10.84.0.1", DestinationPort: 51822, RateLimitPerSecond: 100, BurstPackets: 200},
		},
	}
	if _, err := RenderFirewall(plan); err != nil {
		t.Fatal(err)
	}
	plan.Generation++
	plan.AdminRelays = append([]vpsagent.VPSHostAdminRelay(nil), plan.AdminRelays[1])
	payload, err := RenderFirewall(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	if strings.Contains(text, "relay-1") || !strings.Contains(text, "gateway-vpn administrator relay dnat relay-2") ||
		!strings.Contains(text, "ip daddr 203.0.113.11 udp dport 51824") || !strings.Contains(text, "snat ip to 10.84.0.1") {
		t.Fatalf("selective relay removal changed the surviving relay:\n%s", text)
	}
}
