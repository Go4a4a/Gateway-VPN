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
