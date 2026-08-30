//go:build linux

package vpsfabric

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

func TestRenderedFirewallPassesRealNFTParser(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_VPS_NFT_INTEGRATION") != "1" {
		t.Skip("set GATEWAY_VPN_VPS_NFT_INTEGRATION=1 inside a disposable Linux host")
	}
	server, _ := wgingress.GenerateKeyPair()
	gateway, _ := wgingress.GenerateKeyPair()
	gateway2, _ := wgingress.GenerateKeyPair()
	admin, _ := wgingress.GenerateKeyPair()
	admin2, _ := wgingress.GenerateKeyPair()
	plan := vpsagent.VPSHostPlan{
		Generation: 7, InterfaceName: vpsagent.VPSManagementInterface, ListenPort: vpsagent.VPSManagementPort,
		RouteProtocol: vpsagent.VPSOwnedRouteProtocol, InterfaceAddresses: []string{vpsagent.VPSHubAddressPrefix, "10.82.0.1/30", "10.84.0.1/30"},
		Peers: []vpsagent.VPSHostPeer{
			{ID: "admin-kernel", Kind: "ADMIN", PublicKey: admin.Public, Address: "10.81.0.10/32", AllowedIPs: []string{"10.81.0.10/32"}},
			{ID: "admin-kernel-2", Kind: "ADMIN", PublicKey: admin2.Public, Address: "10.81.0.11/32", AllowedIPs: []string{"10.81.0.11/32"}},
			{ID: "gateway-kernel", Kind: "GATEWAY", PublicKey: gateway.Public, Address: "10.82.0.2/32", WebUIPort: 9444, AllowedIPs: []string{"10.82.0.2/32", "10.96.0.2/32"}},
			{ID: "gateway-kernel-2", Kind: "GATEWAY", PublicKey: gateway2.Public, Address: "10.84.0.2/32", WebUIPort: 443, AllowedIPs: []string{"10.84.0.2/32", "10.97.0.2/32"}},
		},
		ResourceRoutes: []vpsagent.VPSHostRoute{
			{PublicationID: "publication-kernel", GatewayPeerID: "gateway-kernel", Destination: "10.96.0.2/32", Protocol: vpsagent.VPSOwnedRouteProtocol},
			{PublicationID: "publication-kernel-2", GatewayPeerID: "gateway-kernel-2", Destination: "10.97.0.2/32", Protocol: vpsagent.VPSOwnedRouteProtocol},
		},
		ACL: []vpsagent.VPSHostACLRule{
			{ID: "acl-kernel", AdminPeerID: "admin-kernel", GatewayPeerID: "gateway-kernel", PublicationID: "publication-kernel", Source: "10.81.0.10/32", Destination: "10.96.0.2/32", Protocol: "TCP", PortStart: 443, PortEnd: 443},
			{ID: "acl-kernel-2", AdminPeerID: "admin-kernel-2", GatewayPeerID: "gateway-kernel-2", PublicationID: "publication-kernel-2", Source: "10.81.0.11/32", Destination: "10.97.0.2/32", Protocol: "UDP", PortStart: 53, PortEnd: 53},
		},
		HubAdminSources: []string{"10.81.0.10/32", "10.81.0.11/32"},
		AdminRelays: []vpsagent.VPSHostAdminRelay{{
			ID: "relay-kernel", GatewayPeerID: "gateway-kernel", PublicEndpointHost: "vps.example.net",
			PublicBindAddress: "203.0.113.10", PublicUDPPort: 51823,
			GatewayAddress: "10.82.0.2", VPSSourceAddress: "10.82.0.1", DestinationPort: 51822,
			RateLimitPerSecond: 100, BurstPackets: 200,
		}},
	}
	rules, err := RenderFirewall(plan)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/sbin/nft", "--check", "--file", "-")
	command.Stdin = bytes.NewReader(rules)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("real nft parser rejected VPS fabric rules: %v: %s", err, output)
	}
	foreign := []byte(`table inet ufw_fixture {
    chain input {
        counter accept
    }
}
table inet docker_fixture {
    chain forward {
        counter accept
    }
}
table inet amnezia_fixture {
    chain vpn {
        counter accept
    }
}
`)
	if output, err := nftInput(foreign); err != nil {
		t.Fatalf("create foreign nft fixtures: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_, _ = nftInput([]byte("delete table inet gateway_vpn_vps\ndelete table inet ufw_fixture\ndelete table inet docker_fixture\ndelete table inet amnezia_fixture\n"))
	})
	before := make(map[string]string)
	for _, name := range []string{"ufw_fixture", "docker_fixture", "amnezia_fixture"} {
		output, err := exec.Command("/usr/sbin/nft", "list", "table", "inet", name).CombinedOutput()
		if err != nil {
			t.Fatalf("snapshot foreign table %s: %v: %s", name, err, output)
		}
		before[name] = string(output)
	}
	if output, err := nftInput(rules); err != nil {
		t.Fatalf("apply owned VPS fabric table: %v: %s", err, output)
	}
	for name, expected := range before {
		output, err := exec.Command("/usr/sbin/nft", "list", "table", "inet", name).CombinedOutput()
		if err != nil || string(output) != expected {
			t.Fatalf("foreign nft table %s changed: %v\nbefore=%s\nafter=%s", name, err, expected, output)
		}
	}
	wireGuard, err := RenderWireGuard(plan, server.Private)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "wg-mgmt.conf")
	if err := os.WriteFile(config, wireGuard, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/wg-quick", "up", config).CombinedOutput(); err != nil {
		t.Fatalf("real kernel rejected generated wg-mgmt: %v: %s", err, output)
	}
	t.Cleanup(func() { _, _ = exec.Command("/usr/bin/wg-quick", "down", config).CombinedOutput() })
	if output, err := exec.Command("/usr/bin/wg", "show", "wg-mgmt", "peers").CombinedOutput(); err != nil || len(strings.Fields(string(output))) != len(plan.Peers) {
		t.Fatalf("real wg-mgmt peer set differs: %v: %s", err, output)
	}
	for _, address := range plan.InterfaceAddresses {
		output, err := exec.Command("/usr/sbin/ip", "-4", "-o", "address", "show", "dev", "wg-mgmt").CombinedOutput()
		if err != nil || !strings.Contains(string(output), address) {
			t.Fatalf("real wg-mgmt address %s missing: %v: %s", address, err, output)
		}
	}
}

func nftInput(input []byte) ([]byte, error) {
	command := exec.Command("/usr/sbin/nft", "--file", "-")
	command.Stdin = bytes.NewReader(input)
	return command.CombinedOutput()
}
