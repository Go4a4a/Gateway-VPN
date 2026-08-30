//go:build linux

package vpsfabric

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/gatewayfabric"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

const endToEndRelayKernelEnvironment = "GATEWAY_VPN_E2E_RELAY_KERNEL_INTEGRATION"

// TestEndToEndRelayKernelGate proves that the VPS forwards only the encrypted
// inner WireGuard datagram.  The administrator is absent from wg-mgmt and the
// resource ACL is enforced only after wg-admin authenticates the inner peer at
// the Gateway.
func TestEndToEndRelayKernelGate(t *testing.T) {
	if os.Getenv(endToEndRelayKernelEnvironment) != "1" {
		t.Skip("set GATEWAY_VPN_E2E_RELAY_KERNEL_INTEGRATION=1 inside a disposable privileged Linux host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("end-to-end relay kernel gate requires root in a disposable namespace")
	}
	requireKernelCommands(t, "/usr/sbin/ip", "/usr/bin/wg", "/usr/sbin/nft", "/usr/sbin/sysctl")

	suffix := strconv.Itoa(os.Getpid() % 10000)
	gatewayNamespace := "gve2eg-" + suffix
	adminNamespace := "gve2ea-" + suffix
	gatewayUnderlayRoot := "e2eg" + suffix
	adminUnderlayRoot := "e2ea" + suffix
	underlayOctet := 20 + os.Getpid()%200
	vpsUnderlay := fmt.Sprintf("198.18.%d.1", underlayOctet)
	gatewayUnderlay := fmt.Sprintf("198.18.%d.2", underlayOctet)

	cleanupEndToEndRelayKernel(gatewayNamespace, adminNamespace, gatewayUnderlayRoot, adminUnderlayRoot)
	t.Cleanup(func() {
		cleanupEndToEndRelayKernel(gatewayNamespace, adminNamespace, gatewayUnderlayRoot, adminUnderlayRoot)
	})

	originalForward := strings.TrimSpace(kernelOutput(t, "/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward"))
	kernelCommand(t, "/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1")
	t.Cleanup(func() {
		_, _ = exec.Command("/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward="+originalForward).CombinedOutput()
	})

	kernelCommand(t, "/usr/sbin/ip", "netns", "add", gatewayNamespace)
	kernelCommand(t, "/usr/sbin/ip", "netns", "add", adminNamespace)
	kernelCommand(t, "/usr/sbin/ip", "link", "add", gatewayUnderlayRoot, "type", "veth", "peer", "name", "eth-vps", "netns", gatewayNamespace)
	kernelCommand(t, "/usr/sbin/ip", "address", "add", vpsUnderlay+"/30", "dev", gatewayUnderlayRoot)
	kernelCommand(t, "/usr/sbin/ip", "link", "set", gatewayUnderlayRoot, "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "link", "set", "lo", "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "address", "add", gatewayUnderlay+"/30", "dev", "eth-vps")
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "link", "set", "eth-vps", "up")

	kernelCommand(t, "/usr/sbin/ip", "link", "add", adminUnderlayRoot, "type", "veth", "peer", "name", "eth0", "netns", adminNamespace)
	kernelCommand(t, "/usr/sbin/ip", "address", "add", "203.0.113.10/29", "dev", adminUnderlayRoot)
	kernelCommand(t, "/usr/sbin/ip", "link", "set", adminUnderlayRoot, "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", adminNamespace, "link", "set", "lo", "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", adminNamespace, "address", "add", "203.0.113.11/29", "dev", "eth0")
	kernelCommand(t, "/usr/sbin/ip", "-n", adminNamespace, "link", "set", "eth0", "up")

	vpsOuter, _ := wgingress.GenerateKeyPair()
	gatewayOuter, _ := wgingress.GenerateKeyPair()
	gatewayInner, _ := wgingress.GenerateKeyPair()
	adminInner, _ := wgingress.GenerateKeyPair()
	root := t.TempDir()
	vpsOuterKey := writeRelayKernelKey(t, root, "vps-outer.key", vpsOuter.Private)
	gatewayOuterKey := writeRelayKernelKey(t, root, "gateway-outer.key", gatewayOuter.Private)
	gatewayInnerKey := writeRelayKernelKey(t, root, "gateway-inner.key", gatewayInner.Private)
	adminInnerKey := writeRelayKernelKey(t, root, "admin-inner.key", adminInner.Private)

	kernelCommand(t, "/usr/sbin/ip", "link", "add", "wg-mgmt", "type", "wireguard")
	kernelCommand(t, "/usr/sbin/ip", "address", "add", "10.80.0.1/24", "dev", "wg-mgmt")
	kernelCommand(t, "/usr/sbin/ip", "address", "add", "10.82.0.1/30", "dev", "wg-mgmt")
	kernelCommand(t, "/usr/bin/wg", "set", "wg-mgmt", "private-key", vpsOuterKey, "listen-port", "51821",
		"peer", gatewayOuter.Public, "allowed-ips", "10.82.0.2/32,10.96.1.1/32", "endpoint", gatewayUnderlay+":51821", "persistent-keepalive", "1")
	kernelCommand(t, "/usr/sbin/ip", "link", "set", "wg-mgmt", "up")
	kernelCommand(t, "/usr/sbin/ip", "route", "replace", "10.82.0.2/32", "dev", "wg-mgmt")
	kernelCommand(t, "/usr/sbin/ip", "route", "replace", "10.96.1.1/32", "dev", "wg-mgmt")

	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "link", "add", "gvm1", "type", "wireguard")
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "address", "add", "10.82.0.2/32", "dev", "gvm1")
	kernelCommand(t, "/usr/sbin/ip", "netns", "exec", gatewayNamespace, "/usr/bin/wg", "set", "gvm1", "private-key", gatewayOuterKey, "listen-port", "51821",
		"peer", vpsOuter.Public, "allowed-ips", "10.82.0.1/32", "endpoint", vpsUnderlay+":51821", "persistent-keepalive", "1")
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "link", "set", "gvm1", "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "route", "replace", "10.82.0.1/32", "dev", "gvm1")

	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "link", "add", managementfabric.AdminInterfaceName, "type", "wireguard")
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "address", "add", "10.83.0.1/24", "dev", managementfabric.AdminInterfaceName)
	kernelCommand(t, "/usr/sbin/ip", "netns", "exec", gatewayNamespace, "/usr/bin/wg", "set", managementfabric.AdminInterfaceName,
		"private-key", gatewayInnerKey, "listen-port", "51822", "peer", adminInner.Public, "allowed-ips", "10.83.0.10/32")
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "link", "set", managementfabric.AdminInterfaceName, "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "route", "replace", "10.83.0.10/32", "dev", managementfabric.AdminInterfaceName)
	kernelCommand(t, "/usr/sbin/ip", "-n", gatewayNamespace, "address", "add", "192.168.200.1/32", "dev", "lo")

	kernelCommand(t, "/usr/sbin/ip", "-n", adminNamespace, "link", "add", "wg-inner", "type", "wireguard")
	kernelCommand(t, "/usr/sbin/ip", "-n", adminNamespace, "address", "add", "10.83.0.10/32", "dev", "wg-inner")
	kernelCommand(t, "/usr/sbin/ip", "netns", "exec", adminNamespace, "/usr/bin/wg", "set", "wg-inner", "private-key", adminInnerKey,
		"peer", gatewayInner.Public, "allowed-ips", "10.83.0.0/24,10.96.1.1/32", "endpoint", "203.0.113.10:51823", "persistent-keepalive", "1")
	kernelCommand(t, "/usr/sbin/ip", "-n", adminNamespace, "link", "set", "wg-inner", "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", adminNamespace, "route", "replace", "10.83.0.0/24", "dev", "wg-inner")
	kernelCommand(t, "/usr/sbin/ip", "-n", adminNamespace, "route", "replace", "10.96.1.1/32", "dev", "wg-inner")

	vpsPlan := vpsagent.VPSHostPlan{
		Generation: 1, InterfaceName: "wg-mgmt", ListenPort: 51821, RouteProtocol: 186,
		InterfaceAddresses: []string{"10.80.0.1/24", "10.82.0.1/30"},
		Peers: []vpsagent.VPSHostPeer{{
			ID: "gateway-e2e", Kind: "GATEWAY", PublicKey: gatewayOuter.Public,
			Address: "10.82.0.2/32", WebUIPort: 8443, AllowedIPs: []string{"10.82.0.2/32", "10.96.1.1/32"},
		}},
		ResourceRoutes: []vpsagent.VPSHostRoute{{PublicationID: "publication-e2e", GatewayPeerID: "gateway-e2e", Destination: "10.96.1.1/32", Protocol: 186}},
		AdminRelays: []vpsagent.VPSHostAdminRelay{{
			ID: "relay-e2e", GatewayPeerID: "gateway-e2e", PublicEndpointHost: "203.0.113.10", PublicBindAddress: "203.0.113.10",
			PublicUDPPort: 51823, GatewayAddress: "10.82.0.2", VPSSourceAddress: "10.82.0.1",
			DestinationPort: 51822, RateLimitPerSecond: 100, BurstPackets: 200,
		}},
	}
	vpsRules, err := RenderFirewall(vpsPlan)
	if err != nil {
		t.Fatal(err)
	}
	foreignBefore := createEndToEndForeignTables(t)
	if output, err := nftInput(vpsRules); err != nil {
		t.Fatalf("apply VPS relay firewall: %v: %s", err, output)
	}

	gatewayPlan := endToEndGatewayPlan(gatewayOuter, vpsOuter, gatewayInner, adminInner, vpsUnderlay)
	gatewayRules, err := gatewayfabric.RenderFirewallTransaction(gatewayPlan)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := nftNamespaceInput(gatewayNamespace, []byte(endToEndGatewayBaseFirewall)); err != nil {
		t.Fatalf("create Gateway relay firewall base: %v: %s", err, output)
	}
	if output, err := nftNamespaceInput(gatewayNamespace, gatewayRules); err != nil {
		t.Fatalf("apply Gateway relay firewall transaction: %v: %s", err, output)
	}

	waitEndToEndHandshake(t, gatewayNamespace, adminNamespace)
	allowedServer := startKernelTCPServer(t, gatewayNamespace, "192.168.200.1:8443")
	deniedServer := startKernelTCPServer(t, gatewayNamespace, "192.168.200.1:8444")
	expectKernelTCP(t, adminNamespace, "10.96.1.1:8443", true)
	expectKernelTCP(t, adminNamespace, "10.96.1.1:8444", false)
	expectEndToEndRootTCP(t, "10.96.1.1:8443", "", false)
	// A compromised VPS may assign the known inner administrator address, but
	// plaintext injection over the outer wg-mgmt peer must still fail.  It is
	// neither authenticated by wg-admin nor accepted by the Gateway ACL input
	// interface, and WireGuard cryptokey routing also rejects the forged source.
	kernelCommand(t, "/usr/sbin/ip", "address", "add", "10.83.0.10/32", "dev", "lo")
	expectEndToEndRootTCP(t, "10.96.1.1:8443", "10.83.0.10", false)
	kernelCommand(t, "/usr/sbin/ip", "address", "delete", "10.83.0.10/32", "dev", "lo")
	if allowedServer.Process != nil {
		_, _ = allowedServer.Process.Wait()
	}
	kernelCommand(t, "/usr/sbin/ip", "netns", "exec", adminNamespace, "/usr/bin/wg", "set", "wg-inner", "peer", gatewayInner.Public, "remove")
	kernelCommand(t, "/usr/sbin/ip", "netns", "exec", adminNamespace, "/usr/bin/wg", "set", "wg-inner",
		"peer", gatewayInner.Public, "allowed-ips", "10.83.0.0/24,10.96.1.1/32", "endpoint", "203.0.113.10:51824", "persistent-keepalive", "1")
	wrongPortServer := startKernelTCPServer(t, gatewayNamespace, "192.168.200.1:8443")
	expectKernelTCP(t, adminNamespace, "10.96.1.1:8443", false)
	if wrongPortServer.Process != nil {
		_ = wrongPortServer.Process.Kill()
		_, _ = wrongPortServer.Process.Wait()
	}
	kernelCommand(t, "/usr/sbin/ip", "netns", "exec", adminNamespace, "/usr/bin/wg", "set", "wg-inner", "peer", gatewayInner.Public, "remove")
	kernelCommand(t, "/usr/sbin/ip", "netns", "exec", adminNamespace, "/usr/bin/wg", "set", "wg-inner",
		"peer", gatewayInner.Public, "allowed-ips", "10.83.0.0/24,10.96.1.1/32", "endpoint", "203.0.113.10:51823", "persistent-keepalive", "1")
	waitEndToEndHandshake(t, gatewayNamespace, adminNamespace)
	recoveredServer := startKernelTCPServer(t, gatewayNamespace, "192.168.200.1:8443")
	expectKernelTCP(t, adminNamespace, "10.96.1.1:8443", true)

	if output, err := exec.Command("/usr/sbin/ip", "link", "show", managementfabric.AdminInterfaceName).CombinedOutput(); err == nil {
		t.Fatalf("VPS unexpectedly terminates inner wg-admin: %s", output)
	}
	vpsPeers := strings.Fields(kernelOutput(t, "/usr/bin/wg", "show", "wg-mgmt", "peers"))
	if len(vpsPeers) != 1 || vpsPeers[0] != gatewayOuter.Public || strings.Contains(strings.Join(vpsPeers, " "), adminInner.Public) {
		t.Fatalf("VPS outer peer set contains inner administrator identity: %v", vpsPeers)
	}
	relayCounters := kernelOutput(t, "/usr/sbin/nft", "-a", "list", "table", "inet", "gateway_vpn_vps")
	rules, packets, bytes, counterErr := parseRelayCounters(relayCounters, []string{"relay-e2e"})
	if counterErr != nil || rules != 5 || packets == 0 || bytes == 0 {
		t.Fatalf("VPS relay did not account encrypted UDP datagrams: rules=%d packets=%d bytes=%d err=%v\n%s", rules, packets, bytes, counterErr, relayCounters)
	}
	assertForeignTables(t, foreignBefore)

	if deniedServer.Process != nil {
		_ = deniedServer.Process.Kill()
		_, _ = deniedServer.Process.Wait()
	}
	if recoveredServer.Process != nil {
		_, _ = recoveredServer.Process.Wait()
	}
}

func endToEndGatewayPlan(gatewayOuter, vpsOuter, gatewayInner, adminInner wgingress.KeyPair, vpsUnderlay string) managementfabric.GatewayHostPlan {
	return managementfabric.GatewayHostPlan{
		Generation: 1, RouteProtocol: managementfabric.OwnedRouteProtocol,
		Links: []managementfabric.GatewayHostLink{{
			LinkID: "link:e2e", VPSID: "vps:e2e", InterfaceName: "gvm1",
			LocalAddress: "10.82.0.2/32", ManagementSubnet: "10.82.0.0/30", RemoteAddress: "10.82.0.1/32",
			PrivateKeyRef:  "/var/lib/gateway-vpn/secrets/management/link-e2e.key",
			LocalPublicKey: gatewayOuter.Public, RemotePublicKey: vpsOuter.Public, AllowedIPs: []string{"10.82.0.1/32"},
			EndpointAddress: vpsUnderlay, EndpointPort: 51821, PersistentKeepalive: 10,
			UplinkID: "uplink:e2e", UplinkInterface: "eth-vps", UplinkGateway: vpsUnderlay,
			UplinkTable: 1101, UplinkMark: 0x1101, UplinkGeneration: 1,
			Routes: []managementfabric.RenderedRoute{{Owner: "gateway-vpn", LinkID: "link:e2e", InterfaceName: "gvm1", Destination: "10.82.0.0/30", Purpose: "MANAGEMENT_LINK", Protocol: 186}},
		}},
		AdminContour: &managementfabric.RenderedAdminContour{
			InterfaceName:       managementfabric.AdminInterfaceName,
			PrivateKeySecretRef: "/var/lib/gateway-vpn/secrets/management/wg-admin.key",
			PublicKey:           gatewayInner.Public, Subnet: "10.83.0.0/24", GatewayAddress: "10.83.0.1/32", ListenPort: 51822,
			Relays: []managementfabric.RenderedAdminRelayIngress{{
				RelayID: "relay:e2e", LinkID: "link:e2e", InputInterface: "gvm1",
				OuterSource: "10.82.0.1/32", OuterDestination: "10.82.0.2/32",
				PublicEndpointHost: "203.0.113.10", PublicBindAddress: "203.0.113.10", PublicUDPPort: 51823,
				DestinationPort: 51822, RateLimitPerSecond: 100, BurstPackets: 200,
			}},
			Peers: []managementfabric.RenderedAdminPeer{{
				TunnelID: "tunnel:e2e", AdminID: "admin:e2e", RelayID: "relay:e2e", LinkID: "link:e2e",
				PublicKey: adminInner.Public, AssignedAddress: "10.83.0.10/32",
			}},
		},
		Aliases: []managementfabric.RenderedAlias{{
			PublicationID: "publication:e2e", ResourceID: "resource:e2e", LinkID: "link:e2e", InterfaceName: "gvm1",
			ResourceKind: managementfabric.ResourceGatewayService, AccessProfile: managementfabric.ProfileGatewayOnly,
			PublishedAlias: "10.96.1.1/32", LocalDestination: "192.168.200.1",
		}},
		ACL: []managementfabric.RenderedACLRule{{
			RuleID: "acl:e2e", AdminID: "admin:e2e", ResourceID: "resource:e2e", PublicationID: "publication:e2e",
			LinkID: "link:e2e", InputInterface: managementfabric.AdminInterfaceName,
			ResourceKind: managementfabric.ResourceGatewayService, AccessProfile: managementfabric.ProfileGatewayOnly,
			Source: "10.83.0.10/32", PublishedAlias: "10.96.1.1/32", LocalDestination: "192.168.200.1",
			Protocol: managementfabric.ProtocolTCP, PortStart: 8443, PortEnd: 8443,
			TrustMode: managementfabric.TrustEndToEndRelay, TunnelID: "tunnel:e2e", RelayID: "relay:e2e",
		}},
	}
}

const endToEndGatewayBaseFirewall = `table inet gateway_vpn {
    set management_fabric_interfaces { type ifname; }
    set management_fabric_endpoints { type ifname . mark . ipv4_addr . inet_service; }
    set management_fabric_generation { type mark; }
    chain input {
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state { established, related } accept
        iifname "eth-vps" udp dport 51821 accept
        jump management_fabric_input
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state { established, related } accept
        jump management_fabric_forward
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        jump management_fabric_postrouting
    }
    chain management_fabric_input { }
    chain management_fabric_forward { }
    chain management_fabric_postrouting { }
    chain management_fabric_prerouting {
        type nat hook prerouting priority dstnat; policy accept;
    }
}
`

func writeRelayKernelKey(t *testing.T, root, name, key string) string {
	t.Helper()
	filename := filepath.Join(root, name)
	if err := os.WriteFile(filename, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filename
}

func nftNamespaceInput(namespace string, input []byte) ([]byte, error) {
	command := exec.Command("/usr/sbin/ip", "netns", "exec", namespace, "/usr/sbin/nft", "--file", "-")
	command.Stdin = bytes.NewReader(input)
	return command.CombinedOutput()
}

func waitEndToEndHandshake(t *testing.T, gatewayNamespace, adminNamespace string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		admin, adminErr := exec.Command("/usr/sbin/ip", "netns", "exec", adminNamespace, "/usr/bin/wg", "show", "wg-inner", "latest-handshakes").CombinedOutput()
		gatewayTransfer, gatewayErr := exec.Command("/usr/sbin/ip", "netns", "exec", gatewayNamespace, "/usr/bin/wg", "show", "wg-admin", "transfer").CombinedOutput()
		if gatewayErr == nil && adminErr == nil && liveHandshake(admin) && liveTransfer(gatewayTransfer) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("inner wg-admin handshake did not complete\nGateway:\n%s\nAdmin:\n%s",
		kernelOutput(t, "/usr/sbin/ip", "netns", "exec", gatewayNamespace, "/usr/bin/wg", "show", "wg-admin"),
		kernelOutput(t, "/usr/sbin/ip", "netns", "exec", adminNamespace, "/usr/bin/wg", "show", "wg-inner"))
}

func liveHandshake(output []byte) bool {
	fields := strings.Fields(string(output))
	return len(fields) == 2 && fields[1] != "0"
}

func liveTransfer(output []byte) bool {
	fields := strings.Fields(string(output))
	if len(fields) != 3 {
		return false
	}
	rx, rxErr := strconv.ParseUint(fields[1], 10, 64)
	tx, txErr := strconv.ParseUint(fields[2], 10, 64)
	return rxErr == nil && txErr == nil && rx > 0 && tx > 0
}

func expectEndToEndRootTCP(t *testing.T, address, source string, allowed bool) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run", "^TestFabricKernelTCPHelper$")
	command.Env = append(os.Environ(),
		"GATEWAY_VPN_VPS_FABRIC_TCP_HELPER=1",
		"GATEWAY_VPN_VPS_FABRIC_TCP_MODE=client",
		"GATEWAY_VPN_VPS_FABRIC_TCP_ADDRESS="+address,
		"GATEWAY_VPN_VPS_FABRIC_TCP_SOURCE="+source,
	)
	output, runErr := command.CombinedOutput()
	if allowed && runErr != nil {
		t.Fatalf("allowed VPS-root path to %s failed: %v: %s", address, runErr, output)
	}
	if !allowed && runErr == nil {
		t.Fatalf("VPS forged plaintext path to %s succeeded", address)
	}
}

func createEndToEndForeignTables(t *testing.T) map[string]string {
	t.Helper()
	foreign := []byte(`table inet ufw_e2e_gate {
    chain input {
        counter accept
    }
}
table inet docker_e2e_gate {
    chain forward {
        counter accept
    }
}
table inet amnezia_e2e_gate {
    chain vpn {
        counter accept
    }
}
`)
	if output, err := nftInput(foreign); err != nil {
		t.Fatalf("create end-to-end foreign tables: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_, _ = nftInput([]byte("delete table inet gateway_vpn_vps\ndelete table inet ufw_e2e_gate\ndelete table inet docker_e2e_gate\ndelete table inet amnezia_e2e_gate\n"))
	})
	return snapshotForeignTables(t, "ufw_e2e_gate", "docker_e2e_gate", "amnezia_e2e_gate")
}

func cleanupEndToEndRelayKernel(gatewayNamespace, adminNamespace, gatewayUnderlayRoot, adminUnderlayRoot string) {
	_, _ = exec.Command("/usr/sbin/nft", "delete", "table", "inet", "gateway_vpn_vps").CombinedOutput()
	_, _ = exec.Command("/usr/sbin/ip", "link", "delete", "wg-mgmt").CombinedOutput()
	_, _ = exec.Command("/usr/sbin/ip", "link", "delete", gatewayUnderlayRoot).CombinedOutput()
	_, _ = exec.Command("/usr/sbin/ip", "link", "delete", adminUnderlayRoot).CombinedOutput()
	_, _ = exec.Command("/usr/sbin/ip", "netns", "delete", gatewayNamespace).CombinedOutput()
	_, _ = exec.Command("/usr/sbin/ip", "netns", "delete", adminNamespace).CombinedOutput()
}

func kernelOutput(t *testing.T, executable string, arguments ...string) string {
	t.Helper()
	output, err := exec.Command(executable, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("kernel output %s %s: %v: %s", executable, strings.Join(arguments, " "), err, output)
	}
	return string(output)
}
