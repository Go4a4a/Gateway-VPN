//go:build linux

package vpsfabric

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

const fabricKernelIntegrationEnvironment = "GATEWAY_VPN_VPS_FABRIC_KERNEL_INTEGRATION"

type kernelPeer struct {
	name             string
	interfaceAddress []string
	key              wgingress.KeyPair
}

func TestVPSFabricKernelHandshakesAndACL(t *testing.T) {
	if os.Getenv(fabricKernelIntegrationEnvironment) != "1" {
		t.Skip("set GATEWAY_VPN_VPS_FABRIC_KERNEL_INTEGRATION=1 inside a disposable privileged Linux host")
	}
	requireKernelCommands(t, "/usr/sbin/ip", "/usr/bin/wg", "/usr/bin/wg-quick", "/usr/sbin/nft")

	hub, _ := wgingress.GenerateKeyPair()
	admin1, _ := wgingress.GenerateKeyPair()
	admin2, _ := wgingress.GenerateKeyPair()
	gateway1, _ := wgingress.GenerateKeyPair()
	gateway2, _ := wgingress.GenerateKeyPair()
	plan := vpsagent.VPSHostPlan{
		Generation: 11, InterfaceName: vpsagent.VPSManagementInterface, ListenPort: vpsagent.VPSManagementPort,
		RouteProtocol: vpsagent.VPSOwnedRouteProtocol, InterfaceAddresses: []string{vpsagent.VPSHubAddressPrefix, "10.82.0.1/30", "10.84.0.1/30"},
		Peers: []vpsagent.VPSHostPeer{
			{ID: "admin-kernel-1", Kind: "ADMIN", PublicKey: admin1.Public, Address: "10.80.0.10/32", AllowedIPs: []string{"10.80.0.10/32"}},
			{ID: "admin-kernel-2", Kind: "ADMIN", PublicKey: admin2.Public, Address: "10.81.0.11/32", AllowedIPs: []string{"10.81.0.11/32"}},
			{ID: "gateway-kernel-1", Kind: "GATEWAY", PublicKey: gateway1.Public, Address: "10.82.0.2/32", WebUIPort: 9444, AllowedIPs: []string{"10.82.0.2/32", "10.96.0.2/32"}},
			{ID: "gateway-kernel-2", Kind: "GATEWAY", PublicKey: gateway2.Public, Address: "10.84.0.2/32", WebUIPort: 9445, AllowedIPs: []string{"10.84.0.2/32", "10.97.0.2/32"}},
		},
		ResourceRoutes: []vpsagent.VPSHostRoute{
			{PublicationID: "publication-kernel-1", GatewayPeerID: "gateway-kernel-1", Destination: "10.96.0.2/32", Protocol: vpsagent.VPSOwnedRouteProtocol},
			{PublicationID: "publication-kernel-2", GatewayPeerID: "gateway-kernel-2", Destination: "10.97.0.2/32", Protocol: vpsagent.VPSOwnedRouteProtocol},
		},
		ACL: []vpsagent.VPSHostACLRule{
			{ID: "acl-kernel-1", AdminPeerID: "admin-kernel-1", GatewayPeerID: "gateway-kernel-1", PublicationID: "publication-kernel-1", Source: "10.80.0.10/32", Destination: "10.96.0.2/32", Protocol: "TCP", PortStart: 443, PortEnd: 443},
			{ID: "acl-kernel-2", AdminPeerID: "admin-kernel-2", GatewayPeerID: "gateway-kernel-2", PublicationID: "publication-kernel-2", Source: "10.81.0.11/32", Destination: "10.97.0.2/32", Protocol: "TCP", PortStart: 8443, PortEnd: 8443},
		},
		HubAdminSources: []string{"10.80.0.10/32", "10.81.0.11/32"},
	}

	wireGuard, err := RenderWireGuard(plan, hub.Private)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := RenderFirewall(plan)
	if err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(t.TempDir(), "wg-mgmt.conf")
	if err := os.WriteFile(configuration, wireGuard, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/wg-quick", "up", configuration).CombinedOutput(); err != nil {
		t.Fatalf("bring up VPS wg-mgmt: %v: %s", err, output)
	}
	t.Cleanup(func() { _, _ = exec.Command("/usr/bin/wg-quick", "down", configuration).CombinedOutput() })

	foreign := []byte(`table inet ufw_fabric_gate {
    chain input {
        counter accept
    }
}
table inet docker_fabric_gate {
    chain forward {
        counter accept
    }
}
table inet amnezia_fabric_gate {
    chain vpn {
        counter accept
    }
}
`)
	if output, err := nftInput(foreign); err != nil {
		t.Fatalf("create foreign nftables fixtures: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_, _ = nftInput([]byte("delete table inet gateway_vpn_vps\ndelete table inet ufw_fabric_gate\ndelete table inet docker_fabric_gate\ndelete table inet amnezia_fabric_gate\n"))
	})
	foreignBefore := snapshotForeignTables(t, "ufw_fabric_gate", "docker_fabric_gate", "amnezia_fabric_gate")
	if output, err := nftInput(rules); err != nil {
		t.Fatalf("apply owned VPS fabric table: %v: %s", err, output)
	}
	if output, err := exec.Command("/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		t.Fatalf("enable forwarding in disposable namespace: %v: %s", err, output)
	}
	for _, peer := range plan.Peers {
		for _, route := range peer.AllowedIPs {
			kernelCommand(t, "/usr/sbin/ip", "-4", "route", "replace", route, "dev", "wg-mgmt", "protocol", strconv.Itoa(vpsagent.VPSOwnedRouteProtocol))
		}
	}

	suffix := strconv.Itoa(os.Getpid() % 10000)
	underlayOctet := 100 + os.Getpid()%100
	underlayNetwork := fmt.Sprintf("172.30.%d", underlayOctet)

	peers := []kernelPeer{
		{name: "admin1-" + suffix, interfaceAddress: []string{"10.80.0.10/32"}, key: admin1},
		{name: "admin2-" + suffix, interfaceAddress: []string{"10.81.0.11/32"}, key: admin2},
		{name: "gateway1-" + suffix, interfaceAddress: []string{"10.82.0.2/32", "10.96.0.2/32"}, key: gateway1},
		{name: "gateway2-" + suffix, interfaceAddress: []string{"10.84.0.2/32", "10.97.0.2/32"}, key: gateway2},
	}
	for index := range peers {
		createKernelPeer(t, underlayNetwork, index, hub.Public, &peers[index])
	}
	waitForKernelHandshakes(t, len(peers))

	hubServer := startKernelTCPServer(t, "", "10.80.0.1:9443")
	hubServerAdmin2 := startKernelTCPServer(t, "", "10.82.0.1:9443")
	gateway1Web := startKernelTCPServer(t, peers[2].name, "10.82.0.2:9444")
	gateway2Web := startKernelTCPServer(t, peers[3].name, "10.84.0.2:9445")
	resource1 := startKernelTCPServer(t, peers[2].name, "10.96.0.2:443")
	resource2 := startKernelTCPServer(t, peers[3].name, "10.97.0.2:8443")

	expectKernelTCP(t, peers[0].name, "10.80.0.1:9443", true)
	expectKernelTCP(t, peers[1].name, "10.82.0.1:9443", true)
	expectKernelTCP(t, peers[0].name, "10.82.0.2:9444", true)
	expectKernelTCP(t, peers[0].name, "10.84.0.2:9445", true)
	expectKernelTCP(t, peers[0].name, "10.96.0.2:443", true)
	expectKernelTCP(t, peers[1].name, "10.97.0.2:8443", true)

	unauthorizedResource := startKernelTCPServer(t, peers[3].name, "10.97.0.2:9446")
	adminPeer := startKernelTCPServer(t, peers[1].name, "10.81.0.11:9447")
	gatewayToGateway := startKernelTCPServer(t, peers[3].name, "10.84.0.2:9448")
	hubDeniedServer := startKernelTCPServer(t, "", "10.84.0.1:22")
	expectKernelTCP(t, peers[0].name, "10.97.0.2:9446", false)
	expectKernelTCP(t, peers[0].name, "10.81.0.11:9447", false)
	expectKernelTCP(t, peers[2].name, "10.84.0.2:9448", false)
	expectKernelTCP(t, peers[2].name, "10.84.0.1:22", false)

	for _, server := range []*exec.Cmd{hubServer, hubServerAdmin2, gateway1Web, gateway2Web, resource1, resource2, unauthorizedResource, adminPeer, gatewayToGateway, hubDeniedServer} {
		if server.Process != nil {
			_ = server.Process.Kill()
		}
		_, _ = server.Process.Wait()
	}
	assertForeignTables(t, foreignBefore)
}

func TestFabricKernelTCPHelper(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_VPS_FABRIC_TCP_HELPER") != "1" {
		t.Skip("helper process only")
	}
	address := os.Getenv("GATEWAY_VPN_VPS_FABRIC_TCP_ADDRESS")
	switch os.Getenv("GATEWAY_VPN_VPS_FABRIC_TCP_MODE") {
	case "server":
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := os.WriteFile(os.Getenv("GATEWAY_VPN_VPS_FABRIC_TCP_READY"), []byte("ready\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if deadline, ok := listener.(*net.TCPListener); ok {
			_ = deadline.SetDeadline(time.Now().Add(20 * time.Second))
		}
		connection, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		_, err = connection.Write([]byte("gateway-vpn-fabric-ok"))
		if err != nil {
			t.Fatal(err)
		}
	case "client":
		connection, err := net.DialTimeout("tcp4", address, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
		buffer := make([]byte, len("gateway-vpn-fabric-ok"))
		if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "gateway-vpn-fabric-ok" {
			t.Fatalf("fabric TCP response=%q err=%v", buffer, err)
		}
	default:
		t.Fatal("invalid fabric TCP helper mode")
	}
}

func createKernelPeer(t *testing.T, underlayNetwork string, index int, hubPublic string, peer *kernelPeer) {
	t.Helper()
	kernelCommand(t, "/usr/sbin/ip", "netns", "add", peer.name)
	t.Cleanup(func() { _, _ = exec.Command("/usr/sbin/ip", "netns", "delete", peer.name).CombinedOutput() })
	rootVeth := fmt.Sprintf("gv%d-%d", index, os.Getpid()%10000)
	baseAddress := index * 4
	hubUnderlay := fmt.Sprintf("%s.%d", underlayNetwork, baseAddress+1)
	peerUnderlay := fmt.Sprintf("%s.%d/30", underlayNetwork, baseAddress+2)
	kernelCommand(t, "/usr/sbin/ip", "link", "add", rootVeth, "type", "veth", "peer", "name", "eth0", "netns", peer.name)
	kernelCommand(t, "/usr/sbin/ip", "address", "add", hubUnderlay+"/30", "dev", rootVeth)
	kernelCommand(t, "/usr/sbin/ip", "link", "set", rootVeth, "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", peer.name, "link", "set", "lo", "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", peer.name, "address", "add", peerUnderlay, "dev", "eth0")
	kernelCommand(t, "/usr/sbin/ip", "-n", peer.name, "link", "set", "eth0", "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", peer.name, "link", "add", "wg-peer", "type", "wireguard")
	for _, address := range peer.interfaceAddress {
		kernelCommand(t, "/usr/sbin/ip", "-n", peer.name, "address", "add", address, "dev", "wg-peer")
	}
	privateKey := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(privateKey, []byte(peer.key.Private+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kernelCommand(t, "/usr/sbin/ip", "netns", "exec", peer.name, "/usr/bin/wg", "set", "wg-peer", "private-key", privateKey, "peer", hubPublic, "allowed-ips", "10.0.0.0/8", "endpoint", hubUnderlay+":"+strconv.Itoa(vpsagent.VPSManagementPort), "persistent-keepalive", "1")
	kernelCommand(t, "/usr/sbin/ip", "-n", peer.name, "link", "set", "wg-peer", "up")
	kernelCommand(t, "/usr/sbin/ip", "-n", peer.name, "route", "replace", "10.0.0.0/8", "dev", "wg-peer")
}

func waitForKernelHandshakes(t *testing.T, expected int) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		output, err := exec.Command("/usr/bin/wg", "show", "wg-mgmt", "latest-handshakes").CombinedOutput()
		fields := strings.Fields(string(output))
		valid := err == nil && len(fields) == expected*2
		for index := 1; valid && index < len(fields); index += 2 {
			valid = fields[index] != "0"
		}
		if valid {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	output, _ := exec.Command("/usr/bin/wg", "show", "wg-mgmt", "latest-handshakes").CombinedOutput()
	t.Fatalf("expected %d live WireGuard handshakes, got %s", expected, output)
}

func startKernelTCPServer(t *testing.T, namespace, address string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	arguments := []string{executable, "-test.run", "^TestFabricKernelTCPHelper$"}
	if namespace != "" {
		arguments = append([]string{"netns", "exec", namespace}, arguments...)
	}
	command := exec.Command("/usr/sbin/ip", arguments...)
	if namespace == "" {
		command = exec.Command(executable, "-test.run", "^TestFabricKernelTCPHelper$")
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	command.Env = append(os.Environ(),
		"GATEWAY_VPN_VPS_FABRIC_TCP_HELPER=1",
		"GATEWAY_VPN_VPS_FABRIC_TCP_MODE=server",
		"GATEWAY_VPN_VPS_FABRIC_TCP_ADDRESS="+address,
		"GATEWAY_VPN_VPS_FABRIC_TCP_READY="+ready,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			return command
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = command.Process.Kill()
	_, _ = command.Process.Wait()
	t.Fatalf("fabric TCP server %s in %q did not become ready: %s", address, namespace, output.String())
	return nil
}

func expectKernelTCP(t *testing.T, namespace, address string, allowed bool) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/sbin/ip", "netns", "exec", namespace, executable, "-test.run", "^TestFabricKernelTCPHelper$")
	command.Env = append(os.Environ(),
		"GATEWAY_VPN_VPS_FABRIC_TCP_HELPER=1",
		"GATEWAY_VPN_VPS_FABRIC_TCP_MODE=client",
		"GATEWAY_VPN_VPS_FABRIC_TCP_ADDRESS="+address,
	)
	output, runErr := command.CombinedOutput()
	if allowed && runErr != nil {
		t.Fatalf("allowed fabric path %s -> %s failed: %v: %s\n%s", namespace, address, runErr, output, kernelFabricDiagnostics(namespace))
	}
	if !allowed && runErr == nil {
		t.Fatalf("forbidden fabric path %s -> %s succeeded", namespace, address)
	}
}

func kernelFabricDiagnostics(namespace string) string {
	commands := [][]string{
		{"/usr/bin/wg", "show", "wg-mgmt"},
		{"/usr/sbin/ip", "-4", "route", "show", "dev", "wg-mgmt"},
		{"/usr/sbin/nft", "-a", "list", "table", "inet", "gateway_vpn_vps"},
		{"/usr/sbin/ip", "netns", "exec", namespace, "/usr/bin/wg", "show", "wg-peer"},
		{"/usr/sbin/ip", "-n", namespace, "-4", "route", "show"},
		{"/usr/sbin/ip", "-n", namespace, "-4", "route", "get", "10.97.0.2"},
	}
	var result strings.Builder
	for _, item := range commands {
		output, err := exec.Command(item[0], item[1:]...).CombinedOutput()
		fmt.Fprintf(&result, "$ %s\n%s(error=%v)\n", strings.Join(item, " "), output, err)
	}
	return result.String()
}

func snapshotForeignTables(t *testing.T, names ...string) map[string]string {
	t.Helper()
	result := make(map[string]string, len(names))
	for _, name := range names {
		output, err := exec.Command("/usr/sbin/nft", "list", "table", "inet", name).CombinedOutput()
		if err != nil {
			t.Fatalf("snapshot foreign nftables table %s: %v: %s", name, err, output)
		}
		result[name] = string(output)
	}
	return result
}

func assertForeignTables(t *testing.T, expected map[string]string) {
	t.Helper()
	for name, before := range expected {
		output, err := exec.Command("/usr/sbin/nft", "list", "table", "inet", name).CombinedOutput()
		if err != nil || string(output) != before {
			t.Fatalf("foreign nftables table %s changed: %v\nbefore=%s\nafter=%s", name, err, before, output)
		}
	}
}

func requireKernelCommands(t *testing.T, commands ...string) {
	t.Helper()
	for _, command := range commands {
		if info, err := os.Stat(command); err != nil || info.IsDir() {
			t.Fatalf("required kernel test command %s is unavailable", command)
		}
	}
}

func kernelCommand(t *testing.T, executable string, arguments ...string) {
	t.Helper()
	if output, err := exec.Command(executable, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("kernel command %s %s failed: %v: %s", executable, strings.Join(arguments, " "), err, output)
	}
}
