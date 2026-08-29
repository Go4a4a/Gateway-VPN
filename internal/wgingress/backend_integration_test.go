package wgingress

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/uplink"
)

// This test intentionally mutates the current network namespace. It is run
// only by the privileged disposable Linux/netns gate, never by the ordinary
// package suite or on a developer host.
func TestBackendAgainstKernelWireGuardNamespace(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_WG_INGRESS_INTEGRATION") != "1" {
		t.Skip("set GATEWAY_VPN_WG_INGRESS_INTEGRATION=1 inside a disposable privileged Linux network namespace")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("WireGuard ingress kernel integration requires Linux root in an isolated namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	executor := platformexec.OSExecutor{}
	clientNamespace := "gvpn-wgc-" + strconv.Itoa(os.Getpid())
	cleanup := func() {
		_, _ = executor.Run(context.Background(), platformexec.Request{Executable: "/usr/sbin/ip", Arguments: []string{"netns", "delete", clientNamespace}})
		_, _ = executor.Run(context.Background(), platformexec.Request{Executable: "/usr/sbin/ip", Arguments: []string{"link", "delete", "lan0"}})
		_, _ = executor.Run(context.Background(), platformexec.Request{Executable: "/usr/sbin/nft", Arguments: []string{"delete", "table", "inet", firewall.TableName}})
	}
	cleanup()
	t.Cleanup(cleanup)

	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "netns", "add", clientNamespace)
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "link", "add", "lan0", "type", "veth", "peer", "name", "client0")
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "link", "set", "client0", "netns", clientNamespace)
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "address", "replace", "192.0.2.1/24", "dev", "lan0")
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "link", "set", "lan0", "up")
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "netns", "exec", clientNamespace, "/usr/sbin/ip", "link", "set", "lo", "up")
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "netns", "exec", clientNamespace, "/usr/sbin/ip", "address", "replace", "192.0.2.2/24", "dev", "client0")
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "netns", "exec", clientNamespace, "/usr/sbin/ip", "link", "set", "client0", "up")

	ruleset, err := firewall.RenderBootBlocked(firewall.BootConfig{
		LANInterface: "lan0", TUNInterface: "gateway-vpn-tun", WireGuardInterface: "wg-mgmt",
		APIPort: 8443, WireGuardListenPort: 51821,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := firewall.ValidateAndLoad(ctx, executor, ruleset, firewall.LoadOptions{NFTExecutable: "/usr/sbin/nft", Mutate: true}); err != nil {
		t.Fatalf("load isolated Gateway firewall: %v", err)
	}

	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	uplinks := uplink.NewRepository(database, 300, 0x1101)
	if _, err := uplinks.EnsureManagedLANInterface(ctx, "lan0", "192.0.2.1/24"); err != nil {
		t.Fatal(err)
	}
	secretRoot := filepath.Join(t.TempDir(), "wireguard-ingress")
	backend := Backend{
		Repository: Repository{Database: database, SecretRoot: secretRoot},
		Keys:       KeyStore{Root: secretRoot}, Executor: executor,
		IP: "/usr/sbin/ip", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft", Mutate: true,
	}
	server, err := backend.UpdateServer(ctx, ServerUpdate{
		Enabled: true, Name: "Kernel integration", SubnetCIDR: "10.90.0.0/24",
		ListenPort: 51820, EndpointHost: "192.0.2.1", MTU: 1420, TopologyMode: "ROUTED",
		DNS: []string{"1.1.1.1"}, ListenInterfaces: []ListenInterface{{
			NetworkInterfaceID: uplink.ManagedLANInterfaceID, ExposureMode: "LOCAL", Priority: 1,
		}},
	})
	if err != nil || server.State != "ACTIVE" || server.AppliedGeneration != server.DesiredGeneration {
		t.Fatalf("activate kernel WireGuard ingress = %+v, %v", server, err)
	}
	peer, err := backend.CreatePeer(ctx, PeerCreate{
		Name: "Kernel client", PeerKind: "DEVICE", KeyMode: "MANAGED",
		PersistentKeepalive: 1, AccessPolicyMode: "AUTO", AllowWhitelistOnly: true,
		BlockWhenUnqualified: true, ClientAllowedIPs: []string{"0.0.0.0/0"},
	})
	if err != nil || peer.AssignedAddress != "10.90.0.2" || !peer.PrivateKeyAvailable {
		t.Fatalf("create kernel WireGuard peer = %+v, %v", peer, err)
	}
	clientPrivate, err := backend.Keys.Read(peer.privateKeySecretRef)
	if err != nil {
		t.Fatal(err)
	}
	preshared, err := backend.Keys.Read(peer.presharedKeySecretRef)
	if err != nil {
		t.Fatal(err)
	}
	clientConfiguration := []byte(fmt.Sprintf(`[Interface]
PrivateKey = %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = 192.0.2.1:51820
AllowedIPs = 10.90.0.0/24
PersistentKeepalive = 1
`, clientPrivate, server.PublicKey, preshared))
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "netns", "exec", clientNamespace, "/usr/sbin/ip", "link", "add", "wg-client", "type", "wireguard")
	mustKernelRunWithInput(t, ctx, executor, clientConfiguration, "/usr/sbin/ip", "netns", "exec", clientNamespace, "/usr/bin/wg", "syncconf", "wg-client", "/dev/stdin")
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "netns", "exec", clientNamespace, "/usr/sbin/ip", "address", "replace", "10.90.0.2/24", "dev", "wg-client")
	mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "netns", "exec", clientNamespace, "/usr/sbin/ip", "link", "set", "wg-client", "up")

	// A one-byte DNS datagram is enough to generate encrypted traffic and a real
	// handshake. No external network or test-only listener is required.
	_, _ = executor.Run(ctx, platformexec.Request{Executable: "/usr/sbin/ip", Arguments: []string{
		"netns", "exec", clientNamespace, "/bin/bash", "-c", "printf x >/dev/udp/10.90.0.1/53",
	}})
	deadline := time.Now().Add(5 * time.Second)
	for {
		observed, probeErr := backend.ProbePeer(ctx, peer.ID)
		if probeErr == nil && observed.LastHandshakeAt != "" && observed.RuntimeState == "HEALTHY" {
			peer = observed
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("kernel WireGuard handshake was not observed: peer=%+v error=%v", observed, probeErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	listeners := mustKernelRun(t, ctx, executor, "/usr/sbin/nft", "list", "set", "inet", firewall.TableName, listenerSetName)
	if !strings.Contains(listeners.Stdout, `"lan0" . 51820`) {
		t.Fatalf("WireGuard ingress listener is not scoped to LAN: %s", listeners.Stdout)
	}
	address := mustKernelRun(t, ctx, executor, "/usr/sbin/ip", "-4", "-o", "address", "show", "dev", DefaultInterfaceName)
	if !strings.Contains(address.Stdout, "10.90.0.1/24") {
		t.Fatalf("WireGuard ingress address is missing: %s", address.Stdout)
	}

	if _, err := backend.RevokePeer(ctx, peer.ID); err != nil {
		t.Fatal(err)
	}
	peers := mustKernelRun(t, ctx, executor, "/usr/bin/wg", "show", DefaultInterfaceName, "peers")
	if strings.TrimSpace(peers.Stdout) != "" {
		t.Fatalf("revoked WireGuard peer remains in kernel: %s", peers.Stdout)
	}
	server, err = backend.UpdateServer(ctx, ServerUpdate{
		Enabled: false, Name: server.Name, SubnetCIDR: server.SubnetCIDR,
		ListenPort: server.ListenPort, EndpointHost: server.EndpointHost, MTU: server.MTU,
		TopologyMode: server.TopologyMode, DNS: server.DNS, ListenInterfaces: server.ListenInterfaces,
	})
	if err != nil || server.State != "DISABLED" {
		t.Fatalf("disable kernel WireGuard ingress = %+v, %v", server, err)
	}
	if _, err := executor.Run(ctx, platformexec.Request{Executable: "/usr/sbin/ip", Arguments: []string{"link", "show", "dev", DefaultInterfaceName}}); err == nil {
		t.Fatal("disabled WireGuard ingress interface remains in kernel")
	}
}

func mustKernelRun(t *testing.T, ctx context.Context, executor platformexec.Executor, executable string, arguments ...string) platformexec.Result {
	t.Helper()
	return mustKernelRunWithInput(t, ctx, executor, nil, executable, arguments...)
}

func mustKernelRunWithInput(t *testing.T, ctx context.Context, executor platformexec.Executor, input []byte, executable string, arguments ...string) platformexec.Result {
	t.Helper()
	result, err := executor.Run(ctx, platformexec.Request{Executable: executable, Arguments: arguments, Stdin: input})
	if err != nil {
		t.Fatalf("isolated kernel command %s failed: exit=%d", filepath.Base(executable), result.ExitCode)
	}
	return result
}
