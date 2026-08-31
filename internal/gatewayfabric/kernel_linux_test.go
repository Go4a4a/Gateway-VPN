//go:build linux

package gatewayfabric

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/wgingress"
)

const gatewayFabricKernelEnvironment = "GATEWAY_VPN_GATEWAY_FABRIC_KERNEL_INTEGRATION"

type gatewayKernelLink struct {
	namespace, uplink, underlayCIDR, gateway, endpoint string
	listenPort, table, mark                            int
	managementAddress, adminAddress                    string
	alias                                              string
	local, remote                                      wgingress.KeyPair
}

func TestGatewayFabricKernelManyToManyACLAndSelectiveRemoval(t *testing.T) {
	if os.Getenv(gatewayFabricKernelEnvironment) != "1" {
		t.Skip("set GATEWAY_VPN_GATEWAY_FABRIC_KERNEL_INTEGRATION=1 inside a disposable privileged Linux host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("Gateway Management Fabric kernel gate requires root in a disposable namespace")
	}
	requireGatewayKernelCommands(t, "/usr/sbin/ip", "/usr/bin/wg", "/usr/sbin/nft", "/usr/sbin/sysctl", "/usr/sbin/useradd")
	ctx := context.Background()
	suffix := strconv.Itoa(os.Getpid() % 10000)
	resourceNamespace := "gvres-" + suffix
	links := []gatewayKernelLink{
		{namespace: "gvvps1-" + suffix, uplink: "up1", underlayCIDR: "172.30.1.2/30", gateway: "172.30.1.1", endpoint: "172.30.1.1", listenPort: 51821, table: 1101, mark: 0x1101, managementAddress: "10.82.0.1", adminAddress: "10.81.0.10", alias: "10.96.1.0/24"},
		{namespace: "gvvps2-" + suffix, uplink: "up2", underlayCIDR: "172.30.2.2/30", gateway: "172.30.2.1", endpoint: "172.30.2.1", listenPort: 51822, table: 1102, mark: 0x1102, managementAddress: "10.84.0.1", adminAddress: "10.83.0.10", alias: "10.97.1.0/24"},
	}
	for index := range links {
		links[index].local, _ = wgingress.GenerateKeyPair()
		links[index].remote, _ = wgingress.GenerateKeyPair()
	}

	cleanupGatewayKernelState(resourceNamespace, links)
	t.Cleanup(func() { cleanupGatewayKernelState(resourceNamespace, links) })
	ensureGatewayKernelUser(t, "gateway-vpn")
	ensureGatewayKernelUser(t, "gateway-vpn-mihomo")
	setupGatewayKernelNetworks(t, resourceNamespace, links)

	database, repository := seedGatewayKernelRepository(t, ctx, links)
	t.Cleanup(func() { _ = database.Close() })
	plan, err := repository.BuildGatewayHostPlan(ctx)
	if err != nil || len(plan.Links) != 2 || len(plan.ACL) != 2 {
		t.Fatalf("two-link Gateway plan links=%d acl=%d err=%v", len(plan.Links), len(plan.ACL), err)
	}
	for _, link := range plan.Links {
		underlay := strings.TrimSuffix(link.UplinkGateway, ".1") + ".0/30"
		source := strings.TrimSuffix(link.UplinkGateway, ".1") + ".2"
		gatewayKernelCommand(t, "/usr/sbin/ip", "-4", "route", "replace", underlay, "dev", link.UplinkInterface, "src", source, "table", strconv.FormatInt(link.UplinkTable, 10), "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol))
		gatewayKernelCommand(t, "/usr/sbin/ip", "-4", "rule", "add", "priority", strconv.FormatInt(link.UplinkTable, 10), "fwmark", strconv.FormatInt(link.UplinkMark, 10), "lookup", strconv.FormatInt(link.UplinkTable, 10), "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol))
	}
	for index := range links {
		setupGatewayKernelVPS(t, plan.Links[index], &links[index])
	}

	boot, err := firewall.RenderBootBlocked(firewall.BootConfig{LANInterface: "lan0", TUNInterface: "tun0", WireGuardInterface: "wg-ingress", APIPort: 8443, WireGuardListenPort: 51820})
	if err != nil {
		t.Fatal(err)
	}
	if output, err := gatewayNFTInput([]byte(boot.Text)); err != nil {
		t.Fatalf("load production Gateway firewall schema: %v: %s", err, output)
	}
	foreignBefore := createGatewayKernelForeignObjects(t)

	root := t.TempDir()
	transactionRoot := filepath.Join(root, "transactions")
	secretRoot := filepath.Join(root, "secrets")
	for _, directory := range []string{transactionRoot, secretRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for index, link := range links {
		if err := os.WriteFile(filepath.Join(secretRoot, fmt.Sprintf("link-%d.key", index+1)), []byte(link.local.Private+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	applier := &Applier{Repository: repository, Executor: platformexec.OSExecutor{}, Paths: Paths{
		TransactionRoot: transactionRoot, SecretRoot: secretRoot,
		SecretReferenceRoot: "/var/lib/gateway-vpn/secrets/management",
		IP:                  "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg", RequireRootOwnership: true,
	}}
	if err := applier.Apply(ctx); err != nil {
		t.Fatalf("apply real two-link Gateway projection: %v\n%s", err, gatewayKernelDiagnostics(links))
	}
	waitGatewayKernelHandshakes(t, "gvm1", "gvm2")
	observedGeneration, observations, err := applier.ObserveManagementLinks(ctx)
	if err != nil || observedGeneration != plan.Generation || len(observations) != 2 {
		t.Fatalf("observe real two-link Gateway runtime generation=%d links=%+v err=%v", observedGeneration, observations, err)
	}
	for _, observation := range observations {
		if observation.State != managementfabric.RuntimeLinkReachable || observation.LastHandshakeAt == "" || observation.ErrorCode != "" {
			t.Fatalf("real Gateway runtime observation is not reachable: %+v", observation)
		}
	}
	assertGatewayKernelProjection(t, plan)

	resourceServer := startGatewayKernelTCPServer(t, resourceNamespace, "192.168.50.10:8443")
	deniedPortServer := startGatewayKernelTCPServer(t, resourceNamespace, "192.168.50.10:8444")
	expectGatewayKernelTCP(t, links[0].namespace, links[0].adminAddress, "10.96.1.10:8443", true)
	expectGatewayKernelTCP(t, links[1].namespace, links[1].adminAddress, "10.97.1.10:8443", true)
	expectGatewayKernelTCP(t, links[0].namespace, links[0].adminAddress, "10.97.1.10:8443", false)
	expectGatewayKernelTCP(t, links[1].namespace, links[1].adminAddress, "10.97.1.10:8444", false)
	_ = resourceServer
	_ = deniedPortServer

	gvm2Index := gatewayKernelInterfaceIndex(t, "gvm2")
	if _, err := database.ExecContext(ctx, `
UPDATE management_links SET enabled=0,state='DISABLED',updated_at=? WHERE id='link:kernel:1';
UPDATE management_fabric_generations SET desired_generation=desired_generation+1,state='PENDING',updated_at=? WHERE singleton_id=1`, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := applier.Apply(ctx); err != nil {
		t.Fatalf("disable first Gateway link: %v\n%s", err, gatewayKernelDiagnostics(links))
	}
	if gatewayKernelInterfaceExists("gvm1") || gatewayKernelInterfaceIndex(t, "gvm2") != gvm2Index {
		t.Fatalf("selective removal reset the wrong interface: gvm1=%t gvm2=%d/%d", gatewayKernelInterfaceExists("gvm1"), gvm2Index, gatewayKernelInterfaceIndex(t, "gvm2"))
	}
	if rows := gatewayKernelOwnedRouteRows(t, "1101", links[0].endpoint+"/32", links[0].uplink); len(rows) != 0 {
		t.Fatalf("disabled link endpoint route remains: %s", rows)
	}
	if rows := gatewayKernelOwnedRouteRows(t, "1102", links[1].endpoint+"/32", links[1].uplink); len(rows) != 1 {
		t.Fatalf("surviving link endpoint route = %s", rows)
	}
	waitGatewayKernelHandshakes(t, "gvm2")
	observedGeneration, observations, err = applier.ObserveManagementLinks(ctx)
	if err != nil || observedGeneration <= plan.Generation || len(observations) != 1 || observations[0].LinkID != "link:kernel:2" || observations[0].State != managementfabric.RuntimeLinkReachable {
		t.Fatalf("observe surviving Gateway runtime generation=%d links=%+v err=%v", observedGeneration, observations, err)
	}
	expectGatewayKernelTCP(t, links[1].namespace, links[1].adminAddress, "10.97.1.10:8443", true)
	expectGatewayKernelTCP(t, links[0].namespace, links[0].adminAddress, "10.96.1.10:8443", false)
	endpoints := gatewayKernelOutput(t, "/usr/sbin/nft", "list", "set", "inet", "gateway_vpn", "management_fabric_endpoints")
	if strings.Contains(endpoints, `"up1"`) || !strings.Contains(endpoints, `"up2"`) {
		t.Fatalf("management endpoint set after selective removal:\n%s", endpoints)
	}
	assertGatewayKernelForeignObjects(t, foreignBefore)
}

func seedGatewayKernelRepository(t *testing.T, ctx context.Context, links []gatewayKernelLink) (*sql.DB, *managementfabric.Repository) {
	t.Helper()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	repository := managementfabric.NewRepository(database, []managementfabric.ReservedPrefix{{Owner: "LAN", CIDR: "192.168.200.0/24"}})
	if _, err := repository.EnsureLocalSite(ctx, "site:kernel", "Kernel Gateway"); err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	adminPools := []string{"10.81.0.0/24", "10.83.0.0/24"}
	aliasPools := []string{"10.96.0.0/16", "10.97.0.0/16"}
	managementSubnets := []string{"10.82.0.0/24", "10.84.0.0/24"}
	localAddresses := []string{"10.82.0.2", "10.84.0.2"}
	for index, link := range links {
		vpsID := fmt.Sprintf("vps:kernel:%d", index+1)
		if _, err := repository.CreateVPS(ctx, managementfabric.CreateVPSInput{ID: vpsID, Name: "Kernel VPS", VerifiedFingerprint: strings.Repeat(strconv.Itoa(index+1), 64), PublicKey: link.remote.Public, AdminAddressPool: adminPools[index], ResourceAliasPool: aliasPools[index]}); err != nil {
			t.Fatal(err)
		}
		modemID := fmt.Sprintf("modem:kernel:%d", index+1)
		if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: modemID, Name: "Kernel uplink", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat(string(rune('a'+index)), 64)}); err != nil {
			t.Fatal(err)
		}
		if _, err := modems.ApplyLease(ctx, modemID, modem.LeaseInput{InterfaceName: link.uplink, ManagementCIDR: strings.TrimSuffix(link.underlayCIDR, ".2/30") + ".0/30", Gateway: link.gateway, DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.CreateLink(ctx, managementfabric.CreateLinkInput{
			ID: fmt.Sprintf("link:kernel:%d", index+1), SiteID: "site:kernel", VPSID: vpsID, Enabled: true,
			ManagementSubnet: managementSubnets[index], LocalAddress: localAddresses[index], RemoteAddress: link.managementAddress,
			LocalPrivateKeySecretRef: fmt.Sprintf("/var/lib/gateway-vpn/secrets/management/link-%d.key", index+1),
			LocalPublicKey:           link.local.Public, RemotePublicKey: link.remote.Public,
			UplinkPolicy: managementfabric.UplinkPinnedOnly, PinnedUplinkID: modemID, PersistentKeepalive: 10,
			Endpoints: []managementfabric.EndpointSpec{{Host: link.endpoint, Port: link.listenPort}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	admin1, _ := wgingress.GenerateKeyPair()
	admin2, _ := wgingress.GenerateKeyPair()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO management_admins(id,name,identity_kind,enabled,state,created_at,updated_at) VALUES('admin:kernel','Kernel admin','ADMIN',1,'ACTIVE',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO management_admin_vps_peers(id,admin_id,vps_id,public_key,assigned_address,state,desired_generation,applied_generation,created_at,updated_at) VALUES('admin-peer:kernel:1','admin:kernel','vps:kernel:1',?,'10.81.0.10','ACTIVE',1,0,?,?)`, []any{admin1.Public, stamp, stamp}},
		{`INSERT INTO management_admin_vps_peers(id,admin_id,vps_id,public_key,assigned_address,state,desired_generation,applied_generation,created_at,updated_at) VALUES('admin-peer:kernel:2','admin:kernel','vps:kernel:2',?,'10.83.0.10','ACTIVE',1,0,?,?)`, []any{admin2.Public, stamp, stamp}},
		{`INSERT INTO management_resources(id,site_id,name,resource_kind,access_profile,local_destination,enabled,advanced_scope_acknowledged,desired_route_generation,applied_route_generation,health_state,created_at,updated_at) VALUES('resource:kernel','site:kernel','Kernel LAN','LOCAL_SUBNET','VIA_DEDICATED_LAN','192.168.50.0/24',1,1,1,0,'UNKNOWN',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO management_resource_publications(id,resource_id,link_id,published_alias,desired_route_generation,applied_route_generation,desired_acl_generation,applied_acl_generation,state,created_at,updated_at) VALUES('publication:kernel:1','resource:kernel','link:kernel:1','10.96.1.0/24',1,0,1,0,'PENDING',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO management_resource_publications(id,resource_id,link_id,published_alias,desired_route_generation,applied_route_generation,desired_acl_generation,applied_acl_generation,state,created_at,updated_at) VALUES('publication:kernel:2','resource:kernel','link:kernel:2','10.97.1.0/24',1,0,1,0,'PENDING',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO management_resource_acl(id,admin_id,resource_id,protocol,port_start,port_end,enabled,generation,created_at,updated_at) VALUES('acl:kernel','admin:kernel','resource:kernel','TCP',8443,8443,1,1,?,?)`, []any{stamp, stamp}},
		{`UPDATE management_fabric_generations SET desired_generation=desired_generation+1,state='PENDING',updated_at=? WHERE singleton_id=1`, []any{stamp}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			database.Close()
			t.Fatal(err)
		}
	}
	return database, repository
}

func setupGatewayKernelNetworks(t *testing.T, resourceNamespace string, links []gatewayKernelLink) {
	t.Helper()
	gatewayKernelCommand(t, "/usr/sbin/ip", "link", "add", "lan0", "type", "dummy")
	gatewayKernelCommand(t, "/usr/sbin/ip", "address", "add", "192.168.200.1/24", "dev", "lan0")
	gatewayKernelCommand(t, "/usr/sbin/ip", "link", "set", "lan0", "up")
	for _, link := range links {
		gatewayKernelCommand(t, "/usr/sbin/ip", "netns", "add", link.namespace)
		gatewayKernelCommand(t, "/usr/sbin/ip", "link", "add", link.uplink, "type", "veth", "peer", "name", "eth0", "netns", link.namespace)
		gatewayKernelCommand(t, "/usr/sbin/ip", "address", "add", link.underlayCIDR, "dev", link.uplink)
		gatewayKernelCommand(t, "/usr/sbin/ip", "link", "set", link.uplink, "up")
		gatewayKernelCommand(t, "/usr/sbin/ip", "-n", link.namespace, "link", "set", "lo", "up")
		gatewayKernelCommand(t, "/usr/sbin/ip", "-n", link.namespace, "address", "add", link.gateway+"/30", "dev", "eth0")
		gatewayKernelCommand(t, "/usr/sbin/ip", "-n", link.namespace, "link", "set", "eth0", "up")
	}
	gatewayKernelCommand(t, "/usr/sbin/ip", "netns", "add", resourceNamespace)
	gatewayKernelCommand(t, "/usr/sbin/ip", "link", "add", "res0", "type", "veth", "peer", "name", "eth0", "netns", resourceNamespace)
	gatewayKernelCommand(t, "/usr/sbin/ip", "address", "add", "192.168.50.1/24", "dev", "res0")
	gatewayKernelCommand(t, "/usr/sbin/ip", "link", "set", "res0", "up")
	gatewayKernelCommand(t, "/usr/sbin/ip", "-n", resourceNamespace, "link", "set", "lo", "up")
	gatewayKernelCommand(t, "/usr/sbin/ip", "-n", resourceNamespace, "address", "add", "192.168.50.10/24", "dev", "eth0")
	gatewayKernelCommand(t, "/usr/sbin/ip", "-n", resourceNamespace, "link", "set", "eth0", "up")
	gatewayKernelCommand(t, "/usr/sbin/ip", "-n", resourceNamespace, "route", "add", "default", "via", "192.168.50.1")
	gatewayKernelCommand(t, "/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1")
}

func setupGatewayKernelVPS(t *testing.T, plan managementfabric.GatewayHostLink, link *gatewayKernelLink) {
	t.Helper()
	privateKey := filepath.Join(t.TempDir(), "vps.key")
	if err := os.WriteFile(privateKey, []byte(link.remote.Private+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gatewayKernelCommand(t, "/usr/sbin/ip", "-n", link.namespace, "link", "add", "wgvps", "type", "wireguard")
	gatewayKernelCommand(t, "/usr/sbin/ip", "netns", "exec", link.namespace, "/usr/bin/wg", "set", "wgvps", "private-key", privateKey, "listen-port", strconv.Itoa(link.listenPort), "peer", link.local.Public, "allowed-ips", plan.LocalAddress+","+link.alias)
	gatewayKernelCommand(t, "/usr/sbin/ip", "-n", link.namespace, "address", "add", link.managementAddress+"/32", "dev", "wgvps")
	gatewayKernelCommand(t, "/usr/sbin/ip", "-n", link.namespace, "address", "add", link.adminAddress+"/32", "dev", "wgvps")
	gatewayKernelCommand(t, "/usr/sbin/ip", "-n", link.namespace, "link", "set", "wgvps", "up")
	for _, destination := range []string{"10.96.1.0/24", "10.97.1.0/24"} {
		gatewayKernelCommand(t, "/usr/sbin/ip", "-n", link.namespace, "route", "replace", destination, "dev", "wgvps")
	}
}

func assertGatewayKernelProjection(t *testing.T, plan managementfabric.GatewayHostPlan) {
	t.Helper()
	for _, link := range plan.Links {
		result := gatewayKernelOutput(t, "/usr/sbin/ip", "-json", "-4", "route", "get", link.EndpointAddress, "mark", strconv.FormatInt(link.UplinkMark, 10))
		if !exactRouteGet(result, link.UplinkInterface, link.UplinkGateway, link.UplinkTable) {
			t.Fatalf("marked endpoint route for %s: %s", link.InterfaceName, result)
		}
		rows := gatewayKernelOwnedRouteRows(t, strconv.FormatInt(link.UplinkTable, 10), link.EndpointAddress+"/32", link.UplinkInterface)
		if len(rows) != 1 {
			t.Fatalf("exact endpoint /32 for %s: %s", link.InterfaceName, rows)
		}
	}
	rules := gatewayKernelOutput(t, "/usr/sbin/nft", "-a", "list", "table", "inet", "gateway_vpn")
	for _, required := range []string{"dnat ip prefix", "ct state new tcp dport 8443", `iifname "gvm1"`, `iifname "gvm2"`, "masquerade"} {
		if !strings.Contains(rules, required) {
			t.Fatalf("kernel firewall misses %q:\n%s", required, rules)
		}
	}
}

func TestGatewayFabricKernelTCPHelper(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_GATEWAY_FABRIC_TCP_HELPER") != "1" {
		t.Skip("helper process only")
	}
	address := os.Getenv("GATEWAY_VPN_GATEWAY_FABRIC_TCP_ADDRESS")
	switch os.Getenv("GATEWAY_VPN_GATEWAY_FABRIC_TCP_MODE") {
	case "server":
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := os.WriteFile(os.Getenv("GATEWAY_VPN_GATEWAY_FABRIC_TCP_READY"), []byte("ready\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for {
			connection, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			request := make([]byte, 1)
			if _, err := io.ReadFull(connection, request); err != nil || request[0] != 1 {
				_ = connection.Close()
				t.Fatalf("Gateway fabric TCP request=%v err=%v", request, err)
			}
			_, writeErr := connection.Write([]byte("gateway-vpn-gateway-fabric-ok"))
			_ = connection.Close()
			if writeErr != nil {
				t.Fatal(writeErr)
			}
		}
	case "client":
		local := net.ParseIP(os.Getenv("GATEWAY_VPN_GATEWAY_FABRIC_TCP_SOURCE"))
		dialer := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: local}}
		connection, err := dialer.Dial("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := connection.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, len("gateway-vpn-gateway-fabric-ok"))
		if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "gateway-vpn-gateway-fabric-ok" {
			t.Fatalf("Gateway fabric TCP response=%q err=%v", buffer, err)
		}
	default:
		t.Fatal("invalid Gateway fabric TCP helper mode")
	}
}

func startGatewayKernelTCPServer(t *testing.T, namespace, address string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "ready")
	command := exec.Command("/usr/sbin/ip", "netns", "exec", namespace, executable, "-test.run", "^TestGatewayFabricKernelTCPHelper$")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	command.Env = append(os.Environ(), "GATEWAY_VPN_GATEWAY_FABRIC_TCP_HELPER=1", "GATEWAY_VPN_GATEWAY_FABRIC_TCP_MODE=server", "GATEWAY_VPN_GATEWAY_FABRIC_TCP_ADDRESS="+address, "GATEWAY_VPN_GATEWAY_FABRIC_TCP_READY="+ready)
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
	t.Fatalf("Gateway fabric TCP server %s did not become ready: %s", address, output.String())
	return nil
}

func expectGatewayKernelTCP(t *testing.T, namespace, source, address string, allowed bool) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/sbin/ip", "netns", "exec", namespace, executable, "-test.run", "^TestGatewayFabricKernelTCPHelper$")
	command.Env = append(os.Environ(), "GATEWAY_VPN_GATEWAY_FABRIC_TCP_HELPER=1", "GATEWAY_VPN_GATEWAY_FABRIC_TCP_MODE=client", "GATEWAY_VPN_GATEWAY_FABRIC_TCP_ADDRESS="+address, "GATEWAY_VPN_GATEWAY_FABRIC_TCP_SOURCE="+source)
	output, runErr := command.CombinedOutput()
	if allowed && runErr != nil {
		t.Fatalf("allowed Gateway fabric path %s(%s) -> %s failed: %v: %s\n%s", namespace, source, address, runErr, output, gatewayKernelDiagnostics(nil))
	}
	if !allowed && runErr == nil {
		t.Fatalf("forbidden Gateway fabric path %s(%s) -> %s succeeded", namespace, source, address)
	}
}

func waitGatewayKernelHandshakes(t *testing.T, interfaces ...string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, name := range interfaces {
			fields := strings.Fields(gatewayKernelOutputNoFail("/usr/bin/wg", "show", name, "latest-handshakes"))
			ready = ready && len(fields) == 2 && fields[1] != "0"
		}
		if ready {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("WireGuard handshakes did not become live:\n%s", gatewayKernelDiagnostics(nil))
}

func createGatewayKernelForeignObjects(t *testing.T) map[string]string {
	t.Helper()
	for _, item := range []struct{ name, address string }{{"docker0", "172.19.0.1/16"}, {"amn0", "172.20.0.1/16"}} {
		gatewayKernelCommand(t, "/usr/sbin/ip", "link", "add", item.name, "type", "dummy")
		gatewayKernelCommand(t, "/usr/sbin/ip", "address", "add", item.address, "dev", item.name)
		gatewayKernelCommand(t, "/usr/sbin/ip", "link", "set", item.name, "up")
	}
	foreign := []byte(`table inet ufw_gateway_gate {
	chain input {
		counter accept
	}
}
table inet docker_gateway_gate {
	chain forward {
		counter accept
	}
}
table inet amnezia_gateway_gate {
	chain vpn {
		counter accept
	}
}
`)
	if output, err := gatewayNFTInput(foreign); err != nil {
		t.Fatalf("create foreign Gateway fixtures: %v: %s", err, output)
	}
	result := map[string]string{}
	for _, name := range []string{"ufw_gateway_gate", "docker_gateway_gate", "amnezia_gateway_gate"} {
		result["nft:"+name] = gatewayKernelOutput(t, "/usr/sbin/nft", "list", "table", "inet", name)
	}
	for _, name := range []string{"docker0", "amn0"} {
		result["link:"+name] = gatewayKernelOutput(t, "/usr/sbin/ip", "-json", "link", "show", "dev", name)
	}
	return result
}

func assertGatewayKernelForeignObjects(t *testing.T, before map[string]string) {
	t.Helper()
	for key, expected := range before {
		parts := strings.SplitN(key, ":", 2)
		actual := ""
		if parts[0] == "nft" {
			actual = gatewayKernelOutput(t, "/usr/sbin/nft", "list", "table", "inet", parts[1])
		} else {
			actual = gatewayKernelOutput(t, "/usr/sbin/ip", "-json", "link", "show", "dev", parts[1])
		}
		if actual != expected {
			t.Fatalf("foreign object %s changed\nbefore=%s\nafter=%s", key, expected, actual)
		}
	}
}

func gatewayKernelOwnedRouteRows(t *testing.T, table, destination, device string) []json.RawMessage {
	t.Helper()
	output, err := exec.Command("/usr/sbin/ip", "-json", "-4", "route", "show", "table", table, "exact", destination, "dev", device, "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)).CombinedOutput()
	if err != nil {
		t.Fatalf("query owned route: %v: %s", err, output)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(output, &rows); err != nil {
		t.Fatalf("decode owned route rows: %v: %s", err, output)
	}
	return rows
}

func gatewayKernelInterfaceIndex(t *testing.T, name string) int {
	t.Helper()
	output := gatewayKernelOutput(t, "/usr/sbin/ip", "-json", "link", "show", "dev", name)
	var rows []struct {
		Index int `json:"ifindex"`
	}
	if json.Unmarshal([]byte(output), &rows) != nil || len(rows) != 1 || rows[0].Index <= 0 {
		t.Fatalf("invalid interface inventory for %s: %s", name, output)
	}
	return rows[0].Index
}

func gatewayKernelInterfaceExists(name string) bool {
	return exec.Command("/usr/sbin/ip", "link", "show", "dev", name).Run() == nil
}

func ensureGatewayKernelUser(t *testing.T, name string) {
	t.Helper()
	if exec.Command("/usr/bin/id", "-u", name).Run() == nil {
		return
	}
	gatewayKernelCommand(t, "/usr/sbin/useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name)
}

func requireGatewayKernelCommands(t *testing.T, commands ...string) {
	t.Helper()
	for _, command := range commands {
		if info, err := os.Stat(command); err != nil || info.IsDir() {
			t.Fatalf("required Gateway kernel command %s is unavailable", command)
		}
	}
}

func gatewayKernelCommand(t *testing.T, executable string, arguments ...string) {
	t.Helper()
	if output, err := exec.Command(executable, arguments...).CombinedOutput(); err != nil {
		t.Fatalf("kernel command %s %s failed: %v: %s", executable, strings.Join(arguments, " "), err, output)
	}
}

func gatewayKernelOutput(t *testing.T, executable string, arguments ...string) string {
	t.Helper()
	output, err := exec.Command(executable, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("kernel query %s %s failed: %v: %s", executable, strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func gatewayKernelOutputNoFail(executable string, arguments ...string) string {
	output, _ := exec.Command(executable, arguments...).CombinedOutput()
	return string(output)
}

func gatewayNFTInput(input []byte) ([]byte, error) {
	command := exec.Command("/usr/sbin/nft", "--file", "-")
	command.Stdin = bytes.NewReader(input)
	return command.CombinedOutput()
}

func cleanupGatewayKernelState(resourceNamespace string, links []gatewayKernelLink) {
	_, _ = gatewayNFTInput([]byte("delete table inet gateway_vpn\ndelete table inet ufw_gateway_gate\ndelete table inet docker_gateway_gate\ndelete table inet amnezia_gateway_gate\n"))
	for _, name := range []string{"gvm1", "gvm2", "lan0", "res0", "docker0", "amn0", "up1", "up2"} {
		_, _ = exec.Command("/usr/sbin/ip", "link", "delete", "dev", name).CombinedOutput()
	}
	for _, link := range links {
		_, _ = exec.Command("/usr/sbin/ip", "-4", "rule", "delete", "priority", strconv.Itoa(link.table)).CombinedOutput()
		_, _ = exec.Command("/usr/sbin/ip", "netns", "delete", link.namespace).CombinedOutput()
	}
	if resourceNamespace != "" {
		_, _ = exec.Command("/usr/sbin/ip", "netns", "delete", resourceNamespace).CombinedOutput()
	}
}

func gatewayKernelDiagnostics(links []gatewayKernelLink) string {
	commands := [][]string{
		{"/usr/bin/wg", "show"},
		{"/usr/sbin/ip", "-4", "rule", "show"},
		{"/usr/sbin/ip", "-4", "route", "show", "table", "all", "protocol", strconv.Itoa(managementfabric.OwnedRouteProtocol)},
		{"/usr/sbin/nft", "-a", "list", "table", "inet", "gateway_vpn"},
	}
	var result strings.Builder
	for _, item := range commands {
		output, err := exec.Command(item[0], item[1:]...).CombinedOutput()
		fmt.Fprintf(&result, "$ %s\n%s(error=%v)\n", strings.Join(item, " "), output, err)
	}
	for _, link := range links {
		output, err := exec.Command("/usr/sbin/ip", "netns", "exec", link.namespace, "/usr/bin/wg", "show").CombinedOutput()
		fmt.Fprintf(&result, "$ ip netns exec %s wg show\n%s(error=%v)\n", link.namespace, output, err)
	}
	return result.String()
}
