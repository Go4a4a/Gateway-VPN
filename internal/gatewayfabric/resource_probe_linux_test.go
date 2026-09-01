//go:build linux

package gatewayfabric

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/wgingress"
)

const resourceProbeKernelEnvironment = "GATEWAY_VPN_RESOURCE_PROBE_INTEGRATION"

func TestResourceProbeAgainstKernelRoutes(t *testing.T) {
	if os.Getenv(resourceProbeKernelEnvironment) != "1" {
		t.Skip("set GATEWAY_VPN_RESOURCE_PROBE_INTEGRATION=1 inside the disposable resource netns gate")
	}
	if os.Geteuid() != 0 {
		t.Fatal("resource probe kernel gate requires root")
	}
	for _, path := range []string{"/usr/sbin/ip", "/usr/sbin/nft", "/usr/bin/wg", "/usr/bin/ping"} {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			t.Fatalf("required executable %s is unavailable: %v", path, err)
		}
	}
	ctx := context.Background()
	root := t.TempDir()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(root, "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := managementfabric.NewRepository(database, nil)
	if _, err := repository.EnsureLocalSite(ctx, "site:kernel-probe", "Kernel probe"); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at) VALUES('netif:kernel-lan','PERMANENT_MAC',?,'lan0','UP',?,?)`, []any{strings.Repeat("a", 64), stamp, stamp}},
		{`INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at) VALUES('netif:kernel-mgmt','PERMANENT_MAC',?,'mgmt0','UP',?,?)`, []any{strings.Repeat("b", 64), stamp, stamp}},
		{`INSERT INTO interface_role_assignments(id,network_interface_id,role,state,created_at,updated_at) VALUES('role:kernel-lan','netif:kernel-lan','LAN_MEMBER','ACTIVE',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO interface_role_assignments(id,network_interface_id,role,state,created_at,updated_at) VALUES('role:kernel-mgmt','netif:kernel-mgmt','MANAGEMENT','ACTIVE',?,?)`, []any{stamp, stamp}},
	} {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO wireguard_ingress_servers(id,enabled,name,interface_name,subnet_cidr,listen_port,private_key_secret_ref,topology_mode,created_at,updated_at) VALUES('wg-server:kernel-probe',1,'Kernel probe','wg-ingress','10.90.0.0/24',51822,'/var/lib/gateway-vpn/secrets/wireguard-ingress/server.key','ROUTED',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO wireguard_ingress_peers(id,server_id,display_number,name,enabled,peer_kind,key_mode,public_key,assigned_address,persistent_keepalive,created_at,updated_at) VALUES('wg-peer:kernel-probe','wg-server:kernel-probe',1,'Router',1,'ROUTER_ROUTED','EXTERNAL',?,'10.90.0.2',25,?,?)`, []any{pair.Public, stamp, stamp}},
		{`INSERT INTO wireguard_ingress_peer_routes(peer_id,cidr,direction,created_at) VALUES('wg-peer:kernel-probe','192.168.51.0/24','INGRESS',?)`, []any{stamp}},
	} {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	port := []managementfabric.ResourcePort{{Protocol: managementfabric.ProtocolTCP, PortStart: 18443, PortEnd: 18443}}
	inputs := []managementfabric.ResourceInput{
		{ID: "resource:kernel-gateway", Name: "Gateway", Kind: managementfabric.ResourceGatewayService, AccessProfile: managementfabric.ProfileGatewayOnly, LocalDestination: "192.168.201.1", Enabled: true, Ports: port},
		{ID: "resource:kernel-keenetic", Name: "Keenetic WAN", Kind: managementfabric.ResourceKeeneticService, AccessProfile: managementfabric.ProfileKeeneticWAN, LocalDestination: "192.168.200.254", Enabled: true, Ports: port},
		{ID: "resource:kernel-routed", Name: "Keenetic routed", Kind: managementfabric.ResourceLocalHost, AccessProfile: managementfabric.ProfileKeeneticWANRouted, LocalDestination: "192.168.50.10", Enabled: true, Ports: port},
		{ID: "resource:kernel-wg", Name: "WireGuard routed", Kind: managementfabric.ResourceLocalHost, AccessProfile: managementfabric.ProfileWireGuardRouter, LocalDestination: "192.168.51.10", Enabled: true, Ports: port},
		{ID: "resource:kernel-dedicated", Name: "Dedicated subnet", Kind: managementfabric.ResourceLocalSubnet, AccessProfile: managementfabric.ProfileDedicatedLAN, LocalDestination: "192.168.60.0/24", HealthProbeAddress: "192.168.60.10", Enabled: true, AdvancedScopeAcknowledged: true, Ports: port},
	}
	for _, input := range inputs {
		if _, err := repository.CreateResource(ctx, input); err != nil {
			t.Fatalf("create %s: %v", input.ID, err)
		}
	}
	transactionRoot, secretRoot := filepath.Join(root, "transactions"), filepath.Join(root, "secrets")
	for _, directory := range []string{transactionRoot, secretRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	applier := &Applier{Repository: repository, Executor: platformexec.OSExecutor{}, Paths: Paths{
		TransactionRoot: transactionRoot, SecretRoot: secretRoot,
		SecretReferenceRoot: "/var/lib/gateway-vpn/secrets/management",
		IP:                  "/usr/sbin/ip", NFT: "/usr/sbin/nft", WG: "/usr/bin/wg", Ping: "/usr/bin/ping", RequireRootOwnership: true,
	}}
	expected := map[string]string{
		"resource:kernel-gateway": "lo", "resource:kernel-keenetic": "lan0", "resource:kernel-routed": "lan0",
		"resource:kernel-wg": "wg-ingress", "resource:kernel-dedicated": "mgmt0",
	}
	for _, input := range inputs {
		result, err := applier.ProbeResource(ctx, input.ID)
		if err != nil || result.State != "HEALTHY" || result.Interface != expected[input.ID] || len(result.Checks) != 1 || result.Checks[0].State != "PASSED" {
			t.Fatalf("kernel probe %s = %+v, %v", input.ID, result, err)
		}
	}

	missing, err := repository.CreateResource(ctx, managementfabric.ResourceInput{
		ID: "resource:kernel-no-return", Name: "Missing return path", Kind: managementfabric.ResourceLocalHost,
		AccessProfile: managementfabric.ProfileKeeneticWANRouted, LocalDestination: "192.168.50.20", Enabled: true, Ports: port,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := applier.ProbeResource(ctx, missing.ID)
	if err != nil || result.State != "WAITING_EXTERNAL_CONFIGURATION" || result.ReasonCode != "RESOURCE_TRANSPORT_UNREACHABLE" {
		t.Fatalf("missing external return path = %+v, %v", result, err)
	}

	if output, err := exec.Command("/usr/sbin/ip", "route", "add", "default", "dev", "mgmt0", "metric", "500").CombinedOutput(); err != nil {
		t.Fatalf("add dedicated default route: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/ip", "route", "del", "default", "dev", "mgmt0", "metric", "500").Run()
	})
	result, err = applier.ProbeResource(ctx, "resource:kernel-dedicated")
	if err != nil || result.State != "WAITING_EXTERNAL_CONFIGURATION" || result.ReasonCode != "DEDICATED_INTERFACE_HAS_DEFAULT_ROUTE" {
		t.Fatalf("dedicated interface default route = %+v, %v", result, err)
	}
}
