package gatewayfabric

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/wgingress"
)

type resourceProbeExecutor struct {
	routes       map[string]resourceRoute
	ownedRows    map[string]string
	defaultRows  map[string]string
	requests     []platformexec.Request
	defaultError error
}

func (executor *resourceProbeExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	command := strings.TrimSuffix(filepath.Base(request.Executable), ".exe")
	if command != "ip" {
		return platformexec.Result{}, errors.New("unexpected resource probe executable")
	}
	if len(request.Arguments) == 5 && strings.Join(request.Arguments[:4], " ") == "-json -4 route get" {
		route, exists := executor.routes[request.Arguments[4]]
		if !exists {
			return platformexec.Result{}, errors.New("route missing")
		}
		content, _ := json.Marshal([]resourceRoute{route})
		return platformexec.Result{Stdout: string(content)}, nil
	}
	if len(request.Arguments) == 12 && strings.Join(request.Arguments[:7], " ") == "-json -4 route show table main exact" &&
		request.Arguments[8] == "dev" && request.Arguments[9] == "wg-ingress" &&
		request.Arguments[10] == "protocol" && request.Arguments[11] == "186" {
		rows, exists := executor.ownedRows[request.Arguments[7]]
		if !exists {
			return platformexec.Result{}, errors.New("owned route missing")
		}
		return platformexec.Result{Stdout: rows}, nil
	}
	if len(request.Arguments) == 9 && strings.Join(request.Arguments[:8], " ") == "-json -4 route show table main default dev" {
		if executor.defaultError != nil {
			return platformexec.Result{}, executor.defaultError
		}
		return platformexec.Result{Stdout: executor.defaultRows[request.Arguments[8]]}, nil
	}
	return platformexec.Result{}, errors.New("unexpected resource probe command")
}

type transportProbeCall struct {
	network, interfaceName, address string
	port                            int
}

func TestProbeResourceQualifiesFiveProfilesAndSubnetReturnPath(t *testing.T) {
	ctx, database, repository, applier, executor := newResourceProbeFixture(t)
	insertWireGuardRouterFixture(t, ctx, database)

	inputs := []managementfabric.ResourceInput{
		{ID: "resource:gateway", Name: "Gateway", Kind: managementfabric.ResourceGatewayService, AccessProfile: managementfabric.ProfileGatewayOnly, LocalDestination: "192.168.200.1", Enabled: true, Ports: resourceTCPPort()},
		{ID: "resource:keenetic", Name: "Keenetic WAN", Kind: managementfabric.ResourceKeeneticService, AccessProfile: managementfabric.ProfileKeeneticWAN, LocalDestination: "192.168.200.2", Enabled: true, Ports: resourceTCPPort()},
		{ID: "resource:routed", Name: "Keenetic routed", Kind: managementfabric.ResourceLocalHost, AccessProfile: managementfabric.ProfileKeeneticWANRouted, LocalDestination: "192.168.50.10", Enabled: true, Ports: resourceTCPPort()},
		{ID: "resource:wg", Name: "WireGuard routed", Kind: managementfabric.ResourceLocalHost, AccessProfile: managementfabric.ProfileWireGuardRouter, LocalDestination: "192.168.51.10", Enabled: true, Ports: resourceTCPPort()},
		{ID: "resource:dedicated", Name: "Dedicated subnet", Kind: managementfabric.ResourceLocalSubnet, AccessProfile: managementfabric.ProfileDedicatedLAN, LocalDestination: "192.168.60.0/24", HealthProbeAddress: "192.168.60.10", Enabled: true, AdvancedScopeAcknowledged: true, Ports: resourceTCPPort()},
	}
	for _, input := range inputs {
		if _, err := repository.CreateResource(ctx, input); err != nil {
			t.Fatalf("create %s: %v", input.ID, err)
		}
	}
	executor.routes = map[string]resourceRoute{
		"192.168.200.1": {Type: "local", Device: "lo"},
		"192.168.200.2": {Device: "lan0"},
		"192.168.50.10": {Device: "lan0", Gateway: "192.168.200.254"},
		"192.168.51.10": {Device: "wg-ingress"},
		"192.168.60.10": {Device: "mgmt0"},
	}
	executor.ownedRows["192.168.51.0/24"] = `[{"dst":"192.168.51.0/24","dev":"wg-ingress","protocol":186}]`
	executor.defaultRows["mgmt0"] = "[]"
	var transportCalls []transportProbeCall
	applier.TransportProbe = func(_ context.Context, network, interfaceName, address string, port int) error {
		transportCalls = append(transportCalls, transportProbeCall{network: network, interfaceName: interfaceName, address: address, port: port})
		return nil
	}
	tests := []struct {
		id, interfaceName, address, reason string
	}{
		{"resource:gateway", "lo", "192.168.200.1", "RESOURCE_PROBE_PASSED"},
		{"resource:keenetic", "lan0", "192.168.200.2", "RESOURCE_PROBE_PASSED"},
		{"resource:routed", "lan0", "192.168.50.10", "RESOURCE_PROBE_PASSED"},
		{"resource:wg", "wg-ingress", "192.168.51.10", "RESOURCE_PROBE_PASSED"},
		{"resource:dedicated", "mgmt0", "192.168.60.10", "RESOURCE_SUBNET_PATH_CONFIRMED"},
	}
	for index, test := range tests {
		result, err := applier.ProbeResource(ctx, test.id)
		if err != nil {
			t.Fatalf("ProbeResource(%s): %v", test.id, err)
		}
		if result.State != "HEALTHY" || result.ReasonCode != test.reason || result.Interface != test.interfaceName || len(result.Checks) != 1 || result.Checks[0].State != "PASSED" {
			t.Fatalf("ProbeResource(%s) = %+v", test.id, result)
		}
		if index >= len(transportCalls) || transportCalls[index].address != test.address || transportCalls[index].interfaceName != test.interfaceName || transportCalls[index].network != "tcp" || transportCalls[index].port != 8443 {
			t.Fatalf("transport call %d = %+v", index, transportCalls)
		}
		stored, err := repository.GetResource(ctx, test.id)
		if err != nil || stored.HealthState != "HEALTHY" || stored.LastProbeRouteGeneration != stored.DesiredRouteGeneration {
			t.Fatalf("stored resource %s = %+v, %v", test.id, stored, err)
		}
	}
	if len(transportCalls) != len(tests) {
		t.Fatalf("transport calls = %+v", transportCalls)
	}
}

func TestProbeResourceKeepsExternalPathClosedWithoutReturnPath(t *testing.T) {
	ctx, _, repository, applier, executor := newResourceProbeFixture(t)
	item, err := repository.CreateResource(ctx, managementfabric.ResourceInput{
		ID: "resource:no-return", Name: "Keenetic LAN host", Kind: managementfabric.ResourceLocalHost,
		AccessProfile: managementfabric.ProfileKeeneticWANRouted, LocalDestination: "192.168.50.20", Enabled: true,
		Ports: resourceTCPPort(),
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.routes[item.LocalDestination] = resourceRoute{Device: "lan0", Gateway: "192.168.200.254"}
	applier.TransportProbe = func(context.Context, string, string, string, int) error { return errors.New("connection timed out") }
	result, err := applier.ProbeResource(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "WAITING_EXTERNAL_CONFIGURATION" || result.ReasonCode != "RESOURCE_TRANSPORT_UNREACHABLE" || len(result.Checks) != 1 || result.Checks[0].State != "FAILED" {
		t.Fatalf("missing return path result = %+v", result)
	}
	stored, err := repository.GetResource(ctx, item.ID)
	if err != nil || stored.HealthState != "WAITING_EXTERNAL_CONFIGURATION" || stored.LastProbeRouteGeneration != item.DesiredRouteGeneration {
		t.Fatalf("stored missing return path = %+v, %v", stored, err)
	}
}

func TestProbeResourceRejectsWireGuardRouteWithoutExactOwnedProjection(t *testing.T) {
	ctx, database, repository, applier, executor := newResourceProbeFixture(t)
	insertWireGuardRouterFixture(t, ctx, database)
	item, err := repository.CreateResource(ctx, managementfabric.ResourceInput{
		ID: "resource:wg-unowned", Name: "WireGuard routed", Kind: managementfabric.ResourceLocalHost,
		AccessProfile: managementfabric.ProfileWireGuardRouter, LocalDestination: "192.168.51.10", Enabled: true,
		Ports: resourceTCPPort(),
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.routes[item.LocalDestination] = resourceRoute{Device: "wg-ingress"}
	executor.ownedRows["192.168.51.0/24"] = `[]`
	applier.TransportProbe = func(context.Context, string, string, string, int) error {
		t.Fatal("transport probe must remain closed without an exact owned route")
		return nil
	}
	result, err := applier.ProbeResource(ctx, item.ID)
	if err != nil || result.State != "WAITING_EXTERNAL_CONFIGURATION" || result.ReasonCode != "WG_ROUTER_ROUTE_NOT_CONFIRMED" || len(result.Checks) != 0 {
		t.Fatalf("unowned WireGuard route result = %+v, %v", result, err)
	}
	executor.ownedRows["192.168.51.0/24"] = `[{"dst":"192.168.51.0/24","dev":"wg-ingress","protocol":99}]`
	result, err = applier.ProbeResource(ctx, item.ID)
	if err != nil || result.State != "WAITING_EXTERNAL_CONFIGURATION" || result.ReasonCode != "WG_ROUTER_ROUTE_NOT_CONFIRMED" {
		t.Fatalf("wrong-protocol WireGuard route result = %+v, %v", result, err)
	}
}

func TestProbeResourceRejectsDedicatedDefaultRouteAndInvalidDefaultEvidence(t *testing.T) {
	ctx, _, repository, applier, executor := newResourceProbeFixture(t)
	item, err := repository.CreateResource(ctx, managementfabric.ResourceInput{
		ID: "resource:dedicated-default", Name: "Dedicated host", Kind: managementfabric.ResourceLocalHost,
		AccessProfile: managementfabric.ProfileDedicatedLAN, LocalDestination: "192.168.60.20", Enabled: true,
		Ports: resourceTCPPort(),
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.routes[item.LocalDestination] = resourceRoute{Device: "mgmt0"}
	executor.defaultRows["mgmt0"] = `[{"dst":"default","dev":"mgmt0"}]`
	result, err := applier.ProbeResource(ctx, item.ID)
	if err != nil || result.State != "WAITING_EXTERNAL_CONFIGURATION" || result.ReasonCode != "DEDICATED_INTERFACE_HAS_DEFAULT_ROUTE" {
		t.Fatalf("dedicated default route result = %+v, %v", result, err)
	}
	executor.defaultRows["mgmt0"] = "not-json"
	result, err = applier.ProbeResource(ctx, item.ID)
	if err != nil || result.ReasonCode != "DEDICATED_DEFAULT_ROUTE_CHECK_FAILED" {
		t.Fatalf("invalid default route evidence = %+v, %v", result, err)
	}
}

func newResourceProbeFixture(t *testing.T) (context.Context, *sql.DB, *managementfabric.Repository, *Applier, *resourceProbeExecutor) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(root, "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := managementfabric.NewRepository(database, []managementfabric.ReservedPrefix{{Owner: "gateway-lan", CIDR: "192.168.200.0/24"}})
	if _, err := repository.EnsureLocalSite(ctx, "site:probe", "Probe"); err != nil {
		t.Fatal(err)
	}
	stamp := "2026-09-01T12:00:00Z"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at) VALUES('netif:lan','PERMANENT_MAC',?,'lan0','UP',?,?)`, []any{strings.Repeat("a", 64), stamp, stamp}},
		{`INSERT INTO network_interfaces(id,stable_identity_kind,stable_identity_hash,current_ifname,carrier_state,created_at,updated_at) VALUES('netif:mgmt','PERMANENT_MAC',?,'mgmt0','UP',?,?)`, []any{strings.Repeat("b", 64), stamp, stamp}},
		{`INSERT INTO interface_role_assignments(id,network_interface_id,role,state,created_at,updated_at) VALUES('role:lan','netif:lan','LAN_MEMBER','ACTIVE',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO interface_role_assignments(id,network_interface_id,role,state,created_at,updated_at) VALUES('role:mgmt','netif:mgmt','MANAGEMENT','ACTIVE',?,?)`, []any{stamp, stamp}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	executable := func(name string) string {
		if runtime.GOOS == "windows" {
			return filepath.Join(root, name+".exe")
		}
		return filepath.Join(root, name)
	}
	executor := &resourceProbeExecutor{routes: map[string]resourceRoute{}, ownedRows: map[string]string{}, defaultRows: map[string]string{}}
	applier := &Applier{
		Repository: repository, Executor: executor,
		Paths: Paths{
			TransactionRoot: filepath.Join(root, "transactions"), SecretRoot: filepath.Join(root, "secrets"),
			SecretReferenceRoot: "/var/lib/gateway-vpn/secrets/management",
			IP:                  executable("ip"), NFT: executable("nft"), WG: executable("wg"), Ping: executable("ping"),
		},
		Now: func() time.Time { return time.Date(2026, 9, 1, 12, 30, 0, 0, time.UTC) },
	}
	return ctx, database, repository, applier, executor
}

func insertWireGuardRouterFixture(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	stamp := "2026-09-01T12:00:00Z"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO wireguard_ingress_servers(id,enabled,name,interface_name,subnet_cidr,listen_port,private_key_secret_ref,topology_mode,created_at,updated_at) VALUES('wg-server:probe',1,'Probe','wg-ingress','10.90.0.0/24',51822,'/var/lib/gateway-vpn/secrets/wireguard-ingress/server.key','ROUTED',?,?)`, []any{stamp, stamp}},
		{`INSERT INTO wireguard_ingress_peers(id,server_id,display_number,name,enabled,peer_kind,key_mode,public_key,assigned_address,persistent_keepalive,created_at,updated_at) VALUES('wg-peer:router','wg-server:probe',1,'Router',1,'ROUTER_ROUTED','EXTERNAL',?,'10.90.0.2',25,?,?)`, []any{pair.Public, stamp, stamp}},
		{`INSERT INTO wireguard_ingress_peer_routes(peer_id,cidr,direction,created_at) VALUES('wg-peer:router','192.168.51.0/24','INGRESS',?)`, []any{stamp}},
	}
	for _, statement := range statements {
		if _, err := database.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func resourceTCPPort() []managementfabric.ResourcePort {
	return []managementfabric.ResourcePort{{Protocol: managementfabric.ProtocolTCP, PortStart: 8443, PortEnd: 8443}}
}
