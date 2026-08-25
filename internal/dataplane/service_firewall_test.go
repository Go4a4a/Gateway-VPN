package dataplane

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/subscription"
)

type serviceExecutor struct {
	requests            []platformexec.Request
	generation          [2]uint32
	endpointGeneration  [2]uint32
	wireGuardGeneration [2]uint32
	payloads            []string
}

func (executor *serviceExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	arguments := strings.Join(request.Arguments, " ")
	if request.Executable == "/usr/sbin/ip" {
		switch arguments {
		case "-json -4 rule show":
			return platformexec.Result{Stdout: desiredRulesJSON}, nil
		case "-json -4 route show table all protocol 186":
			return platformexec.Result{Stdout: desiredRoutesJSON}, nil
		case "-json -4 route get 1.1.1.1 mark 0x1101":
			return platformexec.Result{Stdout: `[{"dst":"1.1.1.1","gateway":"192.168.8.1","dev":"enx0001","table":1101}]`}, nil
		}
		return platformexec.Result{}, fmt.Errorf("unexpected ip request %s", arguments)
	}
	switch arguments {
	case "list table inet gateway_vpn":
		return platformexec.Result{Stdout: serviceFirewallIntegrityText()}, nil
	case "--json list set inet gateway_vpn service_context_generation", "--json list set inet gateway_vpn mihomo_endpoint_generation", "--json list set inet gateway_vpn wireguard_endpoint_generation":
		setName := serviceContextGeneration
		generation := executor.generation
		if strings.HasSuffix(arguments, mihomoEndpointGeneration) {
			setName = mihomoEndpointGeneration
			generation = executor.endpointGeneration
		}
		if strings.HasSuffix(arguments, wireGuardGenerationSet) {
			setName = wireGuardGenerationSet
			generation = executor.wireGuardGeneration
		}
		elements := ""
		if generation != ([2]uint32{}) {
			elements = fmt.Sprintf(`,"elem":[%d,%d]`, generation[0], generation[1])
		}
		return platformexec.Result{Stdout: fmt.Sprintf(`{"nftables":[{"set":{"family":"inet","table":"gateway_vpn","name":%q%s}}]}`, setName, elements)}, nil
	case "--check --file -":
		return platformexec.Result{}, nil
	case "--file -":
		payload := string(request.Stdin)
		executor.payloads = append(executor.payloads, payload)
		marker := "service_context_generation { "
		if index := strings.Index(payload, marker); index >= 0 {
			_, _ = fmt.Sscanf(payload[index:], "service_context_generation { %d, %d", &executor.generation[0], &executor.generation[1])
		}
		endpointMarker := "mihomo_endpoint_generation { "
		if index := strings.Index(payload, endpointMarker); index >= 0 {
			_, _ = fmt.Sscanf(payload[index:], "mihomo_endpoint_generation { %d, %d", &executor.endpointGeneration[0], &executor.endpointGeneration[1])
		}
		wireGuardMarker := "wireguard_endpoint_generation { "
		if index := strings.Index(payload, wireGuardMarker); index >= 0 {
			_, _ = fmt.Sscanf(payload[index:], "wireguard_endpoint_generation { %d, %d", &executor.wireGuardGeneration[0], &executor.wireGuardGeneration[1])
		}
		return platformexec.Result{}, nil
	default:
		return platformexec.Result{}, fmt.Errorf("unexpected nft request %s", arguments)
	}
}

func TestServiceFirewallAuthorizesExactWireGuardEndpointTuple(t *testing.T) {
	_, modems, subscriptions, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	executor := &serviceExecutor{}
	backend := ServiceFirewallBackend{
		Routing: testRoutingBackend(modems, executor, &routingGate{}), Modems: modems,
		Subscriptions: subscriptions, Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"},
	}
	current, err := modems.Get(context.Background(), "modem-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.AuthorizeWireGuardEndpoint(context.Background(), current, "203.0.113.10"); err != nil {
		t.Fatalf("AuthorizeWireGuardEndpoint() error = %v", err)
	}
	if len(executor.payloads) != 2 {
		t.Fatalf("service+WireGuard payload count = %d", len(executor.payloads))
	}
	payload := executor.payloads[1]
	for _, expected := range []string{
		"flush set inet gateway_vpn wireguard_endpoint_v4",
		"flush set inet gateway_vpn wireguard_endpoint_generation",
		`wireguard_endpoint_v4 { "enx0001" . 0x1101 . 203.0.113.10 }`,
	} {
		if !strings.Contains(payload, expected) {
			t.Errorf("WireGuard endpoint payload missing %q:\n%s", expected, payload)
		}
	}
	if executor.wireGuardGeneration == ([2]uint32{}) {
		t.Fatal("WireGuard generation was not observed after apply")
	}
	if err := backend.AuthorizeWireGuardEndpoint(context.Background(), current, "203.0.113.10"); err != nil {
		t.Fatalf("AuthorizeWireGuardEndpoint(no-op) error = %v", err)
	}
	if len(executor.payloads) != 2 {
		t.Fatalf("unchanged WireGuard tuple was rewritten: %d payloads", len(executor.payloads))
	}
}

func TestServiceFirewallSynchronizesModemTuplesAndAuthorizesBoundHTTPS(t *testing.T) {
	_, modems, subscriptions, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	executor := &serviceExecutor{}
	gate := &routingGate{}
	routingBackend := testRoutingBackend(modems, executor, gate)
	backend := ServiceFirewallBackend{Routing: routingBackend, Modems: modems, Subscriptions: subscriptions, Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"}}
	if err := backend.SyncRouting(context.Background()); err != nil {
		t.Fatalf("SyncRouting() error = %v", err)
	}
	if len(executor.payloads) != 1 {
		t.Fatalf("service context payload count = %d", len(executor.payloads))
	}
	base := executor.payloads[0]
	for _, expected := range []string{
		"flush set inet gateway_vpn bootstrap_http_v4",
		"flush set inet gateway_vpn mihomo_endpoint_tcp_v4",
		`hilink_interfaces { "enx0001" }`,
		`hilink_management_v4 { "enx0001" . 192.168.8.1 }`,
		`bootstrap_dns_v4 { "enx0001" . 0x1101 . 1.1.1.1 }`,
	} {
		if !strings.Contains(base, expected) {
			t.Errorf("service context missing %q:\n%s", expected, base)
		}
	}
	if err := backend.AuthorizeBootstrap(context.Background(), BootstrapAuthorization{ModemID: "modem-a", SubscriptionID: "sub-a", Addresses: []string{"203.0.113.10"}, Port: 443}); err != nil {
		t.Fatalf("AuthorizeBootstrap() error = %v", err)
	}
	if len(executor.payloads) != 2 {
		t.Fatalf("all service payload count = %d", len(executor.payloads))
	}
	authorization := executor.payloads[1]
	for _, expected := range []string{
		`destroy element inet gateway_vpn bootstrap_http_v4 { "enx0001" . 0x1101 . 203.0.113.10 . 443 }`,
		`add element inet gateway_vpn bootstrap_http_v4 { "enx0001" . 0x1101 . 203.0.113.10 . 443 timeout 2m }`,
	} {
		if !strings.Contains(authorization, expected) {
			t.Errorf("authorization missing %q:\n%s", expected, authorization)
		}
	}
	if gate.blocks != 0 {
		t.Fatalf("unchanged valid routes unexpectedly closed path gate %d times", gate.blocks)
	}
}

func TestServiceFirewallRejectsPrivateOrNonHTTPSBootstrap(t *testing.T) {
	_, modems, subscriptions, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	executor := &serviceExecutor{}
	backend := ServiceFirewallBackend{Routing: testRoutingBackend(modems, executor, &routingGate{}), Modems: modems, Subscriptions: subscriptions, Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"}}
	for _, input := range []BootstrapAuthorization{
		{ModemID: "modem-a", SubscriptionID: "sub-a", Addresses: []string{"192.168.8.1"}, Port: 443},
		{ModemID: "modem-a", SubscriptionID: "sub-a", Addresses: []string{"203.0.113.10"}, Port: 80},
	} {
		if err := backend.AuthorizeBootstrap(context.Background(), input); err == nil {
			t.Fatalf("invalid authorization accepted: %+v", input)
		}
	}
}

func TestServiceFirewallBuildsMihomoEndpointSetsFromProtectedVersion(t *testing.T) {
	database, modems, subscriptions, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	ctx := context.Background()
	versions := subscription.NewVersionRepository(database)
	payload := []byte("vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443#LTE-node")
	staged, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-a", SubscriptionID: "sub-a", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	payloadRoot := filepath.Join(t.TempDir(), "payloads")
	if _, err := subscription.WriteNormalizedPayload(payloadRoot, "sub-a", "version-a", staged.Import); err != nil {
		t.Fatal(err)
	}
	executor := &serviceExecutor{}
	backend := ServiceFirewallBackend{
		Routing: testRoutingBackend(modems, executor, &routingGate{}), Modems: modems, Subscriptions: subscriptions,
		Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"}, Versions: versions, PayloadRoot: payloadRoot,
	}
	if err := backend.AuthorizeMihomoEndpoints(ctx, MihomoEndpointAuthorization{VersionIDs: []string{"version-a"}}); err != nil {
		t.Fatalf("AuthorizeMihomoEndpoints() error = %v", err)
	}
	if len(executor.payloads) != 2 {
		t.Fatalf("service+endpoint payload count = %d", len(executor.payloads))
	}
	endpointPayload := executor.payloads[1]
	for _, expected := range []string{
		"flush set inet gateway_vpn mihomo_endpoint_tcp_v4",
		"flush set inet gateway_vpn mihomo_endpoint_udp_v4",
		`mihomo_endpoint_tcp_v4 { "enx0001" . 0x1101 . 203.0.113.10 . 443 }`,
		`mihomo_endpoint_udp_v4 { "enx0001" . 0x1101 . 203.0.113.10 . 443 }`,
	} {
		if !strings.Contains(endpointPayload, expected) {
			t.Errorf("Mihomo endpoint payload missing %q:\n%s", expected, endpointPayload)
		}
	}
}

func serviceRepositories(t *testing.T) (*sql.DB, *modem.Repository, *subscription.Repository, func()) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "Operator A", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat("a", 64)}); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{InterfaceName: "enx0001", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		database.Close()
		t.Fatal(err)
	}
	subscriptions := subscription.NewRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "Subscription A", SourceType: "url", SourceSecretRef: "/secret/sub-a", RefreshInterval: time.Hour}); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return database, modems, subscriptions, func() { _ = database.Close() }
}

func serviceFirewallIntegrityText() string {
	return `table inet ` + firewall.TableName + ` {
set firewall_schema_generation
set hilink_interfaces
set hilink_management_v4
set wireguard_endpoint_v4
set wireguard_endpoint_generation
set bootstrap_dns_v4
set bootstrap_http_v4
set mihomo_endpoint_tcp_v4
set mihomo_endpoint_udp_v4
set mihomo_endpoint_generation
set service_context_generation
chain output { type filter hook output priority filter; policy drop;
oifname . meta mark . ip daddr @bootstrap_dns_v4 }
}`
}
