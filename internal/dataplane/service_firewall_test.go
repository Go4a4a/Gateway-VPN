package dataplane

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/subscription"
	"gateway-vpn/internal/uplink"
)

type serviceExecutor struct {
	requests            []platformexec.Request
	generation          [2]uint32
	endpointGeneration  [2]uint32
	wireGuardGeneration [2]uint32
	payloads            []string
	rulesJSON           string
	routesJSON          string
}

func (executor *serviceExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	arguments := strings.Join(request.Arguments, " ")
	if request.Executable == "/usr/sbin/sysctl" {
		if arguments != "-n net.ipv4.conf.all.src_valid_mark" {
			return platformexec.Result{}, fmt.Errorf("unexpected sysctl request %s", arguments)
		}
		return platformexec.Result{Stdout: "1\n"}, nil
	}
	if request.Executable == "/usr/sbin/ip" {
		switch arguments {
		case "-N -json -4 rule show":
			value := executor.rulesJSON
			if value == "" {
				value = desiredRulesJSON
			}
			return platformexec.Result{Stdout: value}, nil
		case "-json -4 route show table all protocol 186":
			value := executor.routesJSON
			if value == "" {
				value = desiredRoutesJSON
			}
			return platformexec.Result{Stdout: value}, nil
		case "-json -4 route get 1.1.1.1 mark 0x1101":
			return platformexec.Result{Stdout: `[{"dst":"1.1.1.1","gateway":"192.168.8.1","dev":"enx0001","table":1101}]`}, nil
		case "-json -4 route get 1.1.1.1 mark 0x1102":
			return platformexec.Result{Stdout: `[{"dst":"1.1.1.1","gateway":"172.20.1.1","dev":"enp3s0","table":1102}]`}, nil
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
	database, modems, subscriptions, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	executor := &serviceExecutor{}
	policies := accesspolicy.NewRepository(database)
	backend := ServiceFirewallBackend{
		Routing: testRoutingBackend(uplink.NewRepository(database, 1101, 0x1101), executor, &routingGate{}), Modems: modems,
		Subscriptions: subscriptions, AccessPolicy: policies, Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"},
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
	database, modems, subscriptions, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	targets := bypass.NewRepository(database)
	if _, err := targets.Create(context.Background(), bypass.CreateInput{ID: "target-a", Name: "Target A", Kind: bypass.KindDomain, Value: "example.com", Required: true, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessAnyHTTPResponse}); err != nil {
		t.Fatal(err)
	}
	executor := &serviceExecutor{}
	gate := &routingGate{}
	routingBackend := testRoutingBackend(uplink.NewRepository(database, 1101, 0x1101), executor, gate)
	backend := ServiceFirewallBackend{Routing: routingBackend, Modems: modems, Subscriptions: subscriptions, AccessPolicy: accesspolicy.NewRepository(database), Targets: targets, Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"}}
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
	if err := backend.AuthorizeUpdateService(context.Background(), UpdateServiceAuthorization{UplinkID: "modem-a", Addresses: []string{"8.8.4.4"}, Port: 443}); err != nil {
		t.Fatalf("AuthorizeUpdateService() error = %v", err)
	}
	if len(executor.payloads) != 3 || !strings.Contains(executor.payloads[2], `bootstrap_http_v4 { "enx0001" . 0x1101 . 8.8.4.4 . 443 timeout 2m }`) {
		t.Fatalf("signed update authorization payloads = %#v", executor.payloads)
	}
	for _, address := range []string{"100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.12"} {
		if err := backend.AuthorizeUpdateService(context.Background(), UpdateServiceAuthorization{UplinkID: "modem-a", Addresses: []string{address}, Port: 443}); err == nil {
			t.Fatalf("signed update root boundary accepted non-routable address %s", address)
		}
	}
	if len(executor.payloads) != 3 {
		t.Fatalf("rejected update authorization mutated firewall: %d payloads", len(executor.payloads))
	}
	if gate.blocks != 0 {
		t.Fatalf("unchanged valid routes unexpectedly closed path gate %d times", gate.blocks)
	}
	if err := backend.AuthorizeDirectProbe(context.Background(), DirectProbeAuthorization{ModemID: "modem-a", TargetID: "target-a", Addresses: []string{"203.0.113.11"}, Port: 443}); err != nil {
		t.Fatalf("AuthorizeDirectProbe() error = %v", err)
	}
	if len(executor.payloads) != 4 || !strings.Contains(executor.payloads[3], `bootstrap_http_v4 { "enx0001" . 0x1101 . 203.0.113.11 . 443 timeout 2m }`) {
		t.Fatalf("direct authorization payloads = %#v", executor.payloads)
	}
	if err := backend.AuthorizeDirectProbe(context.Background(), DirectProbeAuthorization{ModemID: "modem-a", TargetID: "target-a", Addresses: []string{"203.0.113.11"}, Port: 444}); err == nil {
		t.Fatal("direct probe authorization accepted a port outside target policy")
	}
	target, err := targets.Get(context.Background(), "target-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := targets.Update(context.Background(), target.ID, bypass.UpdateInput{
		Name: target.Name, Kind: target.Kind, Value: target.Value, Enabled: false,
		Required: target.Required, Timeout: time.Duration(target.TimeoutSeconds) * time.Second,
		SuccessMode: target.SuccessMode, ExpectedStatus: target.ExpectedStatus,
		ExpectedBodySubstring: target.ExpectedBodySubstring, AllowNoRequired: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := backend.AuthorizeDirectProbe(context.Background(), DirectProbeAuthorization{ModemID: "modem-a", TargetID: "target-a", Addresses: []string{"203.0.113.11"}, Port: 443}); err == nil {
		t.Fatal("direct probe authorization accepted a target disabled during policy change")
	}
}

func TestServiceFirewallAuthorizesSignedUpdateThroughReadyEthernetUplink(t *testing.T) {
	database, modems, subscriptions, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	ctx := context.Background()
	uplinks := uplink.NewRepository(database, 1101, 0x1101)
	if _, err := uplinks.ObserveInterface(ctx, uplink.InterfaceObservation{
		ID: "netif:ethernet:a", StableIdentityKind: "ETHERNET_PERMANENT_MAC",
		StableIdentityHash: strings.Repeat("e", 64), CurrentIfname: "enp3s0", CarrierState: "UP",
	}); err != nil {
		t.Fatal(err)
	}
	created, err := uplinks.CreateEthernet(ctx, uplink.CreateEthernetInput{
		ID: "ethernet-a", Name: "WAN Ethernet", NetworkInterfaceID: "netif:ethernet:a",
		AddressMode: uplink.AddressDHCP, DNS: []string{"9.9.9.9"}, MTU: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uplinks.ObserveEthernetRuntime(ctx, created.ID, uplink.EthernetRuntimeObservation{
		NetworkInterfaceID: created.NetworkInterfaceID, InterfaceName: "enp3s0",
		IPv4CIDR: "172.20.1.2/24", Gateway: "172.20.1.1", DNS: []string{"9.9.9.9"},
		State: uplink.StateReady, ReadinessReason: "READY", ConfigurationSeen: true,
	}); err != nil {
		t.Fatal(err)
	}
	executor := &serviceExecutor{
		rulesJSON: `[{"priority":1101,"src":"all","fwmark":"0x1101","table":"1101","protocol":"186"},{"priority":1102,"src":"all","fwmark":"0x1102","table":"1102","protocol":"186"}]`,
		routesJSON: `[
  {"dst":"192.168.8.0/24","dev":"enx0001","scope":"link","table":"1101"},
  {"dst":"default","gateway":"192.168.8.1","dev":"enx0001","table":"1101"},
  {"dst":"172.20.1.0/24","dev":"enp3s0","scope":"link","table":"1102"},
  {"dst":"default","gateway":"172.20.1.1","dev":"enp3s0","table":"1102"}
]`,
	}
	backend := ServiceFirewallBackend{
		Routing: testRoutingBackend(uplinks, executor, &routingGate{}), Modems: modems,
		Subscriptions: subscriptions, AccessPolicy: accesspolicy.NewRepository(database),
		Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"},
	}
	if err := backend.SyncRouting(ctx); err != nil {
		t.Fatalf("SyncRouting(Ethernet) error = %v", err)
	}
	if len(executor.payloads) != 1 {
		t.Fatalf("Ethernet service context payloads = %d", len(executor.payloads))
	}
	contextPayload := executor.payloads[0]
	for _, expected := range []string{
		`hilink_interfaces { "enp3s0" }`,
		`bootstrap_dns_v4 { "enp3s0" . 0x1102 . 1.1.1.1 }`,
	} {
		if !strings.Contains(contextPayload, expected) {
			t.Errorf("Ethernet service context missing %q:\n%s", expected, contextPayload)
		}
	}
	if strings.Contains(contextPayload, `hilink_management_v4 { "enp3s0"`) {
		t.Fatalf("Ethernet incorrectly received a HiLink management exception:\n%s", contextPayload)
	}
	if err := backend.AuthorizeUpdateService(ctx, UpdateServiceAuthorization{UplinkID: created.ID, Addresses: []string{"9.9.9.9"}, Port: 443}); err != nil {
		t.Fatalf("AuthorizeUpdateService(Ethernet) error = %v", err)
	}
	if len(executor.payloads) != 2 || !strings.Contains(executor.payloads[1], `bootstrap_http_v4 { "enp3s0" . 0x1102 . 9.9.9.9 . 443 timeout 2m }`) {
		t.Fatalf("Ethernet update authorization payloads = %#v", executor.payloads)
	}
}

func TestUpdateServiceRoutesAgainstKernelNFTablesAndPolicyRouting(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_UPDATE_SERVICE_INTEGRATION") != "1" {
		t.Skip("set GATEWAY_VPN_UPDATE_SERVICE_INTEGRATION=1 inside an isolated Linux network namespace")
	}
	ctx := context.Background()
	executor := platformexec.OSExecutor{}
	ruleset, err := firewall.RenderBootBlocked(firewall.BootConfig{
		LANInterface: "lan0", TUNInterface: "gateway-vpn-tun", WireGuardInterface: "wg-mgmt",
		APIPort: 8443, WireGuardListenPort: 51821,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := firewall.ValidateAndLoad(ctx, executor, ruleset, firewall.LoadOptions{NFTExecutable: "/usr/sbin/nft", Mutate: true}); err != nil {
		t.Fatalf("load update-service integration ruleset: %v", err)
	}
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "HiLink", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{
		InterfaceName: "wan0", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1",
		DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady,
	}); err != nil {
		t.Fatal(err)
	}
	uplinks := uplink.NewRepository(database, 1101, 0x1101)
	if _, err := uplinks.ObserveInterface(ctx, uplink.InterfaceObservation{
		ID: "netif:wan1", StableIdentityKind: "ETHERNET_PERMANENT_MAC",
		StableIdentityHash: strings.Repeat("e", 64), CurrentIfname: "wan1", CarrierState: "UP",
	}); err != nil {
		t.Fatal(err)
	}
	ethernet, err := uplinks.CreateEthernet(ctx, uplink.CreateEthernetInput{
		ID: "ethernet-a", Name: "Ethernet", NetworkInterfaceID: "netif:wan1",
		AddressMode: uplink.AddressDHCP, DNS: []string{"1.1.1.1"}, MTU: 1500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uplinks.ObserveEthernetRuntime(ctx, ethernet.ID, uplink.EthernetRuntimeObservation{
		NetworkInterfaceID: ethernet.NetworkInterfaceID, InterfaceName: "wan1",
		IPv4CIDR: "172.20.1.2/24", Gateway: "172.20.1.1", DNS: []string{"1.1.1.1"},
		State: uplink.StateReady, ReadinessReason: "READY", ConfigurationSeen: true,
	}); err != nil {
		t.Fatal(err)
	}
	gate := &routingGate{}
	routingBackend := testRoutingBackend(uplinks, executor, gate)
	routingBackend.Sysctl = "/usr/sbin/sysctl"
	backend := ServiceFirewallBackend{
		Routing: routingBackend, Modems: modems,
		Subscriptions: subscription.NewRepository(database), AccessPolicy: accesspolicy.NewRepository(database),
		Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"},
	}
	if err := backend.AuthorizeUpdateService(ctx, UpdateServiceAuthorization{UplinkID: "modem-a", Addresses: []string{"8.8.8.8"}, Port: 443}); err != nil {
		t.Fatalf("authorize HiLink update packet: %v", err)
	}
	if err := backend.AuthorizeUpdateService(ctx, UpdateServiceAuthorization{UplinkID: ethernet.ID, Addresses: []string{"9.9.9.9"}, Port: 443}); err != nil {
		t.Fatalf("authorize Ethernet update packet: %v", err)
	}
	result, err := executor.Run(ctx, platformexec.Request{Executable: "/usr/sbin/nft", Arguments: []string{"list", "set", "inet", firewall.TableName, bootstrapHTTPSet}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tuple := range []string{`"wan0" . 0x00001101 . 8.8.8.8 . 443`, `"wan1" . 0x00001102 . 9.9.9.9 . 443`} {
		if !strings.Contains(result.Stdout, tuple) {
			t.Errorf("kernel update-service allowlist missing %q:\n%s", tuple, result.Stdout)
		}
	}
	management, err := executor.Run(ctx, platformexec.Request{Executable: "/usr/sbin/nft", Arguments: []string{"list", "set", "inet", firewall.TableName, hilinkManagementSet}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(management.Stdout, `"wan0" . 192.168.8.1`) || strings.Contains(management.Stdout, `"wan1"`) {
		t.Fatalf("kernel HiLink management projection is not type-scoped:\n%s", management.Stdout)
	}
	if gate.blocks != 1 {
		t.Fatalf("initial policy-routing mutation did not close the path exactly once: %d", gate.blocks)
	}
	// Kernel state intentionally remains until the disposable namespace exits;
	// the shell harness performs packet probes after this root test process.
}

func TestServiceFirewallRejectsPrivateOrNonHTTPSBootstrap(t *testing.T) {
	database, modems, subscriptions, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	executor := &serviceExecutor{}
	backend := ServiceFirewallBackend{Routing: testRoutingBackend(uplink.NewRepository(database, 1101, 0x1101), executor, &routingGate{}), Modems: modems, Subscriptions: subscriptions, AccessPolicy: accesspolicy.NewRepository(database), Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"}}
	for _, input := range []BootstrapAuthorization{
		{ModemID: "modem-a", SubscriptionID: "sub-a", Addresses: []string{"192.168.8.1"}, Port: 443},
		{ModemID: "modem-a", SubscriptionID: "sub-a", Addresses: []string{"203.0.113.10"}, Port: 80},
	} {
		if err := backend.AuthorizeBootstrap(context.Background(), input); err == nil {
			t.Fatalf("invalid authorization accepted: %+v", input)
		}
	}
}

func TestServiceFirewallAllowsRefreshForRoutingDisabledURLSubscription(t *testing.T) {
	database, modems, subscriptions, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	ctx := context.Background()
	if err := subscriptions.SetEnabled(ctx, "sub-a", false); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	executor := &serviceExecutor{}
	policies := accesspolicy.NewRepository(database)
	backend := ServiceFirewallBackend{
		Routing: testRoutingBackend(uplink.NewRepository(database, 1101, 0x1101), executor, &routingGate{}), Modems: modems,
		Subscriptions: subscriptions, AccessPolicy: policies, Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"},
	}
	if err := backend.AuthorizeBootstrap(ctx, BootstrapAuthorization{ModemID: "modem-a", SubscriptionID: "sub-a", Addresses: []string{"203.0.113.12"}, Port: 443}); err != nil {
		t.Fatalf("AuthorizeBootstrap() for routing-disabled URL subscription error = %v", err)
	}
	if len(executor.payloads) != 2 || !strings.Contains(executor.payloads[1], `bootstrap_http_v4 { "enx0001" . 0x1101 . 203.0.113.12 . 443 timeout 2m }`) {
		t.Fatalf("disabled subscription authorization payloads = %#v", executor.payloads)
	}
	policy, err := policies.GetPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policies.UpdatePolicy(ctx, accesspolicy.PolicyUpdate{
		StartupBlockUntilQualified: policy.StartupBlockUntilQualified,
		DirectServiceRefresh:       false,
		FailureHoldSeconds:         policy.FailureHoldSeconds,
		RecoveryStableSeconds:      policy.RecoveryStableSeconds,
		SwitchCooldownSeconds:      policy.SwitchCooldownSeconds,
	}); err != nil {
		t.Fatal(err)
	}
	if err := backend.AuthorizeBootstrap(ctx, BootstrapAuthorization{ModemID: "modem-a", SubscriptionID: "sub-a", Addresses: []string{"203.0.113.13"}, Port: 443}); err == nil {
		t.Fatal("root bootstrap authorization ignored disabled direct service refresh policy")
	}
	if len(executor.payloads) != 2 {
		t.Fatalf("disabled direct service refresh mutated firewall: %d payloads", len(executor.payloads))
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
		Routing: testRoutingBackend(uplink.NewRepository(database, 1101, 0x1101), executor, &routingGate{}), Modems: modems, Subscriptions: subscriptions,
		AccessPolicy: accesspolicy.NewRepository(database), Executor: executor, NFT: "/usr/sbin/nft", BootstrapDNS: []string{"1.1.1.1"}, Versions: versions, PayloadRoot: payloadRoot,
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
counter service_upload
counter service_download
chain output { type filter hook output priority filter; policy drop;
oifname . meta mark . ip daddr @bootstrap_dns_v4 }
}`
}
