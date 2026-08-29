package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/firewall"
	"gateway-vpn/internal/platformexec"
	statepkg "gateway-vpn/internal/state"
	"gateway-vpn/internal/uplink"
	"gateway-vpn/internal/wgingress"
)

type firewallExecutor struct {
	requests  []platformexec.Request
	state     PathState
	badTable  bool
	badSchema bool
	applyErr  error
}

func (executor *firewallExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	arguments := strings.Join(request.Arguments, " ")
	switch arguments {
	case "list table inet gateway_vpn":
		if executor.badTable {
			return platformexec.Result{Stdout: "table inet gateway_vpn { chain forward { } }"}, nil
		}
		return platformexec.Result{Stdout: healthyPathFirewallTable()}, nil
	case "--json list set inet gateway_vpn firewall_schema_generation":
		generation := firewall.SchemaGeneration
		if executor.badSchema {
			generation++
		}
		return platformexec.Result{Stdout: fmt.Sprintf(`{"nftables":[{"set":{"family":"inet","table":"gateway_vpn","name":"firewall_schema_generation","elem":[%d]}}]}`, generation)}, nil
	case "--check --file -":
		return platformexec.Result{}, nil
	case "--file -":
		if executor.applyErr != nil {
			return platformexec.Result{Stderr: "private nft detail"}, executor.applyErr
		}
		payload := string(request.Stdin)
		switch {
		case strings.Contains(payload, `add element inet gateway_vpn active_tun_interfaces { "gateway-vpn-tun" }`):
			executor.state = PathState{Active: true, Mode: PathModeTUN, Generation: parseNamedUint(payload, activeGenerationSet)}
		case strings.Contains(payload, "add element inet gateway_vpn active_direct_context"):
			var interfaceName string
			var mark uint32
			index := strings.Index(payload, activeDirectContextSet+" { ")
			if index >= 0 {
				_, _ = fmt.Sscanf(payload[index:], activeDirectContextSet+" { %q . 0x%x", &interfaceName, &mark)
			}
			executor.state = PathState{
				Active: true, Mode: PathModeDirect,
				Generation: parseNamedUint(payload, activeGenerationSet), DirectInterface: interfaceName,
				DirectMark: mark, RouteGeneration: parseNamedUint(payload, activeRouteGenerationSet),
			}
		default:
			executor.state = PathState{}
		}
		return platformexec.Result{}, nil
	case "--json list table inet gateway_vpn":
		return platformexec.Result{Stdout: observedJSON(executor.state)}, nil
	default:
		return platformexec.Result{}, fmt.Errorf("unexpected request %s", arguments)
	}
}

func TestFirewallBackendAtomicallyActivatesAndBlocksOnlyOwnedGateCollections(t *testing.T) {
	executor := &firewallExecutor{}
	backend, closeDatabase := testFirewallBackendWithPolicy(t, executor, "SUBSCRIPTION")
	defer closeDatabase()
	if err := backend.ActivatePath(context.Background(), 42); err != nil {
		t.Fatalf("ActivatePath() error = %v", err)
	}
	if executor.state != (PathState{Active: true, Mode: PathModeTUN, Generation: 42}) {
		t.Fatalf("active state = %+v", executor.state)
	}
	activePayload := lastFirewallPayload(t, executor.requests)
	for _, required := range []string{
		"flush set inet gateway_vpn active_tun_interfaces",
		"flush set inet gateway_vpn active_direct_interfaces",
		"flush set inet gateway_vpn active_direct_context",
		"flush map inet gateway_vpn active_direct_marks",
		"flush set inet gateway_vpn active_path_generation",
		"flush set inet gateway_vpn active_route_generation",
		"flush set inet gateway_vpn wireguard_ingress_allowed_v4",
		"add element inet gateway_vpn active_path_generation { 42 }",
		`add element inet gateway_vpn active_tun_interfaces { "gateway-vpn-tun" }`,
	} {
		if !strings.Contains(activePayload, required) {
			t.Errorf("active transaction missing %q: %s", required, activePayload)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "delete table", "hilink_interfaces", "policy accept", "add element inet gateway_vpn active_direct_context"} {
		if strings.Contains(activePayload, forbidden) {
			t.Fatalf("TUN transaction contains forbidden %q", forbidden)
		}
	}
	if err := backend.BlockPath(context.Background()); err != nil {
		t.Fatalf("BlockPath() error = %v", err)
	}
	if executor.state != (PathState{}) {
		t.Fatalf("blocked state = %+v", executor.state)
	}
	blockPayload := lastFirewallPayload(t, executor.requests)
	if strings.Contains(blockPayload, "add element") {
		t.Fatalf("blocked transaction opens a gate: %s", blockPayload)
	}
}

func TestFirewallBackendRendersExactDirectContextAndNeverLeavesTUNOpen(t *testing.T) {
	executor := &firewallExecutor{}
	backend, closeDatabase := testFirewallBackendWithPolicy(t, executor, "DIRECT")
	defer closeDatabase()
	desired := PathState{Active: true, Mode: PathModeDirect, Generation: 73, DirectInterface: "enx0001", DirectMark: 0x1101, RouteGeneration: 9}
	if err := backend.apply(context.Background(), desired); err != nil {
		t.Fatalf("apply(DIRECT) error = %v", err)
	}
	if executor.state != desired {
		t.Fatalf("direct state = %+v", executor.state)
	}
	payload := lastFirewallPayload(t, executor.requests)
	for _, expected := range []string{
		`active_path_generation { 73 }`, `active_route_generation { 9 }`,
		`active_direct_interfaces { "enx0001" }`,
		`active_direct_context { "enx0001" . 0x00001101 }`,
		`active_direct_marks { "enp2s0" : 0x00001101 }`,
		`active_direct_marks { "wg-ingress" : 0x00001101 }`,
	} {
		if !strings.Contains(payload, expected) {
			t.Errorf("direct transaction missing %q:\n%s", expected, payload)
		}
	}
	if strings.Contains(payload, `add element inet gateway_vpn active_tun_interfaces`) {
		t.Fatal("direct transaction also opens the TUN gate")
	}
}

func TestFirewallBackendAuthorizesDirectPathOnlyFromFreshRuntimeIntent(t *testing.T) {
	ctx := context.Background()
	database, modems, _, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	targets := bypass.NewRepository(database)
	if _, err := targets.Create(ctx, bypass.CreateInput{ID: "target-a", Name: "Required target", Kind: bypass.KindDomain, Value: "example.com", Required: true, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessAnyHTTPResponse}); err != nil {
		t.Fatal(err)
	}
	paths := accesspolicy.NewDirectPathRepository(database)
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	path, err := paths.Get(ctx, "direct:path:modem-a")
	if err != nil {
		t.Fatal(err)
	}
	checkedAt := time.Now().UTC()
	if err := paths.Publish(ctx, accesspolicy.DirectResultUpdate{
		PathID: path.ID, ExpectedPolicyGeneration: path.PolicyGeneration, ExpectedRouteGeneration: path.RouteGeneration,
		TransportState: "PASSED", QualityClass: accesspolicy.QualityFull, FunctionalScore: 100,
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 11,
		CheckedAt: checkedAt, ExpiresAt: checkedAt.Add(2 * time.Minute),
		Targets: []accesspolicy.DirectTargetResult{{TargetID: "target-a", TargetClass: "GLOBAL_REQUIRED", State: "PASSED", LatencyMS: 11, HTTPStatus: 204, CheckedAt: checkedAt, ExpiresAt: checkedAt.Add(2 * time.Minute)}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state='VERIFYING', path_state='PATH_VERIFYING', active_uplink_id='modem-a', active_modem_id='modem-a',
    active_path_id=NULL, active_direct_path_id='direct:path:modem-a',
    active_subscription_id=NULL, active_node_id=NULL,
    active_method_id='access:direct', active_method_kind='DIRECT', active_quality_class='FULL',
    config_generation=73
WHERE singleton_id=1`); err != nil {
		t.Fatal(err)
	}
	currentModem, err := modems.Get(ctx, "modem-a")
	if err != nil {
		t.Fatal(err)
	}
	routing := &fakeRoutingSynchronizer{}
	executor := &firewallExecutor{}
	backend := FirewallBackend{
		Database: database, Uplinks: uplink.NewRepository(database, 1101, 0x1101), Routing: routing, Executor: executor,
		NFT: "/usr/sbin/nft", TUNName: "gateway-vpn-tun", LANName: "enp2s0",
	}
	if err := backend.ActivateDirectPath(ctx, "modem-a", currentModem.RouteGeneration); err != nil {
		t.Fatalf("ActivateDirectPath() error = %v", err)
	}
	want := PathState{Active: true, Mode: PathModeDirect, Generation: 73, DirectInterface: "enx0001", DirectMark: 0x1101, RouteGeneration: uint32(currentModem.RouteGeneration)}
	if executor.state != want || routing.calls != 1 {
		t.Fatalf("direct activation state/routing = %+v/%d, want %+v/1", executor.state, routing.calls, want)
	}
	if err := backend.ActivateDirectPath(ctx, "modem-a", currentModem.RouteGeneration+1); err == nil {
		t.Fatal("ActivateDirectPath(stale route generation) error = nil")
	}
	before := len(executor.requests)
	if _, err := database.ExecContext(ctx, "UPDATE direct_uplink_paths SET expires_at='2000-01-01T00:00:00Z' WHERE id=?", path.ID); err != nil {
		t.Fatal(err)
	}
	if err := backend.ActivateDirectPath(ctx, "modem-a", currentModem.RouteGeneration); err == nil || len(executor.requests) != before {
		t.Fatalf("ActivateDirectPath(expired evidence) error/requests = %v/%d, before %d", err, len(executor.requests), before)
	}
}

func TestFirewallBackendActivatesEthernetDirectPathWithoutModemProjection(t *testing.T) {
	ctx := context.Background()
	database, _, _, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	uplinks := uplink.NewRepository(database, 1101, 0x1101)
	if _, err := uplinks.ObserveInterface(ctx, uplink.InterfaceObservation{
		ID: "nic-ethernet-direct", StableIdentityKind: "permanent_mac_hash",
		StableIdentityHash: strings.Repeat("a", 64), CurrentIfname: "enp9s0", CarrierState: "UP",
	}); err != nil {
		t.Fatal(err)
	}
	created, err := uplinks.CreateEthernet(ctx, uplink.CreateEthernetInput{
		ID: "ethernet-direct", Name: "Ethernet direct", NetworkInterfaceID: "nic-ethernet-direct",
		AddressMode: uplink.AddressDHCP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE uplinks SET state='UPLINK_READY', observed_generation=desired_generation, route_generation=1 WHERE id=?", created.ID); err != nil {
		t.Fatal(err)
	}
	currentUplink, err := uplinks.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	targets := bypass.NewRepository(database)
	if _, err := targets.Create(ctx, bypass.CreateInput{ID: "ethernet-target", Name: "Required target", Kind: bypass.KindDomain, Value: "ethernet.example", Required: true, Timeout: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	paths := accesspolicy.NewDirectPathRepository(database)
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	path, err := paths.Get(ctx, "direct:path:"+created.ID)
	if err != nil || path.UplinkType != uplink.TypeEthernet {
		t.Fatalf("Ethernet direct path = %+v, %v", path, err)
	}
	checkedAt := time.Now().UTC()
	if err := paths.Publish(ctx, accesspolicy.DirectResultUpdate{
		PathID: path.ID, ExpectedPolicyGeneration: path.PolicyGeneration, ExpectedRouteGeneration: path.RouteGeneration,
		TransportState: "PASSED", QualityClass: accesspolicy.QualityFull, FunctionalScore: 1000,
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 8,
		CheckedAt: checkedAt, ExpiresAt: checkedAt.Add(2 * time.Minute),
		Targets: []accesspolicy.DirectTargetResult{{TargetID: "ethernet-target", TargetClass: "GLOBAL_REQUIRED", State: "PASSED", LatencyMS: 8, HTTPStatus: 204, CheckedAt: checkedAt, ExpiresAt: checkedAt.Add(2 * time.Minute)}},
	}); err != nil {
		t.Fatal(err)
	}
	intent, changed, err := statepkg.NewRepository(database).BeginDirectActivation(ctx, path.ID, path.PolicyGeneration, path.RouteGeneration)
	if err != nil || !changed || intent.ActiveUplinkID != created.ID || intent.ActiveModemID != "" {
		t.Fatalf("Ethernet activation intent = %+v/%v/%v", intent, changed, err)
	}
	routing := &fakeRoutingSynchronizer{}
	executor := &firewallExecutor{}
	backend := FirewallBackend{
		Database: database, Uplinks: uplinks, Routing: routing, Executor: executor,
		NFT: "/usr/sbin/nft", TUNName: "gateway-vpn-tun", LANName: "enp2s0",
	}
	if err := backend.ActivateDirectPath(ctx, created.ID, currentUplink.RouteGeneration); err != nil {
		t.Fatalf("ActivateDirectPath(Ethernet) error = %v", err)
	}
	want := PathState{
		Active: true, Mode: PathModeDirect, Generation: uint32(intent.ConfigGeneration),
		DirectInterface: "enp9s0", DirectMark: uint32(currentUplink.Fwmark),
		RouteGeneration: uint32(currentUplink.RouteGeneration),
	}
	if executor.state != want || routing.calls != 1 {
		t.Fatalf("Ethernet direct firewall state/routing = %+v/%d, want %+v/1", executor.state, routing.calls, want)
	}
}

func TestFirewallBackendRejectsMissingMarkersWrongSchemaAndRedactsNftFailure(t *testing.T) {
	backend := FirewallBackend{NFT: "/usr/sbin/nft", TUNName: "gateway-vpn-tun", LANName: "enp2s0"}
	backend.Executor = &firewallExecutor{badTable: true}
	if err := backend.ActivatePath(context.Background(), 1); err == nil {
		t.Fatal("ActivatePath(incomplete table) error = nil")
	}
	backend.Executor = &firewallExecutor{badSchema: true}
	if err := backend.ActivatePath(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "schema generation") {
		t.Fatalf("ActivatePath(wrong schema) error = %v", err)
	}
	applyExecutor := &firewallExecutor{applyErr: errors.New("apply failed")}
	backend, closeDatabase := testFirewallBackendWithPolicy(t, applyExecutor, "SUBSCRIPTION")
	defer closeDatabase()
	if err := backend.ActivatePath(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "private nft detail") {
		t.Fatalf("ActivatePath(apply failure) error = %v", err)
	}
}

func TestRenderPathTransactionRejectsHalfActiveStates(t *testing.T) {
	for name, pathState := range map[string]PathState{
		"blocked-with-generation": {Generation: 1},
		"unknown-mode":            {Active: true, Mode: "OTHER", Generation: 1},
		"tun-with-direct-context": {Active: true, Mode: PathModeTUN, Generation: 1, DirectMark: 1},
		"direct-without-route":    {Active: true, Mode: PathModeDirect, Generation: 1, DirectInterface: "enx0001", DirectMark: 0x1101},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderPathTransaction(pathState, "gateway-vpn-tun", "enp2s0", nil); err == nil {
				t.Fatal("renderPathTransaction() error = nil")
			}
		})
	}
}

func TestWireGuardIngressPeerPolicyFiltersSourcesForActiveMethodAndQuality(t *testing.T) {
	ctx := context.Background()
	database, _, _, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	if err := accesspolicy.NewDirectPathRepository(database).Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
UPDATE runtime_state
SET gateway_state='VERIFYING', path_state='PATH_VERIFYING',
    active_uplink_id='modem-a', active_modem_id='modem-a',
    active_path_id=NULL, active_direct_path_id='direct:path:modem-a',
    active_subscription_id=NULL, active_node_id=NULL,
    active_method_id='access:direct', active_method_kind='DIRECT', active_quality_class='FULL'
WHERE singleton_id=1`); err != nil {
		t.Fatal(err)
	}
	secretRoot := filepath.Join(t.TempDir(), "wireguard-ingress")
	repository := wgingress.Repository{Database: database, SecretRoot: secretRoot}
	keys := wgingress.KeyStore{Root: secretRoot}
	if _, err := repository.EnsureDefault(ctx, keys); err != nil {
		t.Fatal(err)
	}
	create := func(name, mode string, block, whitelist bool, methods, routes []string) wgingress.Peer {
		t.Helper()
		pair, err := wgingress.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		peer, err := repository.CreatePeer(ctx, wgingress.PeerCreate{
			Name: name, PeerKind: "ROUTER_ROUTED", KeyMode: "EXTERNAL", PublicKey: pair.Public,
			PersistentKeepalive: 25, AccessPolicyMode: mode, AllowWhitelistOnly: whitelist,
			BlockWhenUnqualified: block, BehindSubnets: routes,
			ClientAllowedIPs: []string{"0.0.0.0/0"}, AllowedAccessMethodIDs: methods,
		}, nil, "", keys)
		if err != nil {
			t.Fatal(err)
		}
		return peer
	}
	direct := create("Direct", "DIRECT_ONLY", true, true, nil, []string{"172.20.0.0/24"})
	_ = create("VPN blocked", "VPN_ONLY", true, true, nil, nil)
	fallback := create("Fallback", "AUTO", false, true, []string{"access:subscription:sub-a"}, nil)
	noWhitelist := create("No whitelist", "AUTO", true, false, nil, nil)
	backend := FirewallBackend{Database: database}
	sources, err := backend.allowedWireGuardSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{direct.AssignedAddress + "/32", "172.20.0.0/24", fallback.AssignedAddress + "/32", noWhitelist.AssignedAddress + "/32"}
	sort.Strings(want)
	if strings.Join(sources, ",") != strings.Join(want, ",") {
		t.Fatalf("FULL allowed sources = %v, want %v", sources, want)
	}
	if _, err := database.Exec("UPDATE runtime_state SET active_quality_class='WHITELIST_ONLY' WHERE singleton_id=1"); err != nil {
		t.Fatal(err)
	}
	sources, err = backend.allowedWireGuardSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{noWhitelist.AssignedAddress + "/32"} {
		if slices.Contains(sources, forbidden) {
			t.Fatalf("WHITELIST_ONLY allowed forbidden source %s in %v", forbidden, sources)
		}
	}
}

func TestDecodePathStateRejectsHalfActiveConflictsAndWrongMap(t *testing.T) {
	tun := PathState{Active: true, Mode: PathModeTUN, Generation: 9}
	if _, err := decodePathState([]byte(observedJSON(tun)), "wrong-tun", "enp2s0"); err == nil {
		t.Fatal("decodePathState(wrong TUN) error = nil")
	}
	half := `{"nftables":[{"set":{"family":"inet","table":"gateway_vpn","name":"active_tun_interfaces","elem":["gateway-vpn-tun"]}},{"set":{"family":"inet","table":"gateway_vpn","name":"active_path_generation"}}]}`
	if _, err := decodePathState([]byte(half), "gateway-vpn-tun", "enp2s0"); err == nil {
		t.Fatal("decodePathState(half active) error = nil")
	}
	direct := PathState{Active: true, Mode: PathModeDirect, Generation: 5, DirectInterface: "enx0001", DirectMark: 0x1101, RouteGeneration: 7}
	conflict := strings.Replace(observedJSON(direct), `"name":"active_tun_interfaces"`, `"name":"active_tun_interfaces","elem":["gateway-vpn-tun"]`, 1)
	if _, err := decodePathState([]byte(conflict), "gateway-vpn-tun", "enp2s0"); err == nil {
		t.Fatal("decodePathState(TUN+DIRECT) error = nil")
	}
	wrongMap := strings.Replace(observedJSON(direct), `"val":"enp2s0"`, `"val":"other-lan"`, 1)
	if _, err := decodePathState([]byte(wrongMap), "gateway-vpn-tun", "enp2s0"); err == nil {
		t.Fatal("decodePathState(wrong direct mark map) error = nil")
	}
}

func TestFirewallBackendAgainstKernelNFTables(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_NFT_PATH_INTEGRATION") != "1" {
		t.Skip("set GATEWAY_VPN_NFT_PATH_INTEGRATION=1 inside an isolated Linux network namespace")
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
		t.Fatalf("load integration ruleset: %v", err)
	}
	defer func() {
		_, _ = executor.Run(context.Background(), platformexec.Request{Executable: "/usr/sbin/nft", Arguments: []string{"delete", "table", "inet", firewall.TableName}})
	}()
	database, _, _, closeDatabase := serviceRepositories(t)
	defer closeDatabase()
	if err := accesspolicy.NewDirectPathRepository(database).Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
UPDATE runtime_state
SET gateway_state='VERIFYING', path_state='PATH_VERIFYING',
    active_uplink_id='modem-a', active_modem_id='modem-a',
    active_path_id=NULL, active_direct_path_id='direct:path:modem-a',
    active_subscription_id=NULL, active_node_id=NULL,
    active_method_id='access:direct', active_method_kind='DIRECT', active_quality_class='FULL'
WHERE singleton_id=1`); err != nil {
		t.Fatal(err)
	}
	backend := FirewallBackend{Database: database, Executor: executor, NFT: "/usr/sbin/nft", TUNName: "gateway-vpn-tun", LANName: "lan0"}
	if err := backend.ActivatePath(ctx, 41); err != nil {
		t.Fatalf("activate kernel TUN path: %v", err)
	}
	direct := PathState{Active: true, Mode: PathModeDirect, Generation: 42, DirectInterface: "wan0", DirectMark: 0x1101, RouteGeneration: 7}
	if err := backend.apply(ctx, direct); err != nil {
		t.Fatalf("activate kernel direct path: %v", err)
	}
	observed, err := backend.ObservePath(ctx)
	if err != nil || observed != direct {
		t.Fatalf("observe kernel direct path = %+v, %v", observed, err)
	}
	if err := backend.BlockPath(ctx); err != nil {
		t.Fatalf("block kernel path: %v", err)
	}
	observed, err = backend.ObservePath(ctx)
	if err != nil || observed != (PathState{}) {
		t.Fatalf("observe kernel blocked path = %+v, %v", observed, err)
	}
}

type fakeRoutingSynchronizer struct {
	calls int
	err   error
}

func (synchronizer *fakeRoutingSynchronizer) SyncRouting(context.Context) error {
	synchronizer.calls++
	return synchronizer.err
}

func parseNamedUint(payload, name string) uint32 {
	index := strings.Index(payload, name+" { ")
	if index < 0 {
		return 0
	}
	var value uint32
	_, _ = fmt.Sscanf(payload[index:], name+" { %d", &value)
	return value
}

func lastFirewallPayload(t *testing.T, requests []platformexec.Request) string {
	t.Helper()
	for index := len(requests) - 1; index >= 0; index-- {
		if strings.Join(requests[index].Arguments, " ") == "--file -" {
			return string(requests[index].Stdin)
		}
	}
	t.Fatal("firewall apply payload is missing")
	return ""
}

func observedJSON(pathState PathState) string {
	tunElements, directInterfaceElements, directContextElements := "", "", ""
	directMapElements, generationElements, routeGenerationElements := "", "", ""
	if pathState.Active {
		generationElements = fmt.Sprintf(`,"elem":[%d]`, pathState.Generation)
		switch pathState.Mode {
		case PathModeTUN:
			tunElements = `,"elem":["gateway-vpn-tun"]`
		case PathModeDirect:
			directInterfaceElements = fmt.Sprintf(`,"elem":[%q]`, pathState.DirectInterface)
			directContextElements = fmt.Sprintf(`,"elem":[{"concat":[%q,%d]}]`, pathState.DirectInterface, pathState.DirectMark)
			directMapElements = fmt.Sprintf(`,"elem":[{"elem":{"val":"enp2s0","data":%d}},{"elem":{"val":"wg-ingress","data":%d}}]`, pathState.DirectMark, pathState.DirectMark)
			routeGenerationElements = fmt.Sprintf(`,"elem":[%d]`, pathState.RouteGeneration)
		}
	}
	return fmt.Sprintf(`{"nftables":[
{"set":{"family":"inet","table":"gateway_vpn","name":"active_tun_interfaces"%s}},
{"set":{"family":"inet","table":"gateway_vpn","name":"active_direct_interfaces"%s}},
{"set":{"family":"inet","table":"gateway_vpn","name":"active_direct_context"%s}},
{"map":{"family":"inet","table":"gateway_vpn","name":"active_direct_marks"%s}},
{"set":{"family":"inet","table":"gateway_vpn","name":"active_path_generation"%s}},
{"set":{"family":"inet","table":"gateway_vpn","name":"active_route_generation"%s}}
]}`, tunElements, directInterfaceElements, directContextElements, directMapElements, generationElements, routeGenerationElements)
}

func healthyPathFirewallTable() string {
	return `table inet gateway_vpn {
set firewall_schema_generation { type mark; elements = { 4 }; }
set user_ingress_interfaces { type ifname; elements = { "enp2s0", "wg-ingress" }; }
set wireguard_ingress_listeners { type ifname . inet_service; }
set wireguard_ingress_allowed_v4 { type ipv4_addr; flags interval; }
set active_tun_interfaces { type ifname; }
set active_direct_interfaces { type ifname; }
set active_direct_context { type ifname . mark; }
map active_direct_marks { type ifname : mark; }
set active_path_generation { type mark; }
set active_route_generation { type mark; }
counter user_upload
counter user_download
counter service_upload
counter service_download
chain prerouting { type filter hook prerouting priority mangle; meta mark set iifname map @active_direct_marks }
chain input { iifname . udp dport @wireguard_ingress_listeners; }
chain forward { type filter hook forward priority filter; policy drop;
ip saddr @wireguard_ingress_allowed_v4
oifname @active_tun_interfaces
oifname . meta mark @active_direct_context
counter comment "gateway-vpn PATH_BLOCKED" }
}`
}

func testFirewallBackendWithPolicy(t *testing.T, executor *firewallExecutor, kind string) (FirewallBackend, func()) {
	t.Helper()
	_ = kind
	database, _, _, closeDatabase := serviceRepositories(t)
	if err := accesspolicy.NewDirectPathRepository(database).Reconcile(context.Background()); err != nil {
		closeDatabase()
		t.Fatal(err)
	}
	if _, err := database.Exec(`
UPDATE runtime_state
SET gateway_state='VERIFYING', path_state='PATH_VERIFYING',
    active_uplink_id='modem-a', active_modem_id='modem-a',
    active_path_id=NULL, active_direct_path_id='direct:path:modem-a',
    active_subscription_id=NULL, active_node_id=NULL,
    active_method_id='access:direct', active_method_kind='DIRECT', active_quality_class='FULL'
WHERE singleton_id=1`); err != nil {
		closeDatabase()
		t.Fatal(err)
	}
	return FirewallBackend{Database: database, Executor: executor, NFT: "/usr/sbin/nft", TUNName: "gateway-vpn-tun", LANName: "enp2s0"}, closeDatabase
}
