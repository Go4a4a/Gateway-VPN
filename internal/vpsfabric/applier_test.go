package vpsfabric

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

type fabricExecutor struct {
	wgConfig    string
	privateKey  string
	publicKey   string
	listenPort  string
	addresses   []string
	peers       []string
	routes      map[string]bool
	firewall    string
	requests    []platformexec.Request
	failLoadOne bool
}

func (executor *fabricExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	args := strings.Join(request.Arguments, " ")
	command := strings.TrimSuffix(filepath.Base(request.Executable), ".exe")
	switch {
	case command == "systemctl" && args == "restart wg-quick@wg-mgmt.service":
		content, err := os.ReadFile(executor.wgConfig)
		if err != nil {
			return platformexec.Result{}, err
		}
		executor.peers = nil
		for _, line := range strings.Split(string(content), "\n") {
			if strings.HasPrefix(line, "Address = ") {
				executor.addresses = strings.Split(strings.TrimPrefix(line, "Address = "), ", ")
			}
			if strings.HasPrefix(line, "ListenPort = ") {
				executor.listenPort = strings.TrimPrefix(line, "ListenPort = ")
			}
			if strings.HasPrefix(line, "PrivateKey = ") {
				executor.privateKey = strings.TrimPrefix(line, "PrivateKey = ")
				executor.publicKey, _ = wgingress.PublicKey(executor.privateKey)
			}
			if strings.HasPrefix(line, "PublicKey = ") {
				executor.peers = append(executor.peers, strings.TrimPrefix(line, "PublicKey = "))
			}
		}
		return platformexec.Result{}, nil
	case command == "nft" && args == "--check --file -":
		if !strings.Contains(string(request.Stdin), "table inet gateway_vpn_vps") {
			return platformexec.Result{}, errors.New("invalid nft")
		}
		return platformexec.Result{}, nil
	case command == "nft" && args == "list table inet gateway_vpn_vps":
		if executor.firewall == "" {
			return platformexec.Result{}, errors.New("missing")
		}
		return platformexec.Result{Stdout: executor.firewall}, nil
	case command == "nft" && args == "--file -":
		if executor.failLoadOne {
			executor.failLoadOne = false
			return platformexec.Result{}, errors.New("injected nft failure")
		}
		content := string(request.Stdin)
		if index := strings.Index(content, "table inet gateway_vpn_vps"); index >= 0 {
			executor.firewall = content[index:]
		}
		return platformexec.Result{}, nil
	case command == "ip" && strings.HasPrefix(args, "-4 route replace "):
		executor.routes[request.Arguments[3]] = true
		return platformexec.Result{}, nil
	case command == "ip" && strings.HasPrefix(args, "-4 route del "):
		delete(executor.routes, request.Arguments[3])
		return platformexec.Result{}, nil
	case command == "ip" && args == "-json -4 route show dev wg-mgmt protocol 186":
		rows := make([]map[string]any, 0, len(executor.routes))
		for route := range executor.routes {
			rows = append(rows, map[string]any{"dst": route, "dev": "wg-mgmt", "protocol": 186})
		}
		content, _ := json.Marshal(rows)
		return platformexec.Result{Stdout: string(content)}, nil
	case command == "ip" && args == "-json -4 address show dev wg-mgmt":
		items := make([]map[string]any, 0, len(executor.addresses))
		for _, raw := range executor.addresses {
			prefix := netip.MustParsePrefix(raw)
			items = append(items, map[string]any{"family": "inet", "local": prefix.Addr().String(), "prefixlen": prefix.Bits()})
		}
		content, _ := json.Marshal([]map[string]any{{"addr_info": items}})
		return platformexec.Result{Stdout: string(content)}, nil
	case command == "wg" && args == "show wg-mgmt listen-port":
		return platformexec.Result{Stdout: executor.listenPort + "\n"}, nil
	case command == "wg" && args == "show wg-mgmt public-key":
		return platformexec.Result{Stdout: executor.publicKey + "\n"}, nil
	case command == "wg" && args == "show wg-mgmt peers":
		return platformexec.Result{Stdout: strings.Join(executor.peers, "\n") + "\n"}, nil
	default:
		return platformexec.Result{}, errors.New("unexpected command: " + request.Executable + " " + args)
	}
}

func TestApplierCommitsOwnedProjectionAndPreservesForeignScope(t *testing.T) {
	fixture := newFabricFixture(t)
	if err := fixture.applier.Apply(context.Background()); err != nil { // seed exact legacy receipt
		t.Fatal(err)
	}
	newAdmin, _ := wgingress.GenerateKeyPair()
	if _, err := fixture.repository.CreateAdmin(context.Background(), vpsagent.AdminCreateInput{Name: "Second", PublicKey: newAdmin.Public, AssignedAddress: "10.81.0.11", KeyMode: "EXTERNAL"}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.applier.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	desired, applied, err := fixture.repository.FabricGenerations(context.Background())
	if err != nil || desired != applied || desired != 2 {
		t.Fatalf("fabric generations = %d/%d, %v", applied, desired, err)
	}
	if !fixture.executor.routes["10.81.0.11/32"] || !strings.Contains(fixture.executor.firewall, "gateway-vpn fabric generation 2") {
		t.Fatalf("runtime not converged: routes=%v firewall=%s", fixture.executor.routes, fixture.executor.firewall)
	}
	for _, request := range fixture.executor.requests {
		command := strings.ToLower(request.Executable + " " + strings.Join(request.Arguments, " ") + " " + string(request.Stdin))
		for _, forbidden := range []string{"flush ruleset", "amnezia", "docker", "ufw", "firewalld", " wg0", " tun0"} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("foreign mutation token %q in %s", forbidden, command)
			}
		}
	}
}

func TestApplierRollsBackFilesRuntimeAndGenerationOnFailure(t *testing.T) {
	fixture := newFabricFixture(t)
	if err := fixture.applier.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldWG, _ := os.ReadFile(fixture.applier.Paths.WireGuardConfig)
	oldFirewall, _ := os.ReadFile(fixture.applier.Paths.FirewallConfig)
	newAdmin, _ := wgingress.GenerateKeyPair()
	if _, err := fixture.repository.CreateAdmin(context.Background(), vpsagent.AdminCreateInput{Name: "Failure", PublicKey: newAdmin.Public, AssignedAddress: "10.81.0.12", KeyMode: "EXTERNAL"}); err != nil {
		t.Fatal(err)
	}
	fixture.executor.failLoadOne = true
	if err := fixture.applier.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "safely rolled back") {
		t.Fatalf("apply failure = %v", err)
	}
	currentWG, _ := os.ReadFile(fixture.applier.Paths.WireGuardConfig)
	currentFirewall, _ := os.ReadFile(fixture.applier.Paths.FirewallConfig)
	if string(currentWG) != string(oldWG) || string(currentFirewall) != string(oldFirewall) {
		t.Fatal("persistent files were not rolled back")
	}
	desired, applied, err := fixture.repository.FabricGenerations(context.Background())
	if err != nil || desired != 2 || applied != 1 {
		t.Fatalf("rollback generations = %d/%d, %v", applied, desired, err)
	}
	if fixture.executor.routes["10.81.0.12/32"] || exists(fixture.applier.journalPath()) {
		t.Fatalf("failed projection survived: routes=%v journal=%t", fixture.executor.routes, exists(fixture.applier.journalPath()))
	}
}

func TestPostRestoreAuthorizationIsSingleUseAndReconcilesChangedDatabase(t *testing.T) {
	fixture := newFabricFixture(t)
	ctx := context.Background()
	if err := fixture.applier.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	restoreID := "vps-restore-0123456789abcdef0123456789abcdef"
	if err := fixture.applier.PrepareRestore(ctx, restoreID); err != nil {
		t.Fatal(err)
	}
	newAdmin, _ := wgingress.GenerateKeyPair()
	if _, err := fixture.repository.CreateAdmin(ctx, vpsagent.AdminCreateInput{Name: "Restored", PublicKey: newAdmin.Public, AssignedAddress: "10.81.0.20", KeyMode: "EXTERNAL"}); err != nil {
		t.Fatal(err)
	}
	reset, err := fixture.applier.ResetAfterRestore(ctx)
	if err != nil || !reset {
		t.Fatalf("restore reset = %t, %v", reset, err)
	}
	if err := fixture.applier.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	pending, err := fixture.applier.RestoreReconciliationPending()
	if err != nil || pending || !fixture.executor.routes["10.81.0.20/32"] {
		t.Fatalf("post-restore state pending=%t routes=%v err=%v", pending, fixture.executor.routes, err)
	}
}

func TestPostRestoreApplyFailureRestoresExactRuntimeAndKeepsAuthorization(t *testing.T) {
	fixture := newFabricFixture(t)
	ctx := context.Background()
	if err := fixture.applier.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	beforeRoutes := maps.Clone(fixture.executor.routes)
	beforeWG, _ := os.ReadFile(fixture.applier.Paths.WireGuardConfig)
	beforeFirewall, _ := os.ReadFile(fixture.applier.Paths.FirewallConfig)
	if err := fixture.applier.PrepareRestore(ctx, "vps-restore-fedcba9876543210fedcba9876543210"); err != nil {
		t.Fatal(err)
	}
	newAdmin, _ := wgingress.GenerateKeyPair()
	if _, err := fixture.repository.CreateAdmin(ctx, vpsagent.AdminCreateInput{Name: "Failed restore", PublicKey: newAdmin.Public, AssignedAddress: "10.81.0.21", KeyMode: "EXTERNAL"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.applier.ResetAfterRestore(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.executor.failLoadOne = true
	if err := fixture.applier.Apply(ctx); err == nil || !strings.Contains(err.Error(), "safely rolled back") {
		t.Fatalf("post-restore apply failure = %v", err)
	}
	afterWG, _ := os.ReadFile(fixture.applier.Paths.WireGuardConfig)
	afterFirewall, _ := os.ReadFile(fixture.applier.Paths.FirewallConfig)
	pending, pendingErr := fixture.applier.RestoreReconciliationPending()
	desired, applied, generationErr := fixture.repository.FabricGenerations(ctx)
	if string(afterWG) != string(beforeWG) || string(afterFirewall) != string(beforeFirewall) || !maps.Equal(beforeRoutes, fixture.executor.routes) {
		t.Fatalf("exact runtime was not restored: routes=%v", fixture.executor.routes)
	}
	if pendingErr != nil || generationErr != nil || !pending || desired != 2 || applied != 0 {
		t.Fatalf("retry state pending=%t generations=%d/%d errors=%v/%v", pending, applied, desired, pendingErr, generationErr)
	}
}

func TestFabricWatchdogDistinguishesHealthyDriftAndReceiptMismatch(t *testing.T) {
	fixture := newFabricFixture(t)
	ctx := context.Background()
	if err := fixture.applier.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	needed, reason, err := fixture.applier.NeedsApply(ctx)
	if err != nil || needed || reason != "HEALTHY" {
		t.Fatalf("healthy watchdog = %t %s %v", needed, reason, err)
	}
	fixture.executor.firewall = strings.Replace(fixture.executor.firewall, "gateway-vpn deny other fabric egress forwarding", "removed-comment", 1)
	needed, reason, err = fixture.applier.NeedsApply(ctx)
	if err != nil || !needed || reason != "RUNTIME_PROJECTION_DRIFT" {
		t.Fatalf("drift watchdog = %t %s %v", needed, reason, err)
	}
	if _, err := fixture.repository.Database.ExecContext(ctx, `UPDATE vps_settings SET value_json='{"desired_generation":1,"applied_generation":0,"state":"PENDING"}' WHERE key='fabric'`); err != nil {
		t.Fatal(err)
	}
	needed, reason, err = fixture.applier.NeedsApply(ctx)
	if err == nil || needed || reason != "RECEIPT_GENERATION_MISMATCH" {
		t.Fatalf("receipt mismatch watchdog = %t %s %v", needed, reason, err)
	}
}

func TestRelayWatchdogTelemetryRequiresEveryOwnedRuleAndAggregatesCounters(t *testing.T) {
	output := strings.Join([]string{
		`counter packets 1 bytes 100 drop comment "gateway-vpn administrator relay rate limit relay:a"`,
		`counter packets 2 bytes 200 dnat comment "gateway-vpn administrator relay dnat relay:a"`,
		`counter packets 3 bytes 300 accept comment "gateway-vpn administrator relay ingress relay:a"`,
		`counter packets 4 bytes 400 accept comment "gateway-vpn administrator relay return relay:a"`,
		`counter packets 5 bytes 500 snat comment "gateway-vpn administrator relay snat relay:a"`,
	}, "\n")
	rules, packets, bytes, err := parseRelayCounters(output, []string{"relay:a"})
	if err != nil || rules != 5 || packets != 15 || bytes != 1500 {
		t.Fatalf("relay telemetry = rules:%d packets:%d bytes:%d error:%v", rules, packets, bytes, err)
	}
	if _, _, _, err := parseRelayCounters(strings.Replace(output, "\n"+strings.Split(output, "\n")[4], "", 1), []string{"relay:a"}); err == nil {
		t.Fatal("incomplete relay rule inventory was accepted")
	}
	if _, _, _, err := parseRelayCounters(output, []string{"relay:other"}); err == nil {
		t.Fatal("foreign relay counters were accepted")
	}
}

func TestOwnedRouteProtocolAcceptsOnlyNumericOrCanonicalIPRouteRepresentation(t *testing.T) {
	for _, value := range []any{nil, float64(vpsagent.VPSOwnedRouteProtocol), "186", "bgp"} {
		if !ownedProtocol(value) {
			t.Fatalf("owned route protocol representation %#v rejected", value)
		}
	}
	for _, value := range []any{float64(185), "185", "static", "boot", map[string]any{}} {
		if ownedProtocol(value) {
			t.Fatalf("foreign route protocol representation %#v accepted", value)
		}
	}
}

type fabricFixture struct {
	repository vpsagent.HubRepository
	applier    *Applier
	executor   *fabricExecutor
}

func newFabricFixture(t *testing.T) fabricFixture {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := vpsagent.Open(context.Background(), filepath.Join(state, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, _ := wgingress.GenerateKeyPair()
	gateway, _ := wgingress.GenerateKeyPair()
	admin, _ := wgingress.GenerateKeyPair()
	if _, err := vpsagent.InitializeIdentity(context.Background(), database, vpsagent.IdentityInput{
		VPSID: "vps:test", DisplayName: "Test", IdentityFingerprint: strings.Repeat("a", 64), PublicKey: server.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key", UpdateIdentityRef: "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	repository := vpsagent.HubRepository{Database: database, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }}
	if _, err := repository.AdoptLegacyInstallerPeers(context.Background(), vpsagent.LegacyAdoptionInput{GatewayPublicKey: gateway.Public, AdminPublicKey: admin.Public, Endpoint: "vps.example:51821"}); err != nil {
		t.Fatal(err)
	}
	plan, err := repository.RenderHostPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wg, _ := RenderWireGuard(plan, server.Private)
	firewall, _ := RenderFirewall(plan)
	wgPath := filepath.Join(root, "wg-mgmt.conf")
	firewallPath := filepath.Join(root, "firewall.nft")
	keyDir := filepath.Join(root, "secrets", "wireguard")
	transaction := filepath.Join(root, "fabric")
	for _, directory := range []string{keyDir, transaction} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(keyDir, "server.key")
	for path, item := range map[string][]byte{wgPath: wg, firewallPath: firewall, keyPath: []byte(server.Private + "\n")} {
		if err := os.WriteFile(path, item, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	executable := func(name string) string {
		if runtime.GOOS == "windows" {
			return filepath.Join(`C:\fake`, name+".exe")
		}
		return "/fake/" + name
	}
	routes, _ := routeDestinations(plan)
	executor := &fabricExecutor{wgConfig: wgPath, publicKey: server.Public, privateKey: server.Private, listenPort: "51821", addresses: append([]string(nil), plan.InterfaceAddresses...), routes: map[string]bool{}, firewall: string(firewall)}
	for _, route := range routes {
		executor.routes[route] = true
	}
	for _, peer := range plan.Peers {
		executor.peers = append(executor.peers, peer.PublicKey)
	}
	sort.Strings(executor.peers)
	applier := &Applier{Repository: repository, Executor: executor, Paths: Paths{
		TransactionRoot: transaction, WireGuardConfig: wgPath, FirewallConfig: firewallPath, PrivateKey: keyPath,
		IP: executable("ip"), NFT: executable("nft"), WG: executable("wg"), Systemctl: executable("systemctl"),
	}}
	return fabricFixture{repository: repository, applier: applier, executor: executor}
}
