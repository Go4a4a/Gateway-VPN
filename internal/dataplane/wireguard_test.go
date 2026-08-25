package dataplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/state"
	wireguardpkg "gateway-vpn/internal/wireguard"
)

type wireGuardEndpointRecorder struct {
	modemIDs         []string
	addresses        []string
	resolvedHosts    []string
	resolveAddresses []string
	resolveErr       error
}

func (recorder *wireGuardEndpointRecorder) ResolveWireGuardEndpoint(_ context.Context, current modem.Modem, hostname string) ([]string, error) {
	recorder.resolvedHosts = append(recorder.resolvedHosts, current.ID+":"+hostname)
	if recorder.resolveErr != nil {
		return nil, recorder.resolveErr
	}
	return append([]string(nil), recorder.resolveAddresses...), nil
}

func (recorder *wireGuardEndpointRecorder) AuthorizeWireGuardEndpoint(_ context.Context, current modem.Modem, address string) error {
	recorder.modemIDs = append(recorder.modemIDs, current.ID)
	recorder.addresses = append(recorder.addresses, address)
	return nil
}

type wireGuardExecutor struct {
	requests  []platformexec.Request
	peerKey   string
	handshake time.Time
}

func (executor *wireGuardExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	if request.Executable == "/usr/bin/wg" && strings.Join(request.Arguments, " ") == "show wg-mgmt latest-handshakes" {
		if executor.handshake.IsZero() {
			return platformexec.Result{Stdout: executor.peerKey + "\t0\n"}, nil
		}
		return platformexec.Result{Stdout: fmt.Sprintf("%s\t%d\n", executor.peerKey, executor.handshake.Unix())}, nil
	}
	return platformexec.Result{}, nil
}

type wireGuardFixture struct {
	database  *sql.DB
	modems    *modem.Repository
	states    *state.Repository
	runtime   wireguardpkg.RuntimeStore
	backend   *WireGuardBackend
	executor  *wireGuardExecutor
	endpoints *wireGuardEndpointRecorder
	now       time.Time
}

func TestWireGuardBackendProbesAndCommitsOnlyNewHandshake(t *testing.T) {
	fixture := newWireGuardFixture(t, true)
	defer fixture.database.Close()
	ctx := context.Background()

	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatalf("first SyncWireGuard() error = %v", err)
	}
	runtimeState, err := fixture.runtime.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeState.CurrentModemID != "" || runtimeState.CandidateModemID != "modem-a" || runtimeState.RouteModemID != "modem-a" {
		t.Fatalf("initial runtime state = %+v", runtimeState)
	}
	if strings.Join(fixture.endpoints.modemIDs, ",") != "modem-a" || strings.Join(fixture.endpoints.addresses, ",") != "203.0.113.10" {
		t.Fatalf("endpoint authorization = %v / %v", fixture.endpoints.modemIDs, fixture.endpoints.addresses)
	}
	assertWireGuardRequest(t, fixture.executor.requests, "/usr/sbin/ip", "-4 route replace 203.0.113.10/32 via 192.168.8.1 dev enx0001 table 1101 protocol 186")
	assertWireGuardRequest(t, fixture.executor.requests, "/usr/bin/wg", "set wg-mgmt fwmark 0x1101")

	fixture.executor.handshake = fixture.now.Add(time.Second)
	fixture.now = fixture.now.Add(2 * time.Second)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatalf("handshake SyncWireGuard() error = %v", err)
	}
	runtimeState, _ = fixture.runtime.Get(ctx)
	snapshot, _ := fixture.states.Get(ctx)
	modemA, _ := fixture.modems.Get(ctx, "modem-a")
	if runtimeState.CurrentModemID != "modem-a" || runtimeState.CandidateModemID != "" || snapshot.ManagementModemID != "modem-a" || modemA.ManagementReachabilityState != "REACHABLE" {
		t.Fatalf("confirmed runtime/snapshot/modem = %+v / %+v / %+v", runtimeState, snapshot, modemA)
	}
}

func TestWireGuardBackendTimesOutAndTriesNextModem(t *testing.T) {
	fixture := newWireGuardFixture(t, true)
	defer fixture.database.Close()
	ctx := context.Background()
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(20 * time.Second)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatalf("timeout SyncWireGuard() error = %v", err)
	}
	runtimeState, _ := fixture.runtime.Get(ctx)
	modemA, _ := fixture.modems.Get(ctx, "modem-a")
	modemB, _ := fixture.modems.Get(ctx, "modem-b")
	if runtimeState.CandidateModemID != "modem-b" || runtimeState.RouteModemID != "modem-b" || modemA.ManagementReachabilityState != "BLOCKED" || modemB.ManagementReachabilityState != "PROBING" {
		t.Fatalf("failover runtime/modems = %+v / %s / %s", runtimeState, modemA.ManagementReachabilityState, modemB.ManagementReachabilityState)
	}
	if strings.Join(fixture.endpoints.modemIDs, ",") != "modem-a,modem-b" {
		t.Fatalf("candidate order = %v", fixture.endpoints.modemIDs)
	}
	assertWireGuardRequest(t, fixture.executor.requests, "/usr/sbin/ip", "-4 route del 203.0.113.10/32 via 192.168.8.1 dev enx0001 table 1101 protocol 186")
}

func TestWireGuardBackendDoesNotWaitAfterCandidateUnplug(t *testing.T) {
	fixture := newWireGuardFixture(t, true)
	defer fixture.database.Close()
	ctx := context.Background()
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fixture.modems.MarkOffline(ctx, "modem-a"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatalf("unplug SyncWireGuard() error = %v", err)
	}
	runtimeState, _ := fixture.runtime.Get(ctx)
	if runtimeState.CandidateModemID != "modem-b" || runtimeState.RouteModemID != "modem-b" {
		t.Fatalf("candidate unplug did not immediately try backup: %+v", runtimeState)
	}
}

func TestWireGuardBackendHonorsFailbackHysteresisAndActiveUnplug(t *testing.T) {
	fixture := newWireGuardFixture(t, true)
	defer fixture.database.Close()
	ctx := context.Background()
	for _, id := range []string{"modem-a", "modem-b"} {
		if err := fixture.modems.SetManagementReachability(ctx, id, "REACHABLE"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := fixture.states.SetManagementModem(ctx, "modem-b", "TEST_CURRENT"); err != nil {
		t.Fatal(err)
	}
	modemB, _ := fixture.modems.Get(ctx, "modem-b")
	if err := fixture.runtime.Put(ctx, wireguardpkg.RuntimeState{
		CurrentModemID: "modem-b", RouteModemID: "modem-b", LastSwitchAt: fixture.now.Format(time.RFC3339Nano),
		ConfigSHA256: currentWireGuardConfigDigest(t, fixture.backend.ConfigPath),
		EndpointIP:   "203.0.113.10", RouteInterface: modemB.InterfaceName, RouteGateway: modemB.Gateway,
		RouteTableID: modemB.RoutingTableID, RouteFwmark: modemB.Fwmark,
	}, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Join(fixture.endpoints.modemIDs, ",") != "modem-b" {
		t.Fatalf("early failback ignored cooldown: %v", fixture.endpoints.modemIDs)
	}

	fixture.now = fixture.now.Add(16 * time.Minute)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	runtimeState, _ := fixture.runtime.Get(ctx)
	if runtimeState.CurrentModemID != "modem-b" || runtimeState.CandidateModemID != "modem-a" {
		t.Fatalf("failback must remain probing before commit: %+v", runtimeState)
	}

	fixture.executor.handshake = fixture.now.Add(time.Second)
	fixture.now = fixture.now.Add(2 * time.Second)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fixture.modems.MarkOffline(ctx, "modem-a"); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	runtimeState, _ = fixture.runtime.Get(ctx)
	if runtimeState.CandidateModemID != "modem-b" || runtimeState.RouteModemID != "modem-b" {
		t.Fatalf("active unplug did not start backup probe: %+v", runtimeState)
	}
}

func TestWireGuardBackendFailedFailbackRestoresPreviousRouteForReprobe(t *testing.T) {
	fixture := newWireGuardFixture(t, true)
	defer fixture.database.Close()
	ctx := context.Background()
	for _, id := range []string{"modem-a", "modem-b"} {
		if err := fixture.modems.SetManagementReachability(ctx, id, "REACHABLE"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := fixture.states.SetManagementModem(ctx, "modem-b", "TEST_CURRENT"); err != nil {
		t.Fatal(err)
	}
	modemB, _ := fixture.modems.Get(ctx, "modem-b")
	if err := fixture.runtime.Put(ctx, wireguardpkg.RuntimeState{
		CurrentModemID: "modem-b", RouteModemID: "modem-b", LastSwitchAt: fixture.now.Add(-time.Hour).Format(time.RFC3339Nano),
		ConfigSHA256: currentWireGuardConfigDigest(t, fixture.backend.ConfigPath),
		EndpointIP:   "203.0.113.10", RouteInterface: modemB.InterfaceName, RouteGateway: modemB.Gateway,
		RouteTableID: modemB.RoutingTableID, RouteFwmark: modemB.Fwmark,
	}, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(20 * time.Second)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatalf("failed failback recovery error = %v", err)
	}
	runtimeState, _ := fixture.runtime.Get(ctx)
	if runtimeState.CurrentModemID != "modem-b" || runtimeState.CandidateModemID != "modem-b" || runtimeState.RouteModemID != "modem-b" {
		t.Fatalf("previous route was not restored for handshake reprobe: %+v", runtimeState)
	}
	if strings.Join(fixture.endpoints.modemIDs, ",") != "modem-a,modem-b" {
		t.Fatalf("failed failback authorization order = %v", fixture.endpoints.modemIDs)
	}
}

func TestWireGuardBackendMissingConfigIsSafeNoop(t *testing.T) {
	fixture := newWireGuardFixture(t, false)
	defer fixture.database.Close()
	if err := fixture.backend.SyncWireGuard(context.Background()); err != nil {
		t.Fatalf("SyncWireGuard(missing config) error = %v", err)
	}
	if len(fixture.executor.requests) != 0 || len(fixture.endpoints.modemIDs) != 0 {
		t.Fatalf("missing config produced side effects: %d / %v", len(fixture.executor.requests), fixture.endpoints.modemIDs)
	}
}

func TestWireGuardBackendResolvesHostnameThroughCandidateModem(t *testing.T) {
	fixture := newWireGuardFixture(t, true)
	defer fixture.database.Close()
	configuration, err := wireguardpkg.LoadConfig(fixture.backend.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	configuration.Endpoint = "vpn.example.com:51821"
	if err := wireguardpkg.SaveConfig(fixture.backend.ConfigPath, configuration); err != nil {
		t.Fatal(err)
	}
	fixture.endpoints.resolveAddresses = []string{"203.0.113.20"}
	if err := fixture.backend.SyncWireGuard(context.Background()); err != nil {
		t.Fatalf("hostname SyncWireGuard() error = %v", err)
	}
	if strings.Join(fixture.endpoints.resolvedHosts, ",") != "modem-a:vpn.example.com" || strings.Join(fixture.endpoints.addresses, ",") != "203.0.113.20" {
		t.Fatalf("hostname resolution/authorization = %v / %v", fixture.endpoints.resolvedHosts, fixture.endpoints.addresses)
	}
	assertWireGuardRequest(t, fixture.executor.requests, "/usr/sbin/ip", "-4 route replace 203.0.113.20/32 via 192.168.8.1 dev enx0001 table 1101 protocol 186")
}

func TestWireGuardBackendAppliesChangedConfigAndRemovesOldEndpointRoute(t *testing.T) {
	fixture := newWireGuardFixture(t, true)
	defer fixture.database.Close()
	ctx := context.Background()
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.executor.handshake = fixture.now.Add(time.Second)
	fixture.now = fixture.now.Add(2 * time.Second)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	configuration, _ := wireguardpkg.LoadConfig(fixture.backend.ConfigPath)
	configuration.Endpoint = "203.0.113.20:51821"
	if err := wireguardpkg.SaveConfig(fixture.backend.ConfigPath, configuration); err != nil {
		t.Fatal(err)
	}
	fixture.executor.requests = nil
	fixture.endpoints.modemIDs = nil
	fixture.endpoints.addresses = nil
	fixture.executor.handshake = time.Time{}
	fixture.now = fixture.now.Add(time.Second)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatalf("config-change SyncWireGuard() error = %v", err)
	}
	runtimeState, _ := fixture.runtime.Get(ctx)
	if runtimeState.CurrentModemID != "modem-a" || runtimeState.CandidateModemID != "modem-a" || runtimeState.EndpointIP != "203.0.113.20" {
		t.Fatalf("changed config was not staged for handshake: %+v", runtimeState)
	}
	assertWireGuardRequest(t, fixture.executor.requests, "/usr/sbin/ip", "-4 route del 203.0.113.10/32 via 192.168.8.1 dev enx0001 table 1101 protocol 186")
}

func TestWireGuardBackendKeepsConfirmedHostnameIPDuringDNSFailure(t *testing.T) {
	fixture := newWireGuardFixture(t, true)
	defer fixture.database.Close()
	ctx := context.Background()
	configuration, _ := wireguardpkg.LoadConfig(fixture.backend.ConfigPath)
	configuration.Endpoint = "vpn.example.com:51821"
	if err := wireguardpkg.SaveConfig(fixture.backend.ConfigPath, configuration); err != nil {
		t.Fatal(err)
	}
	fixture.endpoints.resolveAddresses = []string{"203.0.113.20"}
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.executor.handshake = fixture.now.Add(time.Second)
	fixture.now = fixture.now.Add(2 * time.Second)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.endpoints.resolveErr = errors.New("temporary DNS failure")
	fixture.endpoints.modemIDs = nil
	fixture.endpoints.addresses = nil
	fixture.now = fixture.now.Add(6 * time.Minute)
	if err := fixture.backend.SyncWireGuard(ctx); err != nil {
		t.Fatalf("cached DNS SyncWireGuard() error = %v", err)
	}
	runtimeState, _ := fixture.runtime.Get(ctx)
	current, _ := fixture.modems.Get(ctx, "modem-a")
	expiresAt, _ := time.Parse(time.RFC3339Nano, runtimeState.EndpointExpiresAt)
	if runtimeState.CurrentModemID != "modem-a" || runtimeState.CandidateModemID != "" || runtimeState.EndpointIP != "203.0.113.20" || current.ManagementReachabilityState != "REACHABLE" || expiresAt.Sub(fixture.now) != time.Minute {
		t.Fatalf("confirmed endpoint was not retained: %+v / %+v", runtimeState, current)
	}
	if strings.Join(fixture.endpoints.addresses, ",") != "203.0.113.20" {
		t.Fatalf("cached endpoint was not reauthorized: %v", fixture.endpoints.addresses)
	}
}

func TestWireGuardBackendSerializesConcurrentSync(t *testing.T) {
	fixture := newWireGuardFixture(t, true)
	defer fixture.database.Close()
	var group sync.WaitGroup
	errorsChannel := make(chan error, 8)
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsChannel <- fixture.backend.SyncWireGuard(context.Background())
		}()
	}
	group.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent SyncWireGuard() error = %v", err)
		}
	}
	if len(fixture.endpoints.modemIDs) != 1 || fixture.endpoints.modemIDs[0] != "modem-a" {
		t.Fatalf("concurrent sync started duplicate probes: %v", fixture.endpoints.modemIDs)
	}
}

func newWireGuardFixture(t *testing.T, writeConfig bool) *wireGuardFixture {
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
	for index, input := range []struct {
		id, name, identity, iface, cidr, gateway string
	}{
		{"modem-a", "Operator A", strings.Repeat("a", 64), "enx0001", "192.168.8.0/24", "192.168.8.1"},
		{"modem-b", "Operator B", strings.Repeat("b", 64), "enx0002", "192.168.9.0/24", "192.168.9.1"},
	} {
		if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: input.id, Name: input.name, IdentityKind: "hilink_serial_hash", IdentityHash: input.identity}); err != nil {
			database.Close()
			t.Fatal(err)
		}
		if _, err := modems.ApplyLease(ctx, input.id, modem.LeaseInput{InterfaceName: input.iface, ManagementCIDR: input.cidr, Gateway: input.gateway, DNS: []string{"1.1.1.1"}, MTU: 1500 + int64(index), State: modem.StateReady}); err != nil {
			database.Close()
			t.Fatal(err)
		}
	}
	privateKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	peerKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	configPath := filepath.Join(t.TempDir(), "wireguard.yaml")
	if writeConfig {
		content := fmt.Sprintf("interface_name: wg-mgmt\naddress: 10.80.0.2/32\nprivate_key: %s\npeer_public_key: %s\nendpoint: 203.0.113.10:51821\nallowed_ips: [10.80.0.0/24]\npersistent_keepalive: 25\n", privateKey, peerKey)
		if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
			database.Close()
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	executor := &wireGuardExecutor{peerKey: peerKey}
	endpoints := &wireGuardEndpointRecorder{}
	fixture := &wireGuardFixture{database: database, modems: modems, states: state.NewRepository(database), runtime: wireguardpkg.RuntimeStore{Database: database}, executor: executor, endpoints: endpoints, now: now}
	fixture.backend = &WireGuardBackend{
		Modems: modems, States: fixture.states, Runtime: fixture.runtime, Endpoints: endpoints, Executor: executor,
		IP: "/usr/sbin/ip", WG: "/usr/bin/wg", ConfigPath: configPath, ProbeTimeout: 15 * time.Second,
		Policy: wireguardpkg.SelectionPolicy{ReconnectStable: 3 * time.Minute, FailbackCooldown: 15 * time.Minute},
		Now:    func() time.Time { return fixture.now },
	}
	return fixture
}

func assertWireGuardRequest(t *testing.T, requests []platformexec.Request, executable, arguments string) {
	t.Helper()
	for _, request := range requests {
		if request.Executable == executable && strings.Join(request.Arguments, " ") == arguments {
			return
		}
	}
	t.Fatalf("request %s %s not found in %+v", executable, arguments, requests)
}

func currentWireGuardConfigDigest(t *testing.T, filename string) string {
	t.Helper()
	configuration, err := wireguardpkg.LoadConfig(filename)
	if err != nil {
		t.Fatal(err)
	}
	content, err := wireguardpkg.RenderSyncConf(configuration)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
