//go:build linux

package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/dataplane"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/uplink"
)

const (
	startupIntegrationModemID = "modem-startup"
	startupIntegrationBootID  = "boot-ungated"
)

// TestStartupPolicyAgainstKernelFirewall is intentionally split into process
// phases by test/netns/startup_policy.sh. The persistent SQLite file and the
// namespace kernel state make every invocation equivalent to a control-plane
// restart, while a changed boot ID plus firewall-boot models the next host boot.
func TestStartupPolicyAgainstKernelFirewall(t *testing.T) {
	if os.Getenv("GATEWAY_VPN_STARTUP_POLICY_INTEGRATION") != "1" {
		t.Skip("set GATEWAY_VPN_STARTUP_POLICY_INTEGRATION=1 inside an isolated Linux network namespace")
	}
	databasePath := os.Getenv("GATEWAY_VPN_STARTUP_POLICY_DB")
	if !filepath.IsAbs(databasePath) {
		t.Fatal("GATEWAY_VPN_STARTUP_POLICY_DB must be an absolute path")
	}
	database, err := databasepkg.Open(context.Background(), databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := databasepkg.Migrate(context.Background(), database); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	states := state.NewRepository(database)
	modems := modem.NewRepository(database, 1101, 0x1101)
	paths := accesspolicy.NewDirectPathRepository(database)
	policy := accesspolicy.NewRepository(database)
	backend := startupIntegrationFirewall(database, modems)

	switch phase := os.Getenv("GATEWAY_VPN_STARTUP_POLICY_PHASE"); phase {
	case "gated-boot":
		path := seedStartupIntegrationDirect(t, ctx, database, states, modems, paths)
		if err := policy.SetTemporaryDirectOnly(ctx, true, "previous-boot"); err != nil {
			t.Fatal(err)
		}
		recovery, err := initializeStartupPolicy(ctx, database, states, "boot-gated")
		if err != nil || recovery {
			t.Fatalf("initialize gated boot = %v, %v", recovery, err)
		}
		if err := backend.BlockPath(ctx); err != nil {
			t.Fatalf("block gated boot firewall: %v", err)
		}
		assertStartupBlocked(t, ctx, database, states, paths, policy, backend, path.ID, true)
	case "ungated-activate":
		path := seedStartupIntegrationDirect(t, ctx, database, states, modems, paths)
		if _, err := policy.UpdatePolicy(ctx, accesspolicy.PolicyUpdate{
			StartupBlockUntilQualified: false,
			DirectServiceRefresh:       true,
			FailureHoldSeconds:         30,
			RecoveryStableSeconds:      120,
			SwitchCooldownSeconds:      60,
		}); err != nil {
			t.Fatal(err)
		}
		recovery, err := initializeStartupPolicy(ctx, database, states, startupIntegrationBootID)
		if err != nil || !recovery {
			t.Fatalf("initialize ungated boot = %v, %v", recovery, err)
		}
		prepared := requireStartupSnapshot(t, ctx, states)
		if prepared.PathState != state.PathVerifying || prepared.ActiveDirectPathID != path.ID || prepared.ActiveModemID != startupIntegrationModemID {
			t.Fatalf("ungated recovery intent = %+v", prepared)
		}
		if err := backend.ActivateDirectPath(ctx, startupIntegrationModemID, path.RouteGeneration); err != nil {
			t.Fatalf("activate production direct firewall path: %v", err)
		}
		if _, changed, err := states.FinishDirectActivation(ctx, path.ID, path.PolicyGeneration, path.RouteGeneration); err != nil || !changed {
			t.Fatalf("finish recovered direct path changed=%v err=%v", changed, err)
		}
		if err := policy.SetTemporaryDirectOnly(ctx, true, startupIntegrationBootID); err != nil {
			t.Fatal(err)
		}
		assertStartupDirectActive(t, ctx, states, policy, backend, path)
	case "same-boot-restart":
		path := requireStartupDirectPath(t, ctx, paths)
		before := requireStartupSnapshot(t, ctx, states)
		recovery, err := initializeStartupPolicy(ctx, database, states, startupIntegrationBootID)
		if err != nil || recovery {
			t.Fatalf("initialize same-boot restart = %v, %v", recovery, err)
		}
		after := requireStartupSnapshot(t, ctx, states)
		if after != before {
			t.Fatalf("same-boot restart changed runtime tuple: before=%+v after=%+v", before, after)
		}
		assertStartupDirectActive(t, ctx, states, policy, backend, path)
	case "next-gated-boot":
		path := requireStartupDirectPath(t, ctx, paths)
		if _, err := policy.UpdatePolicy(ctx, accesspolicy.PolicyUpdate{
			StartupBlockUntilQualified: true,
			DirectServiceRefresh:       true,
			FailureHoldSeconds:         30,
			RecoveryStableSeconds:      120,
			SwitchCooldownSeconds:      60,
		}); err != nil {
			t.Fatal(err)
		}
		recovery, err := initializeStartupPolicy(ctx, database, states, "boot-next-gated")
		if err != nil || recovery {
			t.Fatalf("initialize next gated boot = %v, %v", recovery, err)
		}
		if err := backend.BlockPath(ctx); err != nil {
			t.Fatalf("retain next-boot firewall quarantine: %v", err)
		}
		assertStartupBlocked(t, ctx, database, states, paths, policy, backend, path.ID, true)
	default:
		t.Fatalf("unsupported GATEWAY_VPN_STARTUP_POLICY_PHASE %q", phase)
	}
}

func startupIntegrationFirewall(database *sql.DB, modems *modem.Repository) *dataplane.FirewallBackend {
	executor := platformexec.OSExecutor{}
	uplinks := uplink.NewRepository(database, 1101, 0x1101)
	backend := &dataplane.FirewallBackend{
		Database: database,
		Uplinks:  uplinks,
		Executor: executor,
		NFT:      "/usr/sbin/nft",
		TUNName:  "gateway-vpn-tun",
		LANName:  "lan0",
	}
	backend.Routing = &dataplane.RoutingBackend{
		Uplinks:           uplinks,
		Executor:          executor,
		IP:                "/usr/sbin/ip",
		Sysctl:            "/usr/sbin/sysctl",
		LANPrefix:         "192.168.200.0/24",
		WireGuardPrefix:   "10.80.0.0/24",
		BootstrapDNS:      []string{"1.1.1.1"},
		RoutingTableStart: 1101,
		FwmarkStart:       0x1101,
		Gate:              backend,
	}
	return backend
}

func seedStartupIntegrationDirect(t *testing.T, ctx context.Context, database *sql.DB, states *state.Repository, modems *modem.Repository, paths *accesspolicy.DirectPathRepository) accesspolicy.DirectPath {
	t.Helper()
	digest := sha256.Sum256([]byte("startup-policy-kernel-modem"))
	if _, err := modems.Adopt(ctx, modem.AdoptInput{
		ID: startupIntegrationModemID, Name: "Startup integration modem",
		IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:]),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, startupIntegrationModemID, modem.LeaseInput{
		InterfaceName: "wan0", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1",
		DNS: []string{"192.168.8.1"}, MTU: 1500, State: modem.StateReady,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := bypass.NewRepository(database).Create(ctx, bypass.CreateInput{
		ID: "target-startup", Name: "Startup required target", Kind: bypass.KindDomain,
		Value: "example.com", Required: true, Timeout: 5 * time.Second,
		SuccessMode: bypass.SuccessAnyHTTPResponse,
	}); err != nil {
		t.Fatal(err)
	}
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	path := requireStartupDirectPath(t, ctx, paths)
	now := time.Now().UTC()
	if err := paths.Publish(ctx, accesspolicy.DirectResultUpdate{
		PathID: path.ID, ExpectedPolicyGeneration: path.PolicyGeneration,
		ExpectedRouteGeneration: path.RouteGeneration, TransportState: "PASSED",
		QualityClass: accesspolicy.QualityFull, FunctionalScore: 1000,
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 10,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Targets: []accesspolicy.DirectTargetResult{{
			TargetID: "target-startup", TargetClass: "GLOBAL_REQUIRED", State: "PASSED", LatencyMS: 10,
			HTTPStatus: 204, CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := states.BeginDirectActivation(ctx, path.ID, path.PolicyGeneration, path.RouteGeneration); err != nil || !changed {
		t.Fatalf("seed direct activation changed=%v err=%v", changed, err)
	}
	if _, changed, err := states.FinishDirectActivation(ctx, path.ID, path.PolicyGeneration, path.RouteGeneration); err != nil || !changed {
		t.Fatalf("seed direct completion changed=%v err=%v", changed, err)
	}
	return requireStartupDirectPath(t, ctx, paths)
}

func requireStartupDirectPath(t *testing.T, ctx context.Context, paths *accesspolicy.DirectPathRepository) accesspolicy.DirectPath {
	t.Helper()
	items, err := paths.List(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("startup direct paths = %+v, %v", items, err)
	}
	return items[0]
}

func requireStartupSnapshot(t *testing.T, ctx context.Context, states *state.Repository) state.Snapshot {
	t.Helper()
	result, err := states.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertStartupDirectActive(t *testing.T, ctx context.Context, states *state.Repository, policy *accesspolicy.Repository, backend *dataplane.FirewallBackend, path accesspolicy.DirectPath) {
	t.Helper()
	snapshot := requireStartupSnapshot(t, ctx, states)
	if snapshot.GatewayState != state.GatewayActive || snapshot.PathState != state.PathActive || snapshot.ActiveDirectPathID != path.ID || snapshot.ActiveModemID != startupIntegrationModemID || snapshot.ActiveMethodKind != "DIRECT" {
		t.Fatalf("active startup runtime = %+v", snapshot)
	}
	selection, err := policy.GetSelectionRuntime(ctx)
	if err != nil || !selection.TemporaryDirectOnly || selection.TemporaryDirectBootID != startupIntegrationBootID {
		t.Fatalf("same-boot direct-only selection = %+v, %v", selection, err)
	}
	observed, err := backend.ObservePath(ctx)
	expected := dataplane.PathState{
		Active: true, Mode: dataplane.PathModeDirect, Generation: uint32(snapshot.ConfigGeneration),
		DirectInterface: "wan0", DirectMark: 0x1101, RouteGeneration: uint32(path.RouteGeneration),
	}
	if err != nil || observed != expected {
		t.Fatalf("active kernel direct path = %+v, want %+v, error=%v", observed, expected, err)
	}
}

func assertStartupBlocked(t *testing.T, ctx context.Context, database *sql.DB, states *state.Repository, paths *accesspolicy.DirectPathRepository, policy *accesspolicy.Repository, backend *dataplane.FirewallBackend, pathID string, expectDirectOnlyReset bool) {
	t.Helper()
	snapshot := requireStartupSnapshot(t, ctx, states)
	if snapshot.GatewayState != state.GatewayBlocked || snapshot.PathState != state.PathBlocked || snapshot.ActiveDirectPathID != "" || snapshot.ActiveModemID != "" || snapshot.ActiveMethodID != "" {
		t.Fatalf("blocked startup runtime = %+v", snapshot)
	}
	path, err := paths.Get(ctx, pathID)
	if err != nil || path.State != "STALE" || path.ExpiresAt != "" {
		t.Fatalf("invalidated startup evidence = %+v, %v", path, err)
	}
	var targetEvidence int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM direct_path_target_results WHERE path_id=?", pathID).Scan(&targetEvidence); err != nil || targetEvidence != 0 {
		t.Fatalf("direct target evidence count=%d err=%v", targetEvidence, err)
	}
	selection, err := policy.GetSelectionRuntime(ctx)
	if err != nil || expectDirectOnlyReset && (selection.TemporaryDirectOnly || selection.TemporaryDirectBootID != "") {
		t.Fatalf("new-boot direct-only selection = %+v, %v", selection, err)
	}
	observed, err := backend.ObservePath(ctx)
	if err != nil || observed != (dataplane.PathState{}) {
		t.Fatalf("blocked kernel path = %+v, %v", observed, err)
	}
}
