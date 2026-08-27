package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/state"
)

const testBootID = "a7c2d386-381e-4b36-8e2b-0a766eb57e03"

func TestInitializeStartupPolicyBlocksAndInvalidatesGatedBoot(t *testing.T) {
	ctx, database, states, path := activeDirectStartupFixture(t)
	recovery, err := initializeStartupPolicy(ctx, database, states, testBootID)
	if err != nil || recovery {
		t.Fatalf("initializeStartupPolicy(gated) = %v, %v", recovery, err)
	}
	snapshot, err := states.Get(ctx)
	if err != nil || snapshot.PathState != state.PathBlocked || snapshot.ActiveDirectPathID != "" {
		t.Fatalf("gated startup runtime = %+v, %v", snapshot, err)
	}
	current, err := accesspolicy.NewDirectPathRepository(database).Get(ctx, path.ID)
	if err != nil || current.State != "STALE" || current.ExpiresAt != "" {
		t.Fatalf("gated startup evidence = %+v, %v", current, err)
	}
}

func TestInitializeStartupPolicyPreparesUngatedRecoveryAndPreservesSameBootRestart(t *testing.T) {
	ctx, database, states, path := activeDirectStartupFixture(t)
	policy := accesspolicy.NewRepository(database)
	if _, err := policy.UpdatePolicy(ctx, accesspolicy.PolicyUpdate{
		StartupBlockUntilQualified: false, DirectServiceRefresh: true,
		FailureHoldSeconds: 30, RecoveryStableSeconds: 120, SwitchCooldownSeconds: 60,
	}); err != nil {
		t.Fatal(err)
	}
	recovery, err := initializeStartupPolicy(ctx, database, states, testBootID)
	if err != nil || !recovery {
		t.Fatalf("initializeStartupPolicy(ungated) = %v, %v", recovery, err)
	}
	prepared, err := states.Get(ctx)
	if err != nil || prepared.PathState != state.PathVerifying || prepared.ActiveDirectPathID != path.ID {
		t.Fatalf("ungated startup runtime = %+v, %v", prepared, err)
	}
	if _, changed, err := states.FinishDirectActivation(ctx, path.ID, path.PolicyGeneration, path.RouteGeneration); err != nil || !changed {
		t.Fatalf("FinishDirectActivation() changed=%v err=%v", changed, err)
	}
	beforeRestart, _ := states.Get(ctx)
	recovery, err = initializeStartupPolicy(ctx, database, states, testBootID)
	afterRestart, getErr := states.Get(ctx)
	if err != nil || getErr != nil || recovery || afterRestart.PathState != state.PathActive || afterRestart.ActiveDirectPathID != path.ID || afterRestart.ConfigGeneration != beforeRestart.ConfigGeneration {
		t.Fatalf("same-boot restart = recovery=%v before=%+v after=%+v errors=%v/%v", recovery, beforeRestart, afterRestart, err, getErr)
	}
}

func TestInitializeStartupPolicyBlocksUngatedBootWithoutLKG(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	if _, err := accesspolicy.NewRepository(database).UpdatePolicy(ctx, accesspolicy.PolicyUpdate{
		StartupBlockUntilQualified: false, DirectServiceRefresh: true,
		FailureHoldSeconds: 30, RecoveryStableSeconds: 120, SwitchCooldownSeconds: 60,
	}); err != nil {
		t.Fatal(err)
	}
	states := state.NewRepository(database)
	recovery, err := initializeStartupPolicy(ctx, database, states, testBootID)
	if err != nil || recovery {
		t.Fatalf("initializeStartupPolicy(no LKG) = %v, %v", recovery, err)
	}
	snapshot, err := states.Get(ctx)
	if err != nil || snapshot.GatewayState != state.GatewayBlocked || snapshot.PathState != state.PathBlocked {
		t.Fatalf("no-LKG startup runtime = %+v, %v", snapshot, err)
	}
}

func activeDirectStartupFixture(t *testing.T) (context.Context, *sql.DB, *state.Repository, accesspolicy.DirectPath) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("startup-modem"))
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{
		InterfaceName: "enxstartup", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1",
		DNS: []string{"192.168.8.1"}, MTU: 1500, State: modem.StateReady,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := bypass.NewRepository(database).Create(ctx, bypass.CreateInput{
		ID: "target-a", Name: "A", Kind: bypass.KindDomain, Value: "example.com",
		Required: true, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessAnyHTTPResponse,
	}); err != nil {
		t.Fatal(err)
	}
	paths := accesspolicy.NewDirectPathRepository(database)
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := paths.List(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("direct startup paths = %+v, %v", items, err)
	}
	path := items[0]
	now := time.Now().UTC()
	if err := paths.Publish(ctx, accesspolicy.DirectResultUpdate{
		PathID: path.ID, ExpectedPolicyGeneration: path.PolicyGeneration, ExpectedRouteGeneration: path.RouteGeneration,
		TransportState: "PASSED", QualityClass: accesspolicy.QualityFull, FunctionalScore: 1000,
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 10,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Targets: []accesspolicy.DirectTargetResult{{TargetID: "target-a", State: "PASSED", LatencyMS: 10, HTTPStatus: 204, CheckedAt: now, ExpiresAt: now.Add(time.Hour)}},
	}); err != nil {
		t.Fatal(err)
	}
	states := state.NewRepository(database)
	if _, changed, err := states.BeginDirectActivation(ctx, path.ID, path.PolicyGeneration, path.RouteGeneration); err != nil || !changed {
		t.Fatalf("BeginDirectActivation() changed=%v err=%v", changed, err)
	}
	if _, changed, err := states.FinishDirectActivation(ctx, path.ID, path.PolicyGeneration, path.RouteGeneration); err != nil || !changed {
		t.Fatalf("FinishDirectActivation() changed=%v err=%v", changed, err)
	}
	return ctx, database, states, path
}
