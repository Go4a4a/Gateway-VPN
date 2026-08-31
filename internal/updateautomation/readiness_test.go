package updateautomation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/wireguard"
)

func TestSQLiteApplyReadinessRequiresFreshFullPathAndManagementHandshake(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: t.TempDir() + "/state.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC)
	digest := sha256.Sum256([]byte("automatic-update-uplink"))
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem:update", Name: "Update", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem:update", modem.LeaseInput{InterfaceName: "enxupdate", ManagementCIDR: "192.168.80.0/24", Gateway: "192.168.80.1", DNS: []string{"192.168.80.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		t.Fatal(err)
	}
	stamp := now.Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx, `
INSERT INTO bypass_probe_targets(
    id,name,target_kind,target_value,normalized_url,enabled,required,priority,
    timeout_seconds,success_mode,state,target_class,created_at,updated_at
) VALUES('target:update','Update target','domain','example.com','https://example.com/',
         1,1,10,8,'any_http_response','UNKNOWN','GLOBAL_REQUIRED',?,?)`, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	paths := accesspolicy.NewDirectPathRepository(database)
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := paths.List(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("direct paths=%+v error=%v", items, err)
	}
	path := items[0]
	if err := paths.Publish(ctx, accesspolicy.DirectResultUpdate{
		PathID: path.ID, ExpectedPolicyGeneration: path.PolicyGeneration, ExpectedRouteGeneration: path.RouteGeneration,
		TransportState: "PASSED", QualityClass: accesspolicy.QualityFull, FunctionalScore: 1000,
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 10,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Targets: []accesspolicy.DirectTargetResult{{TargetID: "target:update", TargetClass: "GLOBAL_REQUIRED", State: "PASSED", LatencyMS: 10, HTTPStatus: 204, CheckedAt: now, ExpiresAt: now.Add(time.Hour)}},
	}); err != nil {
		t.Fatal(err)
	}
	states := state.NewRepository(database)
	if _, changed, err := states.BeginDirectActivation(ctx, path.ID, path.PolicyGeneration, path.RouteGeneration); err != nil || !changed {
		t.Fatalf("begin direct activation changed=%t error=%v", changed, err)
	}
	if _, changed, err := states.FinishDirectActivation(ctx, path.ID, path.PolicyGeneration, path.RouteGeneration); err != nil || !changed {
		t.Fatalf("finish direct activation changed=%t error=%v", changed, err)
	}

	readiness := SQLiteApplyReadiness{Database: database}
	if reason, err := readiness.Check(ctx, now); err != nil || reason != ReadinessManagementChannelUnavailable {
		t.Fatalf("readiness without management=%q error=%v", reason, err)
	}
	if err := (wireguard.RuntimeStore{Database: database}).Put(ctx, wireguard.RuntimeState{LastHandshakeAt: now.Add(-time.Minute).Format(time.RFC3339Nano)}, now); err != nil {
		t.Fatal(err)
	}
	if reason, err := readiness.Check(ctx, now); err != nil || reason != "" {
		t.Fatalf("ready automatic update=%q error=%v", reason, err)
	}
	if err := (wireguard.RuntimeStore{Database: database}).Put(ctx, wireguard.RuntimeState{LastHandshakeAt: now.Add(-4 * time.Minute).Format(time.RFC3339Nano)}, now); err != nil {
		t.Fatal(err)
	}
	if reason, err := readiness.Check(ctx, now); err != nil || reason != ReadinessManagementChannelUnavailable {
		t.Fatalf("stale management readiness=%q error=%v", reason, err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE direct_uplink_paths SET expires_at=? WHERE id=?", now.Add(-time.Second).Format(time.RFC3339Nano), path.ID); err != nil {
		t.Fatal(err)
	}
	if reason, err := readiness.Check(ctx, now); err != nil || reason != ReadinessFullPathUnavailable {
		t.Fatalf("expired full path readiness=%q error=%v", reason, err)
	}
}
