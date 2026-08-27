package accesspolicy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"testing"
	"time"

	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/subscription"
)

func TestReconcileBootInvalidatesQualificationOnlyWhenStartupGateEnabled(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		ctx, database := accessDatabase(t)
		vpnPathID, directPathID := seedBootEvidence(t, ctx, database)
		result, err := NewRepository(database).ReconcileBoot(ctx, "boot-a")
		if err != nil || !result.NewBoot || !result.QualificationInvalidated {
			t.Fatalf("ReconcileBoot(enabled) = %+v, %v", result, err)
		}
		assertBootEvidence(t, database, vpnPathID, directPathID, "STALE", "STALE", 0)
	})

	t.Run("disabled", func(t *testing.T) {
		ctx, database := accessDatabase(t)
		vpnPathID, directPathID := seedBootEvidence(t, ctx, database)
		repository := NewRepository(database)
		if _, err := repository.UpdatePolicy(ctx, PolicyUpdate{
			StartupBlockUntilQualified: false, DirectServiceRefresh: true,
			FailureHoldSeconds: 30, RecoveryStableSeconds: 120, SwitchCooldownSeconds: 60,
		}); err != nil {
			t.Fatal(err)
		}
		result, err := repository.ReconcileBoot(ctx, "boot-a")
		if err != nil || !result.NewBoot || result.StartupBlockUntilQualified || result.QualificationInvalidated {
			t.Fatalf("ReconcileBoot(disabled) = %+v, %v", result, err)
		}
		assertBootEvidence(t, database, vpnPathID, directPathID, "QUALIFIED", "QUALIFIED", 2)
	})
}

func seedBootEvidence(t *testing.T, ctx context.Context, database *sql.DB) (string, string) {
	t.Helper()
	digest := sha256.Sum256([]byte("boot-modem"))
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{
		InterfaceName: "enxboot", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1",
		DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady,
	}); err != nil {
		t.Fatal(err)
	}
	subscriptions := subscription.NewRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	versions := subscription.NewVersionRepository(database)
	staged, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-a", SubscriptionID: "sub-a", Payload: []byte("vless://11111111-1111-1111-1111-111111111111@proxy.example.com:443#LTE")})
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.Activate(ctx, staged.Version.ID); err != nil {
		t.Fatal(err)
	}
	targets := bypass.NewRepository(database)
	if _, err := targets.Create(ctx, bypass.CreateInput{ID: "target-a", Name: "A", Kind: bypass.KindDomain, Value: "example.com", Required: true, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessAnyHTTPResponse}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	vpnPaths := pathmatrix.NewRepository(database)
	if err := vpnPaths.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	vpnPath, err := vpnPaths.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := vpnPaths.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: vpnPath.ID, ExpectedPolicyGeneration: vpnPath.PolicyGeneration, ExpectedRouteGeneration: vpnPath.RouteGeneration,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: staged.Nodes[0].ID,
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 10,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []pathmatrix.NodeEvidence{{NodeID: staged.Nodes[0].ID, State: pathmatrix.NodeBypassQualified, LatencyMS: 10,
			Targets: []pathmatrix.TargetEvidence{{TargetID: "target-a", State: "PASSED", LatencyMS: 10}}}},
	}); err != nil {
		t.Fatal(err)
	}
	directPaths := NewDirectPathRepository(database)
	if err := directPaths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	directItems, err := directPaths.List(ctx)
	if err != nil || len(directItems) != 1 {
		t.Fatalf("direct paths = %+v, %v", directItems, err)
	}
	directPath := directItems[0]
	if err := directPaths.Publish(ctx, DirectResultUpdate{
		PathID: directPath.ID, ExpectedPolicyGeneration: directPath.PolicyGeneration, ExpectedRouteGeneration: directPath.RouteGeneration,
		TransportState: "PASSED", QualityClass: QualityFull, FunctionalScore: 1000,
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 9,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Targets: []DirectTargetResult{{TargetID: "target-a", State: "PASSED", LatencyMS: 9, HTTPStatus: 204, CheckedAt: now, ExpiresAt: now.Add(time.Hour)}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO path_health_runtime(path_id,probe_class,next_probe_at,last_result,updated_at)
VALUES(?, 'STANDBY', ?, 'PASSED', ?)`, vpnPath.ID, now.Add(time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	return vpnPath.ID, directPath.ID
}

func assertBootEvidence(t *testing.T, database *sql.DB, vpnPathID, directPathID, vpnState, directState string, targetRows int) {
	t.Helper()
	var gotVPN, gotDirect string
	var vpnExpiry, directExpiry sql.NullString
	if err := database.QueryRow("SELECT state, expires_at FROM subscription_modem_paths WHERE id=?", vpnPathID).Scan(&gotVPN, &vpnExpiry); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT state, expires_at FROM direct_modem_paths WHERE id=?", directPathID).Scan(&gotDirect, &directExpiry); err != nil {
		t.Fatal(err)
	}
	if gotVPN != vpnState || gotDirect != directState {
		t.Fatalf("path states = %s/%s, want %s/%s", gotVPN, gotDirect, vpnState, directState)
	}
	if targetRows == 0 && (vpnExpiry.Valid || directExpiry.Valid) {
		t.Fatalf("invalidated expiry remains: vpn=%q direct=%q", vpnExpiry.String, directExpiry.String)
	}
	var count int
	if err := database.QueryRow("SELECT (SELECT COUNT(*) FROM path_node_target_results)+(SELECT COUNT(*) FROM direct_path_target_results)").Scan(&count); err != nil || count != targetRows {
		t.Fatalf("target evidence rows = %d, %v; want %d", count, err, targetRows)
	}
}
