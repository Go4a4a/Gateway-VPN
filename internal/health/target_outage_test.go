package health_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/subscription"
)

func TestTargetOutageRequiresIndependentModemsAndSubscriptionsAndRecovers(t *testing.T) {
	ctx, database := outageDatabase(t)
	modems := modem.NewRepository(database, 1101, 0x1101)
	for _, id := range []string{"m1", "m2"} {
		digest := sha256.Sum256([]byte(id))
		if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: id, Name: id, IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatal(err)
	}
	subscriptions := subscription.NewRepository(database)
	for _, id := range []string{"s1", "s2"} {
		if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: id, Name: id, SourceType: "url", SourceSecretRef: "/secret/" + id, RefreshInterval: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if _, err := database.ExecContext(ctx, `
INSERT INTO bypass_probe_targets (
    id, name, target_kind, target_value, normalized_url, enabled, required,
    priority, timeout_seconds, success_mode, state, created_at, updated_at
) VALUES ('target', 'Target', 'domain', 'example.com', 'https://example.com/', 1, 1, 10, 8, 'any_http_response', 'NORMAL', ?, ?)`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	for _, subscriptionID := range []string{"s1", "s2"} {
		versionID := "version-" + subscriptionID
		nodeID := "node-" + subscriptionID
		if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_versions(id, subscription_id, content_sha256, nodes_total, state, created_at)
VALUES (?, ?, ?, 1, 'LKG', ?)`, versionID, subscriptionID, hex.EncodeToString(make([]byte, 32)), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx, `
INSERT INTO nodes(id, version_id, external_name, normalized_name, fingerprint, proxy_type)
VALUES (?, ?, ?, ?, ?, 'vless')`, nodeID, versionID, nodeID, nodeID, "fp-"+nodeID); err != nil {
			t.Fatal(err)
		}
	}
	matrix := pathmatrix.NewRepository(database)
	if err := matrix.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Hour).Format(time.RFC3339Nano)
	checked := now.Format(time.RFC3339Nano)
	for _, pair := range [][2]string{{"m1", "s1"}, {"m1", "s2"}, {"m2", "s1"}, {"m2", "s2"}} {
		path, err := matrix.Get(ctx, pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		nodeID := "node-" + pair[1]
		if _, err := database.ExecContext(ctx, `
INSERT INTO path_nodes(path_id, node_id, qualification_state, qualification_generation, route_generation, qualification_expires_at)
VALUES (?, ?, 'BYPASS_FAILED', 0, 0, ?)`, path.ID, nodeID, expires); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx, `
INSERT INTO path_node_target_results(
    path_id, node_id, target_id, state, checked_at, expires_at,
    policy_generation, route_generation
) VALUES (?, ?, 'target', 'FAILED', ?, ?, 0, 0)`, path.ID, nodeID, checked, expires); err != nil {
			t.Fatal(err)
		}
	}
	evaluator := health.TargetOutageEvaluator{Database: database, Config: health.DefaultTargetOutageConfig()}
	if _, err := database.ExecContext(ctx, `
INSERT INTO bypass_probe_targets (
    id, name, target_kind, target_value, normalized_url, enabled, required,
    priority, timeout_seconds, success_mode, state, created_at, updated_at
) VALUES ('target-ok', 'Target OK', 'domain', 'ok.example.com', 'https://ok.example.com/', 1, 0, 20, 8, 'any_http_response', 'UNKNOWN', ?, ?)`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO path_node_target_results(
    path_id, node_id, target_id, state, checked_at, expires_at,
    policy_generation, route_generation
)
SELECT path_id, node_id, 'target-ok', 'PASSED', ?, ?, policy_generation, route_generation
FROM path_node_target_results WHERE target_id='target'`, checked, expires); err != nil {
		t.Fatal(err)
	}
	normal, err := evaluator.Evaluate(ctx, "target-ok")
	if err != nil || !normal.Changed || normal.State != health.TargetNormal || normal.SuccessCombinations != 4 {
		t.Fatalf("Evaluate(first successful evidence) = %+v, %v", normal, err)
	}
	assessment, err := evaluator.Evaluate(ctx, "target")
	if err != nil || !assessment.Changed || assessment.State != health.TargetSuspect || assessment.FailureCombinations != 4 {
		t.Fatalf("Evaluate(failures) = %+v, %v", assessment, err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE path_node_target_results SET state='PASSED'
WHERE path_id IN ('path:m1:s1', 'path:m2:s2')`); err != nil {
		t.Fatal(err)
	}
	assessment, err = evaluator.Evaluate(ctx, "target")
	if err != nil || !assessment.Changed || assessment.State != health.TargetNormal || assessment.SuccessCombinations != 2 {
		t.Fatalf("Evaluate(recovery) = %+v, %v", assessment, err)
	}
	var eventCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type IN ('TARGET_STATE_NORMAL','TARGET_OUTAGE_SUSPECTED','TARGET_OUTAGE_RECOVERED')").Scan(&eventCount); err != nil || eventCount != 3 {
		t.Fatalf("target state event count = %d, %v", eventCount, err)
	}
}

func outageDatabase(t *testing.T) (context.Context, *sql.DB) {
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
	return ctx, database
}
