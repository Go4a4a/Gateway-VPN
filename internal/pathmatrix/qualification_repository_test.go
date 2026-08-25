package pathmatrix

import (
	"errors"
	"testing"
	"time"

	"gateway-vpn/internal/store"
)

func TestStoreQualificationIsAtomicAndGenerationScoped(t *testing.T) {
	ctx, database := migratedDatabase(t)
	seedModems(t, ctx, database, "modem-a")
	seedSubscriptions(t, ctx, database, "sub-a")
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatal(err)
	}
	seedNode(t, ctx, database, "sub-a", "node-a")
	if _, err := database.ExecContext(ctx, "UPDATE subscriptions SET active_version_id='version:sub-a' WHERE id='sub-a'"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO bypass_probe_targets (
    id, name, target_kind, target_value, normalized_url, enabled, required,
    priority, timeout_seconds, success_mode, state, created_at, updated_at
) VALUES ('target-a', 'A', 'domain', 'example.com', 'https://example.com/', 1, 1, 10, 8, 'any_http_response', 'UNKNOWN', ?, ?)`, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	cell, _ := repository.Get(ctx, "modem-a", "sub-a")
	now := time.Now().UTC()
	snapshot := QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: cell.PolicyGeneration, ExpectedRouteGeneration: cell.RouteGeneration,
		State: StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 42,
		CheckedAt: now, ExpiresAt: now.Add(time.Minute),
		Nodes: []NodeEvidence{{NodeID: "node-a", State: NodeBypassQualified, LatencyMS: 42, Targets: []TargetEvidence{{TargetID: "target-a", State: "PASSED", LatencyMS: 30, HTTPStatus: 204}}}},
	}
	if err := repository.StoreQualification(ctx, snapshot); err != nil {
		t.Fatalf("StoreQualification() error = %v", err)
	}
	qualified, _ := repository.Get(ctx, "modem-a", "sub-a")
	if qualified.State != StateQualified || qualified.SelectedNodeID != "node-a" || qualified.QualifiedNodes != 1 {
		t.Fatalf("qualified cell = %+v", qualified)
	}
	var nodeCount, targetCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM path_nodes WHERE path_id=?", cell.ID).Scan(&nodeCount); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM path_node_target_results WHERE path_id=?", cell.ID).Scan(&targetCount); err != nil {
		t.Fatal(err)
	}
	if nodeCount != 1 || targetCount != 1 {
		t.Fatalf("evidence counts = %d/%d", nodeCount, targetCount)
	}

	if err := repository.BumpRouteGeneration(ctx, "modem-a"); err != nil {
		t.Fatal(err)
	}
	if err := repository.StoreQualification(ctx, snapshot); !errors.Is(err, store.ErrStaleGeneration) {
		t.Fatalf("stale StoreQualification() error = %v", err)
	}
	var afterStale int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM path_nodes WHERE path_id=?", cell.ID).Scan(&afterStale); err != nil {
		t.Fatal(err)
	}
	if afterStale != 1 {
		t.Fatalf("stale update changed evidence count to %d", afterStale)
	}
}

func TestStoreQualificationRejectsNodeFromAnotherSubscription(t *testing.T) {
	ctx, database := migratedDatabase(t)
	seedModems(t, ctx, database, "modem-a")
	seedSubscriptions(t, ctx, database, "sub-a", "sub-b")
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatal(err)
	}
	seedNode(t, ctx, database, "sub-a", "node-a")
	seedNode(t, ctx, database, "sub-b", "node-b")
	if _, err := database.ExecContext(ctx, "UPDATE subscriptions SET active_version_id='version:sub-a' WHERE id='sub-a'"); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	cell, _ := repository.Get(ctx, "modem-a", "sub-a")
	now := time.Now().UTC()
	err := repository.StoreQualification(ctx, QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: cell.PolicyGeneration, ExpectedRouteGeneration: cell.RouteGeneration,
		State: StateFailed, TransportState: "FAILED", RequiredTargetsTotal: 1,
		CheckedAt: now, ExpiresAt: now.Add(time.Minute), Nodes: []NodeEvidence{{NodeID: "node-b", State: NodeBypassFailed}},
	})
	if err == nil {
		t.Fatal("StoreQualification(foreign node) error = nil")
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM path_nodes WHERE path_id=?", cell.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("foreign node failure left %d evidence rows", count)
	}
}

func TestStoreNodeQualificationPreservesFreshPeersAndRecomputesBestNode(t *testing.T) {
	ctx, database := migratedDatabase(t)
	seedModems(t, ctx, database, "modem-a")
	seedSubscriptions(t, ctx, database, "sub-a")
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatal(err)
	}
	seedNode(t, ctx, database, "sub-a", "node-a")
	if _, err := database.ExecContext(ctx, `
INSERT INTO nodes(id, version_id, external_name, normalized_name, fingerprint, proxy_type)
VALUES ('node-b', 'version:sub-a', 'node-b', 'node-b', 'fingerprint:node-b', 'vless')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE subscription_versions SET nodes_total=2 WHERE id='version:sub-a'; UPDATE subscriptions SET active_version_id='version:sub-a' WHERE id='sub-a'"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := database.ExecContext(ctx, `
INSERT INTO bypass_probe_targets (
    id, name, target_kind, target_value, normalized_url, enabled, required,
    priority, timeout_seconds, success_mode, state, created_at, updated_at
) VALUES ('target-a', 'A', 'domain', 'example.com', 'https://example.com/', 1, 1, 10, 8, 'any_http_response', 'UNKNOWN', ?, ?)`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	cell, _ := repository.Get(ctx, "modem-a", "sub-a")
	if err := repository.StoreQualification(ctx, QualificationSnapshot{
		PathID: cell.ID, State: StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 20,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []NodeEvidence{
			{NodeID: "node-a", State: NodeBypassQualified, LatencyMS: 20, Targets: []TargetEvidence{{TargetID: "target-a", State: "PASSED"}}},
			{NodeID: "node-b", State: NodeBypassQualified, LatencyMS: 30, Targets: []TargetEvidence{{TargetID: "target-a", State: "PASSED"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := repository.StoreNodeQualification(ctx, NodeQualificationSnapshot{
		PathID: cell.ID, CandidateNodes: 2, RequiredTargetsTotal: 1,
		CheckedAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour),
		Node: NodeEvidence{NodeID: "node-b", State: NodeBypassFailed, LatencyMS: 40, ErrorCode: "TARGET_FAILED", Targets: []TargetEvidence{{TargetID: "target-a", State: "FAILED", ErrorCode: "TARGET_FAILED"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != StateQualified || updated.SelectedNodeID != "node-a" || updated.QualifiedNodes != 1 {
		t.Fatalf("aggregate after exact failure = %+v", updated)
	}
	var nodeCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM path_nodes WHERE path_id=?", cell.ID).Scan(&nodeCount); err != nil || nodeCount != 2 {
		t.Fatalf("preserved path node count = %d, %v", nodeCount, err)
	}
	updated, err = repository.StoreNodeQualification(ctx, NodeQualificationSnapshot{
		PathID: cell.ID, CandidateNodes: 2, RequiredTargetsTotal: 1,
		CheckedAt: now.Add(2 * time.Minute), ExpiresAt: now.Add(time.Hour),
		Node: NodeEvidence{NodeID: "node-b", State: NodeBypassQualified, LatencyMS: 5, Targets: []TargetEvidence{{TargetID: "target-a", State: "PASSED"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.SelectedNodeID != "node-b" || updated.QualifiedNodes != 2 || updated.RequiredTargetsPassed != 1 {
		t.Fatalf("aggregate after exact success = %+v", updated)
	}
}
