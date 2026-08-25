package pathmatrix

import (
	"testing"
	"time"
)

func TestPathNodeAndTargetDetailsUseKeysetPaginationAndGenerationFreshness(t *testing.T) {
	ctx, database := migratedDatabase(t)
	seedModems(t, ctx, database, "modem-a")
	seedSubscriptions(t, ctx, database, "sub-a")
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatal(err)
	}
	seedNode(t, ctx, database, "sub-a", "node-a")
	if _, err := database.ExecContext(ctx, `
INSERT INTO nodes(id, version_id, external_name, normalized_name, fingerprint, proxy_type)
VALUES ('node-b', 'version:sub-a', 'node-b', 'node-b', 'fingerprint:node-b', 'vless');
UPDATE subscriptions SET active_version_id='version:sub-a' WHERE id='sub-a'`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := database.ExecContext(ctx, `
INSERT INTO bypass_probe_targets (
 id, name, target_kind, target_value, normalized_url, enabled, required,
 priority, timeout_seconds, success_mode, state, created_at, updated_at
) VALUES
 ('target-a', 'A', 'domain', 'a.example', 'https://a.example/', 1, 1, 10, 8, 'any_http_response', 'UNKNOWN', ?, ?),
 ('target-b', 'B', 'domain', 'b.example', 'https://b.example/', 1, 0, 20, 8, 'any_http_response', 'UNKNOWN', ?, ?)`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	if err := repository.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	cell, _ := repository.Get(ctx, "modem-a", "sub-a")
	if err := repository.StoreQualification(ctx, QualificationSnapshot{
		PathID: cell.ID, State: StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 10,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []NodeEvidence{
			{NodeID: "node-a", State: NodeBypassQualified, LatencyMS: 10, Targets: []TargetEvidence{{TargetID: "target-a", State: "PASSED"}, {TargetID: "target-b", State: "FAILED", ErrorCode: "OPTIONAL_FAILED"}}},
			{NodeID: "node-b", State: NodeBypassFailed, ErrorCode: "TRANSPORT_FAILED"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	first, err := repository.ListPathNodes(ctx, cell.ID, 1, "", now)
	if err != nil || len(first.Items) != 1 || first.NextAfterNodeID == "" || !first.Items[0].CurrentEvidence {
		t.Fatalf("first path node page = %+v, %v", first, err)
	}
	second, err := repository.ListPathNodes(ctx, cell.ID, 1, first.NextAfterNodeID, now)
	if err != nil || len(second.Items) != 1 || second.NextAfterNodeID != "" || second.Items[0].NodeID == first.Items[0].NodeID {
		t.Fatalf("second path node page = %+v, %v", second, err)
	}
	targetFirst, err := repository.ListNodeTargets(ctx, cell.ID, "node-a", 1, nil, now)
	if err != nil || len(targetFirst.Items) != 1 || targetFirst.NextCursor == nil || targetFirst.Items[0].TargetID != "target-a" {
		t.Fatalf("first target page = %+v, %v", targetFirst, err)
	}
	targetSecond, err := repository.ListNodeTargets(ctx, cell.ID, "node-a", 1, targetFirst.NextCursor, now)
	if err != nil || len(targetSecond.Items) != 1 || targetSecond.NextCursor != nil || targetSecond.Items[0].TargetID != "target-b" {
		t.Fatalf("second target page = %+v, %v", targetSecond, err)
	}
	if err := repository.BumpRouteGeneration(ctx, "modem-a"); err != nil {
		t.Fatal(err)
	}
	stale, err := repository.ListPathNodes(ctx, cell.ID, 10, "", now)
	if err != nil || stale.Items[0].QualificationState != EvidenceStale || stale.Items[0].CurrentEvidence {
		t.Fatalf("stale node details = %+v, %v", stale, err)
	}
}
