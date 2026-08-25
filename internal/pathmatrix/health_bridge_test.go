package pathmatrix

import (
	"testing"
	"time"

	"gateway-vpn/internal/health"
)

func TestSnapshotFromHealthPreservesNodeAndTargetScope(t *testing.T) {
	now := time.Now().UTC()
	snapshot := SnapshotFromHealth(health.CellResult{
		PathID: "path-a", State: health.CellQualified, TransportState: health.ProbePassed,
		SelectedNodeID: "node-a", RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 20,
		Nodes: []health.NodeResult{{NodeID: "node-a", State: health.NodeQualified, AggregateLatencyMS: 20, Targets: []health.TargetResult{{TargetID: "target-a", State: health.ProbePassed, LatencyMS: 10}}}},
	}, 4, 7, now, now.Add(time.Minute))
	if snapshot.ExpectedPolicyGeneration != 4 || snapshot.ExpectedRouteGeneration != 7 || len(snapshot.Nodes) != 1 || snapshot.Nodes[0].State != NodeBypassQualified || snapshot.Nodes[0].Targets[0].TargetID != "target-a" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}
