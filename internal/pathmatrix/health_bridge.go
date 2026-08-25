package pathmatrix

import (
	"time"

	"gateway-vpn/internal/health"
)

// SnapshotFromHealth converts one in-memory qualification run to the atomic
// persistence contract without losing its path scope or generations.
func SnapshotFromHealth(result health.CellResult, policyGeneration, routeGeneration int64, checkedAt, expiresAt time.Time) QualificationSnapshot {
	snapshot := QualificationSnapshot{
		PathID:                   result.PathID,
		ExpectedPolicyGeneration: policyGeneration,
		ExpectedRouteGeneration:  routeGeneration,
		State:                    result.State,
		TransportState:           result.TransportState,
		SelectedNodeID:           result.SelectedNodeID,
		RequiredTargetsPassed:    int64(result.RequiredTargetsPassed),
		RequiredTargetsTotal:     int64(result.RequiredTargetsTotal),
		LatencyMS:                result.LatencyMS,
		CheckedAt:                checkedAt,
		ExpiresAt:                expiresAt,
		Nodes:                    make([]NodeEvidence, 0, len(result.Nodes)),
	}
	for _, node := range result.Nodes {
		errorCode := node.Transport.ErrorCode
		if errorCode == "" {
			for _, target := range node.Targets {
				if target.State != health.ProbePassed {
					errorCode = target.ErrorCode
					break
				}
			}
		}
		evidence := NodeEvidence{NodeID: node.NodeID, State: node.State, LatencyMS: node.AggregateLatencyMS, ErrorCode: errorCode}
		for _, target := range node.Targets {
			evidence.Targets = append(evidence.Targets, TargetEvidence{TargetID: target.TargetID, State: target.State, LatencyMS: target.LatencyMS, HTTPStatus: target.HTTPStatus, ErrorCode: target.ErrorCode})
		}
		snapshot.Nodes = append(snapshot.Nodes, evidence)
	}
	return snapshot
}
