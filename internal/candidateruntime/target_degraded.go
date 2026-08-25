package candidateruntime

import (
	"context"
	"errors"
	"fmt"

	"gateway-vpn/internal/health"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/state"
)

type targetObservationEvaluator interface {
	EvaluateWithObservation(context.Context, string, health.TargetObservation) (health.TargetAssessment, error)
}

func (current *Runtime) evaluateTargetObservation(ctx context.Context, targetID, modemID, subscriptionID string, passed bool) (health.TargetAssessment, error) {
	evaluator, ok := current.TargetStates.(targetObservationEvaluator)
	if !ok {
		return health.TargetAssessment{}, errors.New("target observation evaluator is unavailable")
	}
	return evaluator.EvaluateWithObservation(ctx, targetID, health.TargetObservation{
		ModemID: modemID, SubscriptionID: subscriptionID, Passed: passed,
	})
}

// publishTargetDegraded replaces only the exact active-node evidence, verifies
// that every required failure is TARGET_SUSPECT, and then changes the durable
// Gateway state without touching the already-open firewall generation or
// Mihomo active selections.
func (current *Runtime) publishTargetDegraded(ctx context.Context, operation PathOperationResult) error {
	if current == nil || operation.PathID == "" || operation.NodeID == "" ||
		operation.Result.TransportState != health.ProbePassed || len(operation.Result.Nodes) != 1 ||
		operation.Result.Nodes[0].NodeID != operation.NodeID || operation.Result.Nodes[0].State != health.NodeFailed {
		return errors.New("complete failed active-node target evidence is required")
	}
	current.mutex.Lock()
	defer current.mutex.Unlock()
	if current.OperationLock != nil {
		current.OperationLock.Lock()
		defer current.OperationLock.Unlock()
	}
	if err := current.validate(); err != nil {
		return err
	}
	runtimeState, err := current.State.Get(ctx)
	if err != nil {
		return err
	}
	if runtimeState.PathState != state.PathActive || runtimeState.ActivePathID != operation.PathID || runtimeState.ActiveNodeID != operation.NodeID {
		return errors.New("target degradation is no longer scoped to the active tuple")
	}
	snapshot := pathmatrix.SnapshotFromHealth(operation.Result, operation.PolicyGeneration, operation.RouteGeneration, operation.CheckedAt, operation.ExpiresAt)
	if len(snapshot.Nodes) != 1 {
		return errors.New("target degradation snapshot must contain one exact node")
	}
	candidateNodes := operation.CandidateNodesTotal
	if candidateNodes <= 0 {
		candidateNodes = 1
	}
	if _, err := current.Paths.StoreNodeQualification(ctx, pathmatrix.NodeQualificationSnapshot{
		PathID: operation.PathID, ExpectedPolicyGeneration: operation.PolicyGeneration,
		ExpectedRouteGeneration: operation.RouteGeneration, CandidateNodes: int64(candidateNodes),
		RequiredTargetsTotal: int64(operation.Result.RequiredTargetsTotal),
		CheckedAt:            operation.CheckedAt, ExpiresAt: operation.ExpiresAt, Node: snapshot.Nodes[0],
	}); err != nil {
		return fmt.Errorf("store target-degraded active evidence: %w", err)
	}
	current.evaluateTargetStates(ctx, mustProbeTargets(current, ctx))
	if _, err := current.Paths.MarkTargetDegraded(ctx, operation.PathID, operation.NodeID, operation.PolicyGeneration, operation.RouteGeneration, operation.CheckedAt); err != nil {
		return fmt.Errorf("mark target-degraded path: %w", err)
	}
	if _, _, err := current.State.MarkTargetDegraded(ctx, operation.PathID, operation.NodeID, operation.PolicyGeneration, operation.RouteGeneration); err != nil {
		return fmt.Errorf("mark target-degraded runtime: %w", err)
	}
	current.appendPathOperationEvent(ctx, "PERIODIC_TARGET_OUTAGE_SUPPRESSED", operation)
	return nil
}
