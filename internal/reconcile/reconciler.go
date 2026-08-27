// Package reconcile converges persisted desired state with observed data-plane
// state while preserving fail-closed behavior.
package reconcile

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/store"
)

type Observed struct {
	FirewallReady      bool
	MihomoReady        bool
	TUNReady           bool
	MethodKind         string
	ActivePathID       string
	ActiveDirectPathID string
	ActiveNodeID       string
}

type Observer interface {
	Observe(context.Context) (Observed, error)
}

type Candidate struct {
	Key              string
	MethodID         string
	MethodKind       string
	QualityClass     string
	PathID           string
	ModemID          string
	SubscriptionID   string
	NodeID           string
	PolicyGeneration int64
	RouteGeneration  int64
	ConfigGeneration int64
}

type Inventory interface {
	HasRequiredTargets(context.Context) (bool, error)
	HasReadyModems(context.Context) (bool, error)
	FreshCandidate(context.Context, string) (Candidate, error)
	FreshNodeCandidate(context.Context, string, string) (Candidate, error)
	TargetDegradedCandidate(context.Context, string, string) (Candidate, error)
	BestFreshCandidate(context.Context) (Candidate, error)
}

type Actuator interface {
	Block(context.Context, string) error
	Activate(context.Context, Candidate) error
}

type Reconciler struct {
	Observer     Observer
	Inventory    Inventory
	State        *state.Repository
	Actuator     Actuator
	AccessPaths  *accesspolicy.DirectPathRepository
	AccessPolicy *accesspolicy.Repository
	Now          func() time.Time

	mutex sync.Mutex
}

type Result struct {
	Action    string
	Candidate Candidate
}

func (reconciler *Reconciler) Reconcile(ctx context.Context) (Result, error) {
	reconciler.mutex.Lock()
	defer reconciler.mutex.Unlock()
	return reconciler.reconcile(ctx)
}

func (reconciler *Reconciler) reconcile(ctx context.Context) (Result, error) {
	if reconciler.Observer == nil || reconciler.Inventory == nil || reconciler.State == nil || reconciler.Actuator == nil {
		return Result{}, errors.New("complete reconciler dependencies are required")
	}
	observed, err := reconciler.Observer.Observe(ctx)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "OBSERVATION_FAILED", err)
	}
	if !observed.FirewallReady {
		return reconciler.block(ctx, state.GatewayBlocked, "FIREWALL_NOT_READY", nil)
	}
	desired, err := reconciler.State.Get(ctx)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "RUNTIME_STATE_UNAVAILABLE", err)
	}
	hasTargets, err := reconciler.Inventory.HasRequiredTargets(ctx)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "TARGET_INVENTORY_FAILED", err)
	}
	hasModems, err := reconciler.Inventory.HasReadyModems(ctx)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "MODEM_INVENTORY_FAILED", err)
	}
	if !hasModems {
		return reconciler.block(ctx, state.GatewayAllModemsOffline, "ALL_MODEMS_OFFLINE", nil)
	}
	if reconciler.AccessPaths != nil || reconciler.AccessPolicy != nil {
		if reconciler.AccessPaths == nil || reconciler.AccessPolicy == nil {
			return reconciler.block(ctx, state.GatewayBlocked, "UNIFIED_POLICY_UNAVAILABLE", errors.New("both unified access repositories are required"))
		}
		return reconciler.reconcileUnified(ctx, observed, desired, hasTargets)
	}
	if !observed.MihomoReady || !observed.TUNReady {
		return reconciler.block(ctx, state.GatewayBlocked, "MIHOMO_OR_TUN_NOT_READY", nil)
	}
	if desired.PolicyTransitionActive() {
		return reconciler.reconcilePolicyTransition(ctx, observed, desired, hasTargets)
	}
	if !hasTargets {
		return reconciler.block(ctx, state.GatewayNoBypassTargets, "NO_BYPASS_TARGETS", nil)
	}
	if desired.GatewayState == state.GatewayDegradedTarget && desired.PathState == state.PathActive &&
		desired.ActivePathID != "" && desired.ActiveNodeID != "" &&
		observed.ActivePathID == desired.ActivePathID && observed.ActiveNodeID == desired.ActiveNodeID {
		fresh, freshErr := reconciler.Inventory.FreshNodeCandidate(ctx, desired.ActivePathID, desired.ActiveNodeID)
		if freshErr == nil {
			if _, _, err := reconciler.State.RecoverTargetDegraded(ctx, fresh.PathID, fresh.NodeID, fresh.PolicyGeneration, fresh.RouteGeneration); err != nil {
				return reconciler.block(ctx, state.GatewayBlocked, "TARGET_DEGRADED_RECOVERY_FAILED", err)
			}
			return Result{Action: "TARGET_DEGRADED_RECOVERED", Candidate: fresh}, nil
		}
		if freshErr != nil && !errors.Is(freshErr, store.ErrNotFound) {
			return reconciler.block(ctx, state.GatewayBlocked, "TARGET_DEGRADED_VALIDATION_FAILED", freshErr)
		}
		degraded, degradedErr := reconciler.Inventory.TargetDegradedCandidate(ctx, desired.ActivePathID, desired.ActiveNodeID)
		if degradedErr == nil {
			return Result{Action: "NO_CHANGE_DEGRADED_TARGET", Candidate: degraded}, nil
		}
		if degradedErr != nil && !errors.Is(degradedErr, store.ErrNotFound) {
			return reconciler.block(ctx, state.GatewayBlocked, "TARGET_DEGRADED_VALIDATION_FAILED", degradedErr)
		}
	}
	if desired.PathState == state.PathActive && desired.ActivePathID != "" && observed.ActivePathID == desired.ActivePathID && observed.ActiveNodeID == desired.ActiveNodeID {
		candidate, err := reconciler.Inventory.FreshNodeCandidate(ctx, desired.ActivePathID, desired.ActiveNodeID)
		if err == nil {
			return Result{Action: "NO_CHANGE", Candidate: candidate}, nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return reconciler.block(ctx, state.GatewayBlocked, "ACTIVE_PATH_VALIDATION_FAILED", err)
		}
	}
	var candidate Candidate
	if desired.PathState == state.PathVerifying && desired.ActivePathID != "" {
		candidate, err = reconciler.Inventory.FreshNodeCandidate(ctx, desired.ActivePathID, desired.ActiveNodeID)
	}
	if candidate.PathID == "" || err != nil {
		candidate, err = reconciler.Inventory.BestFreshCandidate(ctx)
	}
	if errors.Is(err, store.ErrNotFound) {
		return reconciler.block(ctx, state.GatewayNoWorkingSubscription, "NO_FRESH_QUALIFIED_PATH", nil)
	}
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "PATH_INVENTORY_FAILED", err)
	}
	return reconciler.activate(ctx, candidate)
}

func (reconciler *Reconciler) reconcileUnified(ctx context.Context, observed Observed, desired state.Snapshot, hasTargets bool) (Result, error) {
	if desired.PolicyTransitionActive() {
		return reconciler.reconcileUnifiedPolicyTransition(ctx, observed, desired, hasTargets)
	}
	if !hasTargets {
		return reconciler.block(ctx, state.GatewayNoBypassTargets, "NO_BYPASS_TARGETS", nil)
	}
	policy, err := reconciler.AccessPolicy.GetPolicy(ctx)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_POLICY_UNAVAILABLE", err)
	}
	runtimeState, err := reconciler.AccessPolicy.GetSelectionRuntime(ctx)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_SELECTION_RUNTIME_UNAVAILABLE", err)
	}
	items, err := reconciler.AccessPaths.Candidates(ctx, runtimeState.TemporaryDirectOnly)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_CANDIDATE_INVENTORY_FAILED", err)
	}
	currentKey := activeCandidateKey(desired)
	currentHealthy := false
	hardFailure := false
	filtered := make([]accesspolicy.Candidate, 0, len(items))
	for _, item := range items {
		if item.MethodKind == accesspolicy.MethodSubscription && (!observed.MihomoReady || !observed.TUNReady) {
			continue
		}
		filtered = append(filtered, item)
		if item.Key == currentKey {
			currentHealthy = observedCandidateMatches(observed, desired, item)
		}
	}
	if currentKey != "" && (desired.PathState == state.PathVerifying ||
		desired.PathState == state.PathActive && !observedRuntimeMatches(observed, desired)) {
		hardFailure = true
	}
	decision, err := accesspolicy.Rank(filtered, currentKey)
	if errors.Is(err, accesspolicy.ErrNoCandidate) {
		return reconciler.block(ctx, state.GatewayNoWorkingSubscription, "NO_FRESH_ACCESS_METHOD", nil)
	}
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_RANKING_FAILED", err)
	}
	transition, err := accesspolicy.EvaluateTransition(accesspolicy.TransitionInput{
		CurrentKey: currentKey, ProposedKey: decision.Candidate.Key,
		CurrentHealthy: currentHealthy, HardFailure: hardFailure,
		Policy: policy, Runtime: runtimeState, Now: reconciler.now(),
	})
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_TRANSITION_FAILED", err)
	}
	if transition.TrackPending {
		if err := reconciler.AccessPolicy.TrackPendingCandidate(ctx, decision.Candidate.Key); err != nil {
			return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_PENDING_STATE_FAILED", err)
		}
		return Result{Action: transition.Reason, Candidate: candidateFromAccess(decision.Candidate)}, nil
	}
	if transition.ClearPending {
		if err := reconciler.AccessPolicy.ClearPendingCandidate(ctx); err != nil {
			return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_PENDING_CLEAR_FAILED", err)
		}
	}
	if decision.Candidate.Key == currentKey && currentHealthy {
		return Result{Action: "NO_CHANGE", Candidate: candidateFromAccess(decision.Candidate)}, nil
	}
	if !transition.Allow {
		return Result{Action: transition.Reason, Candidate: candidateFromAccess(decision.Candidate)}, nil
	}
	result, err := reconciler.activate(ctx, candidateFromAccess(decision.Candidate))
	if err != nil {
		return result, err
	}
	if err := reconciler.AccessPolicy.MarkSwitched(ctx, transition.Reason); err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_SWITCH_RECORD_FAILED", err)
	}
	result.Action = "ACCESS_METHOD_ACTIVATED"
	return result, nil
}

func (reconciler *Reconciler) reconcileUnifiedPolicyTransition(ctx context.Context, observed Observed, desired state.Snapshot, hasTargets bool) (Result, error) {
	deadline, err := time.Parse(time.RFC3339Nano, desired.PolicyTransitionDeadline)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "POLICY_DEADLINE_INVALID", err)
	}
	expired := !reconciler.now().Before(deadline)
	if !observedRuntimeMatches(observed, desired) {
		return reconciler.block(ctx, state.GatewayBlocked, "POLICY_ACTIVE_TUPLE_LOST", nil)
	}
	if !hasTargets {
		if !expired {
			return Result{Action: "POLICY_VERIFICATION_PENDING"}, nil
		}
		return reconciler.block(ctx, state.GatewayNoBypassTargets, "NO_BYPASS_TARGETS_AFTER_POLICY_GRACE", nil)
	}
	runtimeState, err := reconciler.AccessPolicy.GetSelectionRuntime(ctx)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_SELECTION_RUNTIME_UNAVAILABLE", err)
	}
	items, err := reconciler.AccessPaths.Candidates(ctx, runtimeState.TemporaryDirectOnly)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_CANDIDATE_INVENTORY_FAILED", err)
	}
	currentKey := activeCandidateKey(desired)
	eligible := make([]accesspolicy.Candidate, 0, len(items))
	for _, item := range items {
		if item.MethodKind == accesspolicy.MethodSubscription && (!observed.MihomoReady || !observed.TUNReady) {
			continue
		}
		eligible = append(eligible, item)
		if item.Key == currentKey && item.MethodKind == accesspolicy.MethodSubscription && item.PolicyGeneration == desired.PolicyTransitionGeneration {
			if _, _, err := reconciler.State.FinishPolicyVerification(ctx, desired.PolicyTransitionGeneration); err != nil {
				return reconciler.block(ctx, state.GatewayBlocked, "POLICY_VERIFICATION_COMMIT_FAILED", err)
			}
			return Result{Action: "POLICY_VERIFIED", Candidate: candidateFromAccess(item)}, nil
		}
	}
	decision, rankErr := accesspolicy.Rank(eligible, currentKey)
	if rankErr == nil {
		result, activateErr := reconciler.activate(ctx, candidateFromAccess(decision.Candidate))
		if activateErr != nil {
			return result, activateErr
		}
		if err := reconciler.AccessPolicy.MarkSwitched(ctx, "POLICY_REPLACEMENT"); err != nil {
			return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_SWITCH_RECORD_FAILED", err)
		}
		result.Action = "ACCESS_METHOD_ACTIVATED"
		return result, nil
	}
	if !errors.Is(rankErr, accesspolicy.ErrNoCandidate) {
		return reconciler.block(ctx, state.GatewayBlocked, "ACCESS_RANKING_FAILED", rankErr)
	}
	if !expired {
		return Result{Action: "POLICY_VERIFICATION_PENDING"}, nil
	}
	return reconciler.block(ctx, state.GatewayNoWorkingSubscription, "POLICY_GRACE_EXPIRED", nil)
}

func (reconciler *Reconciler) now() time.Time {
	if reconciler.Now != nil {
		return reconciler.Now().UTC()
	}
	return time.Now().UTC()
}

func activeCandidateKey(snapshot state.Snapshot) string {
	switch snapshot.ActiveMethodKind {
	case accesspolicy.MethodDirect:
		return snapshot.ActiveDirectPathID
	case accesspolicy.MethodSubscription:
		if snapshot.ActivePathID != "" && snapshot.ActiveNodeID != "" {
			return snapshot.ActivePathID + ":" + snapshot.ActiveNodeID
		}
	}
	return ""
}

func observedRuntimeMatches(observed Observed, snapshot state.Snapshot) bool {
	if snapshot.PathState != state.PathActive || observed.MethodKind != snapshot.ActiveMethodKind {
		return false
	}
	switch snapshot.ActiveMethodKind {
	case accesspolicy.MethodDirect:
		return observed.ActiveDirectPathID == snapshot.ActiveDirectPathID
	case accesspolicy.MethodSubscription:
		return observed.ActivePathID == snapshot.ActivePathID && observed.ActiveNodeID == snapshot.ActiveNodeID
	default:
		return false
	}
}

func observedCandidateMatches(observed Observed, snapshot state.Snapshot, candidate accesspolicy.Candidate) bool {
	return observedRuntimeMatches(observed, snapshot) && candidate.Key == activeCandidateKey(snapshot)
}

func candidateFromAccess(candidate accesspolicy.Candidate) Candidate {
	return Candidate{
		Key: candidate.Key, MethodID: candidate.MethodID, MethodKind: candidate.MethodKind,
		QualityClass: candidate.Quality, PathID: candidate.PathID, ModemID: candidate.ModemID,
		SubscriptionID: candidate.SubscriptionID, NodeID: candidate.NodeID,
		PolicyGeneration: candidate.PolicyGeneration, RouteGeneration: candidate.RouteGeneration,
	}
}

// ActivateExact performs a user-requested activation only after the exact
// path/node tuple has fresh BYPASS_QUALIFIED evidence in the current policy
// and route generations. Invalid, failed, or stale requests leave the current
// active path untouched.
func (reconciler *Reconciler) ActivateExact(ctx context.Context, pathID, nodeID string) (Result, error) {
	reconciler.mutex.Lock()
	defer reconciler.mutex.Unlock()
	if reconciler.Observer == nil || reconciler.Inventory == nil || reconciler.State == nil || reconciler.Actuator == nil {
		return Result{}, errors.New("complete reconciler dependencies are required")
	}
	if strings.TrimSpace(pathID) == "" || strings.TrimSpace(nodeID) == "" {
		return Result{}, errors.New("path and node ids are required for manual activation")
	}
	hasTargets, err := reconciler.Inventory.HasRequiredTargets(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("read target inventory before manual activation: %w", err)
	}
	if !hasTargets {
		return Result{}, errors.New("manual activation requires at least one enabled required target")
	}
	candidate, err := reconciler.Inventory.FreshNodeCandidate(ctx, pathID, nodeID)
	if err != nil {
		return Result{}, err
	}
	observed, err := reconciler.Observer.Observe(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("observe data plane before manual activation: %w", err)
	}
	if !observed.FirewallReady || !observed.MihomoReady || !observed.TUNReady {
		return Result{}, errors.New("manual activation is unavailable until firewall, Mihomo, and TUN are ready")
	}
	desired, err := reconciler.State.Get(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("read runtime before manual activation: %w", err)
	}
	if desired.PathState == state.PathActive && desired.ActivePathID == pathID && desired.ActiveNodeID == nodeID && observed.ActivePathID == pathID && observed.ActiveNodeID == nodeID {
		return Result{Action: "NO_CHANGE", Candidate: candidate}, nil
	}
	if err := reconciler.State.AppendEvent(ctx, state.EventInput{
		Severity: "INFO", Type: "MANUAL_PATH_ACTIVATION_REQUESTED",
		ModemID: candidate.ModemID, SubscriptionID: candidate.SubscriptionID,
		PathID: candidate.PathID, Details: map[string]any{
			"node_id": candidate.NodeID, "policy_generation": candidate.PolicyGeneration,
			"route_generation": candidate.RouteGeneration,
		},
	}); err != nil {
		return Result{}, fmt.Errorf("audit manual activation request: %w", err)
	}
	return reconciler.activate(ctx, candidate)
}

func (reconciler *Reconciler) reconcilePolicyTransition(ctx context.Context, observed Observed, desired state.Snapshot, hasTargets bool) (Result, error) {
	deadline, err := time.Parse(time.RFC3339Nano, desired.PolicyTransitionDeadline)
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "POLICY_DEADLINE_INVALID", err)
	}
	now := time.Now
	if reconciler.Now != nil {
		now = reconciler.Now
	}
	expired := !now().UTC().Before(deadline)
	if observed.ActivePathID != desired.ActivePathID || observed.ActiveNodeID != desired.ActiveNodeID {
		return reconciler.block(ctx, state.GatewayBlocked, "POLICY_ACTIVE_TUPLE_LOST", nil)
	}
	if !hasTargets {
		if !expired {
			return Result{Action: "POLICY_VERIFICATION_PENDING"}, nil
		}
		return reconciler.block(ctx, state.GatewayNoBypassTargets, "NO_BYPASS_TARGETS_AFTER_POLICY_GRACE", nil)
	}
	active, activeErr := reconciler.Inventory.FreshNodeCandidate(ctx, desired.ActivePathID, desired.ActiveNodeID)
	if activeErr == nil && active.PolicyGeneration == desired.PolicyTransitionGeneration {
		if _, _, err := reconciler.State.FinishPolicyVerification(ctx, desired.PolicyTransitionGeneration); err != nil {
			if errors.Is(err, state.ErrPolicyGraceExpired) {
				return reconciler.block(ctx, state.GatewayNoWorkingSubscription, "POLICY_GRACE_EXPIRED", nil)
			}
			return reconciler.block(ctx, state.GatewayBlocked, "POLICY_VERIFICATION_COMMIT_FAILED", err)
		}
		active.ConfigGeneration = desired.ConfigGeneration
		return Result{Action: "POLICY_VERIFIED", Candidate: active}, nil
	}
	if activeErr != nil && !errors.Is(activeErr, store.ErrNotFound) {
		return reconciler.block(ctx, state.GatewayBlocked, "ACTIVE_POLICY_INVENTORY_FAILED", activeErr)
	}
	candidate, err := reconciler.Inventory.BestFreshCandidate(ctx)
	if err == nil {
		return reconciler.activate(ctx, candidate)
	}
	if !errors.Is(err, store.ErrNotFound) {
		return reconciler.block(ctx, state.GatewayBlocked, "PATH_INVENTORY_FAILED", err)
	}
	if !expired {
		return Result{Action: "POLICY_VERIFICATION_PENDING"}, nil
	}
	return reconciler.block(ctx, state.GatewayNoWorkingSubscription, "POLICY_GRACE_EXPIRED", nil)
}

func (reconciler *Reconciler) activate(ctx context.Context, candidate Candidate) (Result, error) {
	var intent state.Snapshot
	var err error
	if candidate.MethodKind == accesspolicy.MethodDirect {
		intent, _, err = reconciler.State.BeginDirectActivation(ctx, candidate.PathID, candidate.PolicyGeneration, candidate.RouteGeneration)
	} else {
		intent, _, err = reconciler.State.BeginNodeActivation(ctx, candidate.PathID, candidate.NodeID, candidate.PolicyGeneration, candidate.RouteGeneration)
	}
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACTIVATION_INTENT_REJECTED", err)
	}
	candidate.ConfigGeneration = intent.ConfigGeneration
	if err := reconciler.Actuator.Activate(ctx, candidate); err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "PATH_ACTIVATION_FAILED", err)
	}
	if candidate.MethodKind == accesspolicy.MethodDirect {
		_, _, err = reconciler.State.FinishDirectActivation(ctx, candidate.PathID, candidate.PolicyGeneration, candidate.RouteGeneration)
	} else {
		_, _, err = reconciler.State.FinishNodeActivation(ctx, candidate.PathID, candidate.NodeID, candidate.PolicyGeneration, candidate.RouteGeneration)
	}
	if err != nil {
		return reconciler.block(ctx, state.GatewayBlocked, "ACTIVATION_COMMIT_REJECTED", err)
	}
	return Result{Action: "PATH_ACTIVATED", Candidate: candidate}, nil
}

func (reconciler *Reconciler) block(ctx context.Context, gatewayState, reason string, cause error) (Result, error) {
	actuatorErr := reconciler.Actuator.Block(ctx, reason)
	_, _, stateErr := reconciler.State.Block(ctx, gatewayState, reason)
	if cause != nil || actuatorErr != nil || stateErr != nil {
		return Result{Action: "PATH_BLOCKED"}, errors.Join(cause, actuatorErr, stateErr)
	}
	return Result{Action: "PATH_BLOCKED"}, nil
}

type SQLiteInventory struct {
	Database *sql.DB
	Now      func() time.Time
}

func (inventory SQLiteInventory) HasRequiredTargets(ctx context.Context) (bool, error) {
	var count int
	if err := inventory.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM bypass_probe_targets WHERE enabled=1 AND required=1").Scan(&count); err != nil {
		return false, fmt.Errorf("count required bypass targets: %w", err)
	}
	return count > 0, nil
}

func (inventory SQLiteInventory) HasReadyModems(ctx context.Context) (bool, error) {
	var count int
	if err := inventory.Database.QueryRowContext(ctx, "SELECT COUNT(*) FROM modems WHERE enabled=1 AND state='MODEM_READY'").Scan(&count); err != nil {
		return false, fmt.Errorf("count ready modems: %w", err)
	}
	return count > 0, nil
}

func (inventory SQLiteInventory) FreshCandidate(ctx context.Context, pathID string) (Candidate, error) {
	return inventory.readCandidate(ctx, " AND p.id=?", pathID)
}

func (inventory SQLiteInventory) FreshNodeCandidate(ctx context.Context, pathID, nodeID string) (Candidate, error) {
	if strings.TrimSpace(pathID) == "" || strings.TrimSpace(nodeID) == "" {
		return Candidate{}, errors.New("path and node ids are required")
	}
	now := time.Now
	if inventory.Now != nil {
		now = inventory.Now
	}
	formattedNow := now().UTC().Format(time.RFC3339Nano)
	var candidate Candidate
	err := inventory.Database.QueryRowContext(ctx, `
SELECT p.id, p.modem_id, p.subscription_id, pn.node_id,
       p.policy_generation, p.route_generation
FROM subscription_modem_paths AS p
JOIN modems AS m ON m.id=p.modem_id
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=?
JOIN nodes AS n ON n.id=pn.node_id AND n.enabled=1
JOIN subscription_versions AS v ON v.id=n.version_id AND v.id=s.active_version_id
WHERE p.id=? AND p.state='QUALIFIED' AND p.expires_at>?
  AND m.enabled=1 AND m.state='MODEM_READY' AND s.enabled=1
  AND pn.qualification_state='BYPASS_QUALIFIED'
  AND pn.qualification_generation=p.policy_generation
  AND pn.route_generation=p.route_generation AND pn.qualification_expires_at>?`,
		nodeID, pathID, formattedNow, formattedNow).Scan(
		&candidate.PathID, &candidate.ModemID, &candidate.SubscriptionID,
		&candidate.NodeID, &candidate.PolicyGeneration, &candidate.RouteGeneration,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Candidate{}, store.ErrNotFound
	}
	if err != nil {
		return Candidate{}, fmt.Errorf("read fresh exact node candidate: %w", err)
	}
	return candidate, nil
}

func (inventory SQLiteInventory) TargetDegradedCandidate(ctx context.Context, pathID, nodeID string) (Candidate, error) {
	if strings.TrimSpace(pathID) == "" || strings.TrimSpace(nodeID) == "" {
		return Candidate{}, errors.New("path and node ids are required")
	}
	now := time.Now
	if inventory.Now != nil {
		now = inventory.Now
	}
	formattedNow := now().UTC().Format(time.RFC3339Nano)
	var candidate Candidate
	err := inventory.Database.QueryRowContext(ctx, `
SELECT p.id, p.modem_id, p.subscription_id, pn.node_id,
       p.policy_generation, p.route_generation
FROM subscription_modem_paths AS p
JOIN modems AS m ON m.id=p.modem_id
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=?
JOIN nodes AS n ON n.id=pn.node_id AND n.enabled=1
JOIN subscription_versions AS v ON v.id=n.version_id AND v.id=s.active_version_id
WHERE p.id=? AND p.state='DEGRADED' AND p.transport_state='PASSED'
  AND p.selected_node_id=pn.node_id AND p.expires_at>?
  AND m.enabled=1 AND m.state='MODEM_READY' AND s.enabled=1
  AND pn.qualification_state='BYPASS_FAILED'
  AND pn.qualification_generation=p.policy_generation
  AND pn.route_generation=p.route_generation AND pn.qualification_expires_at>?
  AND EXISTS (
      SELECT 1
      FROM bypass_probe_targets AS t
      JOIN path_node_target_results AS r
        ON r.path_id=p.id AND r.node_id=pn.node_id AND r.target_id=t.id
        AND r.policy_generation=p.policy_generation
        AND r.route_generation=p.route_generation AND r.expires_at>?
      WHERE t.enabled=1 AND t.required=1 AND t.state='TARGET_SUSPECT' AND r.state<>'PASSED'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM bypass_probe_targets AS t
      LEFT JOIN path_node_target_results AS r
        ON r.path_id=p.id AND r.node_id=pn.node_id AND r.target_id=t.id
        AND r.policy_generation=p.policy_generation
        AND r.route_generation=p.route_generation AND r.expires_at>?
      WHERE t.enabled=1 AND t.required=1
        AND (r.state IS NULL OR (r.state<>'PASSED' AND t.state<>'TARGET_SUSPECT'))
  )`, nodeID, pathID, formattedNow, formattedNow, formattedNow, formattedNow).Scan(
		&candidate.PathID, &candidate.ModemID, &candidate.SubscriptionID,
		&candidate.NodeID, &candidate.PolicyGeneration, &candidate.RouteGeneration,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Candidate{}, store.ErrNotFound
	}
	if err != nil {
		return Candidate{}, fmt.Errorf("read target-degraded exact candidate: %w", err)
	}
	return candidate, nil
}

func (inventory SQLiteInventory) BestFreshCandidate(ctx context.Context) (Candidate, error) {
	return inventory.readCandidate(ctx, " ORDER BY m.priority, s.priority, p.latency_ms, p.id LIMIT 1")
}

func (inventory SQLiteInventory) readCandidate(ctx context.Context, suffix string, args ...any) (Candidate, error) {
	now := time.Now
	if inventory.Now != nil {
		now = inventory.Now
	}
	query := `
SELECT p.id, p.modem_id, p.subscription_id, p.selected_node_id,
       p.policy_generation, p.route_generation
FROM subscription_modem_paths AS p
JOIN modems AS m ON m.id=p.modem_id
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN nodes AS n ON n.id=p.selected_node_id
JOIN subscription_versions AS v ON v.id=n.version_id AND v.id=s.active_version_id
JOIN path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=p.selected_node_id
WHERE p.state='QUALIFIED' AND p.expires_at>? AND m.enabled=1 AND m.state='MODEM_READY'
  AND s.enabled=1 AND pn.qualification_state='BYPASS_QUALIFIED'
  AND pn.qualification_generation=p.policy_generation
  AND pn.route_generation=p.route_generation AND pn.qualification_expires_at>?`
	formattedNow := now().UTC().Format(time.RFC3339Nano)
	queryArgs := []any{formattedNow, formattedNow}
	queryArgs = append(queryArgs, args...)
	var candidate Candidate
	err := inventory.Database.QueryRowContext(ctx, query+suffix, queryArgs...).Scan(&candidate.PathID, &candidate.ModemID, &candidate.SubscriptionID, &candidate.NodeID, &candidate.PolicyGeneration, &candidate.RouteGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return Candidate{}, store.ErrNotFound
	}
	if err != nil {
		return Candidate{}, fmt.Errorf("read fresh path candidate: %w", err)
	}
	return candidate, nil
}
