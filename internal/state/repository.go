// Package state persists desired runtime state and its audit events.
package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

const (
	GatewayBooting               = "BOOTING"
	GatewayAllUplinksOffline     = "ALL_UPLINKS_OFFLINE"
	GatewayAllModemsOffline      = GatewayAllUplinksOffline // Deprecated compatibility alias.
	GatewayNoBypassTargets       = "NO_BYPASS_TARGETS"
	GatewayNoWorkingSubscription = "NO_WORKING_SUBSCRIPTION"
	GatewayVerifying             = "VERIFYING"
	GatewayVerifyingPolicy       = "VERIFYING_POLICY"
	GatewayDegradedTarget        = "DEGRADED_TARGET"
	GatewayActive                = "ACTIVE"
	GatewayDegraded              = "DEGRADED"
	GatewaySwitching             = "SWITCHING"
	GatewayBlocked               = "BLOCKED"

	PathBlocked   = "PATH_BLOCKED"
	PathVerifying = "PATH_VERIFYING"
	PathActive    = "PATH_ACTIVE"
)

var ErrPolicyGraceExpired = errors.New("policy verification grace period expired")

type Repository struct {
	database *sql.DB
	now      func() time.Time
}

type Snapshot struct {
	GatewayState               string
	PathState                  string
	ActiveUplinkID             string
	ActiveModemID              string
	ActivePathID               string
	ActiveDirectPathID         string
	ManagementUplinkID         string
	ManagementModemID          string
	ActiveSubscriptionID       string
	ActiveNodeID               string
	ActiveMethodID             string
	ActiveMethodKind           string
	ActiveQualityClass         string
	ConfigGeneration           int64
	PolicyTransitionGeneration int64
	PolicyTransitionStartedAt  string
	PolicyTransitionDeadline   string
	UpdatedAt                  string
}

func (snapshot Snapshot) PolicyTransitionActive() bool {
	return snapshot.GatewayState == GatewayVerifyingPolicy && snapshot.PathState == PathActive &&
		snapshot.PolicyTransitionGeneration > 0 && snapshot.PolicyTransitionStartedAt != "" && snapshot.PolicyTransitionDeadline != "" &&
		snapshot.ActiveUplinkID != "" && snapshot.ActivePathID != "" && snapshot.ActiveDirectPathID == "" &&
		snapshot.ActiveSubscriptionID != "" && snapshot.ActiveNodeID != "" && snapshot.ActiveMethodKind == "SUBSCRIPTION"
}

type Event struct {
	ID             int64
	OccurredAt     string
	Severity       string
	Type           string
	UplinkID       string
	ModemID        string
	SubscriptionID string
	PathID         string
	DetailsJSON    string
}

type EventInput struct {
	Severity       string
	Type           string
	UplinkID       string
	ModemID        string
	SubscriptionID string
	PathID         string
	Details        map[string]any
}

func NewRepository(database *sql.DB) *Repository {
	return &Repository{database: database, now: time.Now}
}

func (repository *Repository) Get(ctx context.Context) (Snapshot, error) {
	return scanSnapshot(repository.database.QueryRowContext(ctx, runtimeSelect))
}

// PrepareStartupRecovery preserves one previously active exact tuple while
// the boot firewall remains blocked. It accepts only a currently enabled LKG
// method with an unchanged uplink route generation. Fresh qualification is
// still required by Begin/Finish activation; this method merely records the
// boot-scoped verifying intent and schedules an immediate full background
// check after the lightweight recovery succeeds.
func (repository *Repository) PrepareStartupRecovery(ctx context.Context) (Snapshot, bool, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin startup recovery intent: %w", err)
	}
	defer transaction.Rollback()
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if current.PathState != PathActive || current.PolicyTransitionGeneration != 0 || current.PolicyTransitionStartedAt != "" || current.PolicyTransitionDeadline != "" {
		return Snapshot{}, false, store.ErrNotFound
	}
	switch current.ActiveMethodKind {
	case "SUBSCRIPTION":
		if (current.ActiveQualityClass != "FULL" && current.ActiveQualityClass != "LIMITED") || current.ActivePathID == "" || current.ActiveDirectPathID != "" || current.ActiveUplinkID == "" || current.ActiveSubscriptionID == "" || current.ActiveNodeID == "" || current.ActiveMethodID == "" {
			return Snapshot{}, false, store.ErrNotFound
		}
		err = transaction.QueryRowContext(ctx, `
SELECT 1
FROM subscription_uplink_paths AS p
JOIN uplinks AS u ON u.id=p.uplink_id
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN subscription_versions AS v ON v.id=s.active_version_id AND v.state='LKG'
JOIN nodes AS n ON n.id=? AND n.version_id=v.id
JOIN access_methods AS a ON a.id=? AND a.kind='SUBSCRIPTION' AND a.subscription_id=s.id
WHERE p.id=? AND p.uplink_id=? AND p.subscription_id=?
  AND p.route_generation=u.route_generation
  AND p.policy_generation=COALESCE(CAST((SELECT value_json FROM settings WHERE key='next_policy_generation') AS INTEGER)-1, 0)
  AND a.enabled=1 AND s.enabled=1 AND u.enabled=1 AND u.state='UPLINK_READY'
  AND n.enabled=1 AND n.selection_override<>'exclude'`,
			current.ActiveNodeID, current.ActiveMethodID, current.ActivePathID,
			current.ActiveUplinkID, current.ActiveSubscriptionID).Scan(new(int))
	case "DIRECT":
		if (current.ActiveQualityClass != "FULL" && current.ActiveQualityClass != "LIMITED" && current.ActiveQualityClass != "WHITELIST_ONLY") || current.ActiveDirectPathID == "" || current.ActivePathID != "" || current.ActiveUplinkID == "" || current.ActiveSubscriptionID != "" || current.ActiveNodeID != "" || current.ActiveMethodID == "" {
			return Snapshot{}, false, store.ErrNotFound
		}
		err = transaction.QueryRowContext(ctx, `
SELECT 1
FROM direct_uplink_paths AS p
JOIN uplinks AS u ON u.id=p.uplink_id
JOIN access_methods AS a ON a.id=? AND a.kind='DIRECT'
WHERE p.id=? AND p.uplink_id=? AND p.route_generation=u.route_generation
  AND p.policy_generation=COALESCE(CAST((SELECT value_json FROM settings WHERE key='next_policy_generation') AS INTEGER)-1, 0)
  AND a.enabled=1 AND u.enabled=1 AND u.state='UPLINK_READY'`,
			current.ActiveMethodID, current.ActiveDirectPathID, current.ActiveUplinkID).Scan(new(int))
	default:
		return Snapshot{}, false, store.ErrNotFound
	}
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, store.ErrNotFound
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("validate startup recovery tuple: %w", err)
	}
	nowTime := repository.now().UTC()
	now := nowTime.Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state=?, path_state=?, config_generation=config_generation+1,
    policy_transition_generation=NULL, policy_transition_started_at=NULL,
    policy_transition_deadline=NULL, updated_at=?
WHERE singleton_id=1`, GatewayVerifying, PathVerifying, now); err != nil {
		return Snapshot{}, false, fmt.Errorf("record startup recovery intent: %w", err)
	}
	if current.ActiveMethodKind == "SUBSCRIPTION" {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO path_health_runtime(path_id,probe_class,next_probe_at,last_result,updated_at)
VALUES(?, 'ACTIVE', ?, 'UNKNOWN', ?)
ON CONFLICT(path_id) DO UPDATE SET
    probe_class='ACTIVE', next_probe_at=excluded.next_probe_at,
    last_probe_at=NULL, last_result='UNKNOWN', consecutive_successes=0,
    consecutive_failures=0, deferred_reason=NULL, updated_at=excluded.updated_at`,
			current.ActivePathID, now, now); err != nil {
			return Snapshot{}, false, fmt.Errorf("schedule startup VPN requalification: %w", err)
		}
	} else {
		refreshDeadline := nowTime.Add(30 * time.Second).Format(time.RFC3339Nano)
		if _, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET expires_at=CASE
        WHEN expires_at IS NOT NULL AND julianday(expires_at)>julianday(?) THEN ?
        ELSE expires_at
    END,
    updated_at=?
WHERE id=?`, refreshDeadline, refreshDeadline, now, current.ActiveDirectPathID); err != nil {
			return Snapshot{}, false, fmt.Errorf("schedule startup direct requalification: %w", err)
		}
	}
	pathID := current.ActivePathID
	if current.ActiveMethodKind == "DIRECT" {
		pathID = current.ActiveDirectPathID
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{
		Severity: "INFO", Type: "STARTUP_MINIMAL_RECOVERY_PREPARED",
		UplinkID: current.ActiveUplinkID, SubscriptionID: current.ActiveSubscriptionID,
		PathID: pathID, Details: map[string]any{
			"method_kind":   current.ActiveMethodKind,
			"quality_class": current.ActiveQualityClass,
		},
	}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit startup recovery intent: %w", err)
	}
	result, err := repository.Get(ctx)
	return result, true, err
}

// BeginActivation records a resumable desired transition only for a fresh,
// currently-qualified path and selected node.
func (repository *Repository) BeginActivation(ctx context.Context, pathID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	return repository.beginActivation(ctx, pathID, "", expectedPolicyGeneration, expectedRouteGeneration)
}

// BeginNodeActivation records an activation intent for an explicitly selected
// fresh node. It applies the same fail-closed state transition as automatic
// activation and never accepts stale or failed evidence.
func (repository *Repository) BeginNodeActivation(ctx context.Context, pathID, nodeID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	if strings.TrimSpace(nodeID) == "" {
		return Snapshot{}, false, errors.New("node id is required for exact activation")
	}
	return repository.beginActivation(ctx, pathID, nodeID, expectedPolicyGeneration, expectedRouteGeneration)
}

func (repository *Repository) beginActivation(ctx context.Context, pathID, nodeID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin path activation intent: %w", err)
	}
	defer transaction.Rollback()
	nowTime := repository.now().UTC()
	path, err := readFreshPath(ctx, transaction, pathID, nodeID, expectedPolicyGeneration, expectedRouteGeneration, nowTime)
	if err != nil {
		return Snapshot{}, false, err
	}
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if current.PathState == PathVerifying && current.ActivePathID == path.ID && current.ActiveNodeID == path.NodeID {
		return current, false, nil
	}
	now := nowTime.Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state=?, path_state=?, active_uplink_id=?,
    active_modem_id=(SELECT uplink_id FROM hilink_modems WHERE uplink_id=?), active_path_id=?,
    active_direct_path_id=NULL, active_subscription_id=?, active_node_id=?,
    active_method_id=?, active_method_kind='SUBSCRIPTION', active_quality_class=?,
    config_generation=config_generation+1,
    policy_transition_generation=NULL, policy_transition_started_at=NULL,
    policy_transition_deadline=NULL,
    updated_at=?
WHERE singleton_id=1`, GatewayVerifying, PathVerifying, path.UplinkID, path.UplinkID, path.ID,
		path.SubscriptionID, path.NodeID, path.MethodID, path.QualityClass, now)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("record path activation intent: %w", err)
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{Severity: "INFO", Type: "PATH_ACTIVATION_STARTED", UplinkID: path.UplinkID, SubscriptionID: path.SubscriptionID, PathID: path.ID, Details: map[string]any{"node_id": path.NodeID, "policy_generation": expectedPolicyGeneration, "route_generation": expectedRouteGeneration}}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit path activation intent: %w", err)
	}
	result, err := repository.Get(ctx)
	return result, true, err
}

func (repository *Repository) FinishActivation(ctx context.Context, pathID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	return repository.finishActivation(ctx, pathID, "", expectedPolicyGeneration, expectedRouteGeneration)
}

// MarkTargetDegraded changes only the control-plane state for an already
// active exact tuple. The firewall generation and Mihomo selections remain
// untouched; pathmatrix.MarkTargetDegraded must have validated the suspect
// target evidence first while the shared operation lock is held.
func (repository *Repository) MarkTargetDegraded(ctx context.Context, pathID, nodeID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin target-degraded runtime update: %w", err)
	}
	defer transaction.Rollback()
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if current.GatewayState == GatewayDegradedTarget && current.PathState == PathActive && current.ActivePathID == pathID && current.ActiveNodeID == nodeID {
		return current, false, nil
	}
	if current.PathState != PathActive || current.ActivePathID != pathID || current.ActiveNodeID != nodeID {
		return Snapshot{}, false, store.ErrStaleGeneration
	}
	var uplinkID, subscriptionID string
	err = transaction.QueryRowContext(ctx, `
SELECT p.uplink_id, p.subscription_id
FROM subscription_uplink_paths AS p
JOIN uplink_path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=?
WHERE p.id=? AND p.state='DEGRADED' AND p.transport_state='PASSED'
  AND p.selected_node_id=? AND p.policy_generation=? AND p.route_generation=?
  AND pn.qualification_state='BYPASS_FAILED'
  AND pn.qualification_generation=p.policy_generation
  AND pn.route_generation=p.route_generation AND pn.qualification_expires_at>?`,
		nodeID, pathID, nodeID, expectedPolicyGeneration, expectedRouteGeneration,
		repository.now().UTC().Format(time.RFC3339Nano)).Scan(&uplinkID, &subscriptionID)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, store.ErrStaleGeneration
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("validate target-degraded path state: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state='DEGRADED_TARGET', updated_at=?
WHERE singleton_id=1`, now); err != nil {
		return Snapshot{}, false, fmt.Errorf("record target-degraded runtime: %w", err)
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{
		Severity: "WARNING", Type: "ACTIVE_PATH_TARGET_DEGRADED",
		UplinkID: uplinkID, SubscriptionID: subscriptionID, PathID: pathID,
		Details: map[string]any{"node_id": nodeID, "policy_generation": expectedPolicyGeneration, "route_generation": expectedRouteGeneration},
	}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit target-degraded runtime: %w", err)
	}
	result, err := repository.Get(ctx)
	return result, true, err
}

func (repository *Repository) RecoverTargetDegraded(ctx context.Context, pathID, nodeID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin target-degraded recovery: %w", err)
	}
	defer transaction.Rollback()
	nowTime := repository.now().UTC()
	path, err := readFreshPath(ctx, transaction, pathID, nodeID, expectedPolicyGeneration, expectedRouteGeneration, nowTime)
	if err != nil {
		return Snapshot{}, false, err
	}
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if current.GatewayState == GatewayActive && current.PathState == PathActive && current.ActivePathID == pathID && current.ActiveNodeID == nodeID {
		return current, false, nil
	}
	if current.GatewayState != GatewayDegradedTarget || current.PathState != PathActive || current.ActivePathID != pathID || current.ActiveNodeID != nodeID {
		return Snapshot{}, false, store.ErrStaleGeneration
	}
	now := nowTime.Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, "UPDATE runtime_state SET gateway_state='ACTIVE', updated_at=? WHERE singleton_id=1", now); err != nil {
		return Snapshot{}, false, fmt.Errorf("recover target-degraded runtime: %w", err)
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{
		Severity: "INFO", Type: "ACTIVE_PATH_TARGET_RECOVERED",
		UplinkID: path.UplinkID, SubscriptionID: path.SubscriptionID, PathID: path.ID,
		Details: map[string]any{"node_id": path.NodeID},
	}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit target-degraded recovery: %w", err)
	}
	result, err := repository.Get(ctx)
	return result, true, err
}

func (repository *Repository) FinishNodeActivation(ctx context.Context, pathID, nodeID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	if strings.TrimSpace(nodeID) == "" {
		return Snapshot{}, false, errors.New("node id is required for exact activation completion")
	}
	return repository.finishActivation(ctx, pathID, nodeID, expectedPolicyGeneration, expectedRouteGeneration)
}

// BeginDirectActivation records an exact, generation-scoped direct Internet
// intent. The direct path has its own foreign key and can never alias a VPN
// subscription path.
func (repository *Repository) BeginDirectActivation(ctx context.Context, pathID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin direct path activation intent: %w", err)
	}
	defer transaction.Rollback()
	nowTime := repository.now().UTC()
	path, err := readFreshDirectPath(ctx, transaction, pathID, expectedPolicyGeneration, expectedRouteGeneration, nowTime)
	if err != nil {
		return Snapshot{}, false, err
	}
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if current.PathState == PathVerifying && current.ActiveDirectPathID == path.ID && current.ActiveMethodKind == "DIRECT" {
		return current, false, nil
	}
	now := nowTime.Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state=?, path_state=?, active_uplink_id=?,
    active_modem_id=(SELECT uplink_id FROM hilink_modems WHERE uplink_id=?), active_path_id=NULL,
    active_direct_path_id=?, active_subscription_id=NULL, active_node_id=NULL,
    active_method_id=?, active_method_kind='DIRECT', active_quality_class=?,
    config_generation=config_generation+1,
    policy_transition_generation=NULL, policy_transition_started_at=NULL,
    policy_transition_deadline=NULL, updated_at=?
WHERE singleton_id=1`, GatewayVerifying, PathVerifying, path.UplinkID, path.UplinkID, path.ID,
		path.MethodID, path.QualityClass, now)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("record direct path activation intent: %w", err)
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{
		Severity: "INFO", Type: "DIRECT_PATH_ACTIVATION_STARTED", UplinkID: path.UplinkID,
		PathID: path.ID, Details: map[string]any{
			"quality_class": path.QualityClass, "policy_generation": expectedPolicyGeneration,
			"route_generation": expectedRouteGeneration,
		},
	}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit direct path activation intent: %w", err)
	}
	result, err := repository.Get(ctx)
	return result, true, err
}

func (repository *Repository) FinishDirectActivation(ctx context.Context, pathID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin direct path activation completion: %w", err)
	}
	defer transaction.Rollback()
	nowTime := repository.now().UTC()
	path, err := readFreshDirectPath(ctx, transaction, pathID, expectedPolicyGeneration, expectedRouteGeneration, nowTime)
	if err != nil {
		return Snapshot{}, false, err
	}
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if current.PathState == PathActive && current.ActiveDirectPathID == path.ID && current.ActiveMethodKind == "DIRECT" {
		return current, false, nil
	}
	if current.PathState != PathVerifying || current.ActiveDirectPathID != path.ID || current.ActiveMethodKind != "DIRECT" {
		return Snapshot{}, false, store.ErrStaleGeneration
	}
	now := nowTime.Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state=?, path_state=?, active_quality_class=?,
    policy_transition_generation=NULL, policy_transition_started_at=NULL,
    policy_transition_deadline=NULL, updated_at=?
WHERE singleton_id=1`, GatewayActive, PathActive, path.QualityClass, now)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("record active direct path: %w", err)
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{
		Severity: "INFO", Type: "DIRECT_PATH_ACTIVATED", UplinkID: path.UplinkID,
		PathID: path.ID, Details: map[string]any{"quality_class": path.QualityClass},
	}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit active direct path: %w", err)
	}
	result, err := repository.Get(ctx)
	return result, true, err
}

func (repository *Repository) finishActivation(ctx context.Context, pathID, nodeID string, expectedPolicyGeneration, expectedRouteGeneration int64) (Snapshot, bool, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin path activation completion: %w", err)
	}
	defer transaction.Rollback()
	nowTime := repository.now().UTC()
	path, err := readFreshPath(ctx, transaction, pathID, nodeID, expectedPolicyGeneration, expectedRouteGeneration, nowTime)
	if err != nil {
		return Snapshot{}, false, err
	}
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if current.PathState == PathActive && current.ActivePathID == path.ID && current.ActiveNodeID == path.NodeID {
		return current, false, nil
	}
	if current.PathState != PathVerifying || current.ActivePathID != path.ID || current.ActiveNodeID != path.NodeID {
		return Snapshot{}, false, store.ErrStaleGeneration
	}
	now := nowTime.Format(time.RFC3339Nano)
	// Finish commits the generation allocated by BeginActivation. Incrementing
	// here would make the already-applied firewall generation stale immediately.
	_, err = transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state=?, path_state=?, policy_transition_generation=NULL,
    policy_transition_started_at=NULL, policy_transition_deadline=NULL, updated_at=?
WHERE singleton_id=1`, GatewayActive, PathActive, now)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("record active path: %w", err)
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{Severity: "INFO", Type: "PATH_ACTIVATED", UplinkID: path.UplinkID, SubscriptionID: path.SubscriptionID, PathID: path.ID, Details: map[string]any{"node_id": path.NodeID}}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit active path: %w", err)
	}
	result, err := repository.Get(ctx)
	return result, true, err
}

// Block clears the complete active tuple. Repeating the same blocked reason is
// idempotent and does not create event spam or a new config generation.
func (repository *Repository) Block(ctx context.Context, gatewayState, reason string) (Snapshot, bool, error) {
	if !validBlockedGatewayState(gatewayState) || strings.TrimSpace(reason) == "" {
		return Snapshot{}, false, errors.New("valid blocked gateway state and reason are required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin runtime block: %w", err)
	}
	defer transaction.Rollback()
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if current.GatewayState == gatewayState && current.PathState == PathBlocked &&
		current.ActiveUplinkID == "" && current.ActiveModemID == "" && current.ActivePathID == "" && current.ActiveDirectPathID == "" &&
		current.ActiveSubscriptionID == "" && current.ActiveNodeID == "" &&
		current.ActiveMethodID == "" && current.ActiveMethodKind == "" && current.ActiveQualityClass == "" {
		return current, false, nil
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state=?, path_state=?, active_uplink_id=NULL, active_modem_id=NULL, active_path_id=NULL,
    active_direct_path_id=NULL, active_subscription_id=NULL, active_node_id=NULL,
    active_method_id=NULL, active_method_kind=NULL, active_quality_class=NULL,
    policy_transition_generation=NULL, policy_transition_started_at=NULL,
    policy_transition_deadline=NULL,
    config_generation=config_generation+1, updated_at=?
WHERE singleton_id=1`, gatewayState, PathBlocked, now)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("record blocked runtime state: %w", err)
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{Severity: "WARNING", Type: "PATH_BLOCKED", Details: map[string]any{"reason": reason, "gateway_state": gatewayState}}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit blocked runtime state: %w", err)
	}
	result, err := repository.Get(ctx)
	return result, true, err
}

// FinishPolicyVerification keeps the already-active data plane and only
// commits the new policy generation after the same active node has fresh,
// generation-scoped evidence. No config/firewall generation is changed.
func (repository *Repository) FinishPolicyVerification(ctx context.Context, expectedGeneration int64) (Snapshot, bool, error) {
	if expectedGeneration <= 0 {
		return Snapshot{}, false, errors.New("positive policy transition generation is required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin policy verification completion: %w", err)
	}
	defer transaction.Rollback()
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if !current.PolicyTransitionActive() || current.PolicyTransitionGeneration != expectedGeneration {
		return Snapshot{}, false, store.ErrStaleGeneration
	}
	deadline, err := time.Parse(time.RFC3339Nano, current.PolicyTransitionDeadline)
	if err != nil {
		return Snapshot{}, false, errors.New("stored policy transition deadline is invalid")
	}
	nowTime := repository.now().UTC()
	if !nowTime.Before(deadline) {
		return Snapshot{}, false, ErrPolicyGraceExpired
	}
	formattedNow := nowTime.Format(time.RFC3339Nano)
	var qualityClass string
	err = transaction.QueryRowContext(ctx, `
SELECT p.quality_class
FROM subscription_uplink_paths AS p
JOIN uplink_path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=p.selected_node_id
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN uplinks AS u ON u.id=p.uplink_id
WHERE p.id=? AND p.uplink_id=? AND p.subscription_id=? AND p.selected_node_id=?
  AND p.policy_generation=? AND p.expires_at>?
  AND ((p.state='QUALIFIED' AND p.quality_class='FULL' AND pn.qualification_state='BYPASS_QUALIFIED')
       OR (p.state='DEGRADED' AND p.quality_class='LIMITED' AND pn.qualification_state='BYPASS_LIMITED'))
  AND pn.qualification_generation=p.policy_generation
  AND pn.route_generation=p.route_generation AND pn.qualification_expires_at>?
  AND s.enabled=1 AND u.enabled=1 AND u.state='UPLINK_READY'`,
		current.ActivePathID, current.ActiveUplinkID, current.ActiveSubscriptionID, current.ActiveNodeID,
		expectedGeneration, formattedNow, formattedNow).Scan(&qualityClass)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, store.ErrStaleGeneration
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("validate active node under new policy: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state=?, active_quality_class=?, policy_transition_generation=NULL,
    policy_transition_started_at=NULL, policy_transition_deadline=NULL, updated_at=?
WHERE singleton_id=1 AND gateway_state=? AND path_state=?
  AND policy_transition_generation=?`,
		GatewayActive, qualityClass, formattedNow, GatewayVerifyingPolicy, PathActive, expectedGeneration)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("finish policy verification: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return Snapshot{}, false, store.ErrStaleGeneration
	}
	if err := appendEventTx(ctx, transaction, formattedNow, EventInput{
		Severity: "INFO", Type: "POLICY_VERIFIED", UplinkID: current.ActiveUplinkID,
		SubscriptionID: current.ActiveSubscriptionID, PathID: current.ActivePathID,
		Details: map[string]any{"node_id": current.ActiveNodeID, "policy_generation": expectedGeneration},
	}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit policy verification: %w", err)
	}
	updated, err := repository.Get(ctx)
	return updated, true, err
}

// RecoverPolicyTransition is called before any normal startup convergence.
// Boot firewall is already fail-closed, so an interrupted grace transaction
// is never resumed from old evidence after process restart.
func (repository *Repository) RecoverPolicyTransition(ctx context.Context) (bool, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin policy transition recovery: %w", err)
	}
	defer transaction.Rollback()
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return false, err
	}
	if !current.PolicyTransitionActive() {
		return false, nil
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state=?, path_state=?, active_uplink_id=NULL, active_modem_id=NULL, active_path_id=NULL,
    active_direct_path_id=NULL, active_subscription_id=NULL, active_node_id=NULL,
    active_method_id=NULL, active_method_kind=NULL, active_quality_class=NULL,
    policy_transition_generation=NULL, policy_transition_started_at=NULL,
    policy_transition_deadline=NULL, config_generation=config_generation+1,
    updated_at=?
WHERE singleton_id=1`, GatewayBlocked, PathBlocked, now)
	if err != nil {
		return false, fmt.Errorf("block interrupted policy transition: %w", err)
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{
		Severity: "WARNING", Type: "POLICY_VERIFICATION_INTERRUPTED",
		UplinkID: current.ActiveUplinkID, SubscriptionID: current.ActiveSubscriptionID, PathID: current.ActivePathID,
		Details: map[string]any{
			"node_id": current.ActiveNodeID, "policy_generation": current.PolicyTransitionGeneration,
			"started_at": current.PolicyTransitionStartedAt, "deadline": current.PolicyTransitionDeadline,
			"reason": "PROCESS_RESTART",
		},
	}); err != nil {
		return false, err
	}
	if err := transaction.Commit(); err != nil {
		return false, fmt.Errorf("commit policy transition recovery: %w", err)
	}
	return true, nil
}

// SetManagementModem is the bounded HiLink compatibility entry point.
func (repository *Repository) SetManagementModem(ctx context.Context, modemID, reason string) (Snapshot, bool, error) {
	return repository.setManagementUplink(ctx, modemID, reason, true)
}

// SetManagementUplink selects any ready canonical uplink for management traffic.
func (repository *Repository) SetManagementUplink(ctx context.Context, uplinkID, reason string) (Snapshot, bool, error) {
	return repository.setManagementUplink(ctx, uplinkID, reason, false)
}

func (repository *Repository) setManagementUplink(ctx context.Context, uplinkID, reason string, requireHiLink bool) (Snapshot, bool, error) {
	if strings.TrimSpace(reason) == "" {
		return Snapshot{}, false, errors.New("management uplink reason is required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("begin management uplink update: %w", err)
	}
	defer transaction.Rollback()
	current, err := scanSnapshot(transaction.QueryRowContext(ctx, runtimeSelect))
	if err != nil {
		return Snapshot{}, false, err
	}
	if current.ManagementUplinkID == uplinkID {
		return current, false, nil
	}
	if uplinkID != "" {
		var count int
		query := "SELECT COUNT(*) FROM uplinks WHERE id=? AND enabled=1 AND state='UPLINK_READY'"
		if requireHiLink {
			query = "SELECT COUNT(*) FROM uplinks AS u JOIN hilink_modems AS h ON h.uplink_id=u.id WHERE u.id=? AND u.enabled=1 AND u.state='UPLINK_READY'"
		}
		if err := transaction.QueryRowContext(ctx, query, uplinkID).Scan(&count); err != nil || count != 1 {
			return Snapshot{}, false, errors.New("management uplink must be enabled and ready")
		}
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
UPDATE runtime_state
SET management_uplink_id=?,
    management_modem_id=(SELECT uplink_id FROM hilink_modems WHERE uplink_id=?),
    updated_at=?
WHERE singleton_id=1`, nullIfEmpty(uplinkID), nullIfEmpty(uplinkID), now); err != nil {
		return Snapshot{}, false, fmt.Errorf("record management uplink: %w", err)
	}
	eventPrefix := "MANAGEMENT_UPLINK"
	if requireHiLink {
		eventPrefix = "MANAGEMENT_MODEM"
	}
	eventType := eventPrefix + "_SELECTED"
	if uplinkID == "" {
		eventType = eventPrefix + "_CLEARED"
	}
	if err := appendEventTx(ctx, transaction, now, EventInput{Severity: "INFO", Type: eventType, UplinkID: uplinkID, Details: map[string]any{"previous_uplink_id": current.ManagementUplinkID, "reason": reason}}); err != nil {
		return Snapshot{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Snapshot{}, false, fmt.Errorf("commit management uplink update: %w", err)
	}
	result, err := repository.Get(ctx)
	return result, true, err
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (repository *Repository) AppendEvent(ctx context.Context, input EventInput) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin event append: %w", err)
	}
	defer transaction.Rollback()
	if err := appendEventTx(ctx, transaction, repository.now().UTC().Format(time.RFC3339Nano), input); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit event append: %w", err)
	}
	return nil
}

func (repository *Repository) ListEvents(ctx context.Context, limit int, beforeID int64) ([]Event, error) {
	if limit <= 0 || limit > 500 || beforeID < 0 {
		return nil, errors.New("event limit must be 1..500 and before id cannot be negative")
	}
	query := `
SELECT id, occurred_at, severity, type, uplink_id, modem_id, subscription_id, path_id, details_json
FROM events`
	var args []any
	if beforeID > 0 {
		query += " WHERE id < ?"
		args = append(args, beforeID)
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := repository.database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()
	var result []Event
	for rows.Next() {
		var event Event
		var uplinkID, modemID, subscriptionID, pathID sql.NullString
		if err := rows.Scan(&event.ID, &event.OccurredAt, &event.Severity, &event.Type, &uplinkID, &modemID, &subscriptionID, &pathID, &event.DetailsJSON); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		event.UplinkID, event.ModemID = uplinkID.String, modemID.String
		event.SubscriptionID, event.PathID = subscriptionID.String, pathID.String
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate events: %w", err)
	}
	return result, nil
}

type freshPath struct {
	ID             string
	UplinkID       string
	SubscriptionID string
	NodeID         string
	MethodID       string
	QualityClass   string
}

func readFreshPath(ctx context.Context, transaction *sql.Tx, pathID, nodeID string, policyGeneration, routeGeneration int64, now time.Time) (freshPath, error) {
	var path freshPath
	err := transaction.QueryRowContext(ctx, `
SELECT p.id, p.uplink_id, p.subscription_id, pn.node_id, a.id, p.quality_class
FROM subscription_uplink_paths AS p
JOIN uplink_path_nodes AS pn ON pn.path_id=p.id
JOIN nodes AS n ON n.id=pn.node_id
JOIN subscription_versions AS v ON v.id=n.version_id
JOIN subscriptions AS s ON s.id=p.subscription_id AND s.active_version_id=v.id
JOIN uplinks AS u ON u.id=p.uplink_id
JOIN access_methods AS a ON a.subscription_id=s.id AND a.kind='SUBSCRIPTION'
WHERE p.id=? AND p.policy_generation=? AND p.route_generation=?
  AND ((?='' AND pn.node_id=p.selected_node_id) OR (?<>'' AND pn.node_id=?))
  AND p.expires_at>?
  AND ((p.state='QUALIFIED' AND p.quality_class='FULL' AND pn.qualification_state='BYPASS_QUALIFIED')
       OR (p.state='DEGRADED' AND p.quality_class='LIMITED' AND pn.qualification_state='BYPASS_LIMITED'))
  AND pn.qualification_generation=p.policy_generation
  AND pn.route_generation=p.route_generation AND pn.qualification_expires_at>?
  AND n.enabled=1 AND s.enabled=1 AND a.enabled=1
  AND u.enabled=1 AND u.state='UPLINK_READY'`, pathID, policyGeneration, routeGeneration, nodeID, nodeID, nodeID, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)).Scan(&path.ID, &path.UplinkID, &path.SubscriptionID, &path.NodeID, &path.MethodID, &path.QualityClass)
	if errors.Is(err, sql.ErrNoRows) {
		return freshPath{}, store.ErrStaleGeneration
	}
	if err != nil {
		return freshPath{}, fmt.Errorf("validate fresh qualified path: %w", err)
	}
	return path, nil
}

type freshDirectPath struct {
	ID           string
	UplinkID     string
	MethodID     string
	QualityClass string
}

func readFreshDirectPath(ctx context.Context, transaction *sql.Tx, pathID string, policyGeneration, routeGeneration int64, now time.Time) (freshDirectPath, error) {
	var path freshDirectPath
	err := transaction.QueryRowContext(ctx, `
SELECT p.id, p.uplink_id, a.id, p.quality_class
FROM direct_uplink_paths AS p
JOIN uplinks AS u ON u.id=p.uplink_id
JOIN access_methods AS a ON a.id='access:direct' AND a.kind='DIRECT'
WHERE p.id=? AND p.policy_generation=? AND p.route_generation=?
  AND p.route_generation=u.route_generation
  AND p.quality_class IN ('FULL', 'LIMITED', 'WHITELIST_ONLY')
  AND p.state IN ('QUALIFIED', 'DEGRADED')
  AND julianday(p.expires_at)>julianday(?)
  AND a.enabled=1 AND u.enabled=1 AND u.state='UPLINK_READY'`,
		pathID, policyGeneration, routeGeneration, now.Format(time.RFC3339Nano)).Scan(
		&path.ID, &path.UplinkID, &path.MethodID, &path.QualityClass,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return freshDirectPath{}, store.ErrStaleGeneration
	}
	if err != nil {
		return freshDirectPath{}, fmt.Errorf("validate fresh direct path: %w", err)
	}
	return path, nil
}

func appendEventTx(ctx context.Context, transaction *sql.Tx, occurredAt string, input EventInput) error {
	if !validSeverity(input.Severity) || strings.TrimSpace(input.Type) == "" || len(input.Type) > 128 {
		return errors.New("valid event severity and type are required")
	}
	if input.Details == nil {
		input.Details = map[string]any{}
	}
	details, err := json.Marshal(input.Details)
	if err != nil {
		return fmt.Errorf("encode event details: %w", err)
	}
	if len(details) > 16*1024 {
		return errors.New("event details exceed 16 KiB")
	}
	uplinkID := input.UplinkID
	if uplinkID == "" {
		uplinkID = input.ModemID
	}
	modemID := input.ModemID
	if modemID == "" && uplinkID != "" {
		err := transaction.QueryRowContext(ctx, "SELECT uplink_id FROM hilink_modems WHERE uplink_id=?", uplinkID).Scan(&modemID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("resolve legacy modem event projection: %w", err)
		}
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, uplink_id, modem_id, subscription_id, path_id, details_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, occurredAt, input.Severity, input.Type, nullString(uplinkID), nullString(modemID), nullString(input.SubscriptionID), nullString(input.PathID), string(details))
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

func validSeverity(value string) bool {
	switch value {
	case "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL":
		return true
	default:
		return false
	}
}

func validBlockedGatewayState(value string) bool {
	switch value {
	case GatewayAllUplinksOffline, GatewayNoBypassTargets, GatewayNoWorkingSubscription, GatewayBlocked:
		return true
	default:
		return false
	}
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

const runtimeSelect = `
SELECT gateway_state, path_state, active_uplink_id, active_modem_id, active_path_id,
       active_direct_path_id, management_uplink_id, management_modem_id, active_subscription_id, active_node_id,
       active_method_id, active_method_kind, active_quality_class,
       config_generation, policy_transition_generation,
       policy_transition_started_at, policy_transition_deadline, updated_at
FROM runtime_state WHERE singleton_id=1`

type scanner interface {
	Scan(...any) error
}

func scanSnapshot(row scanner) (Snapshot, error) {
	var snapshot Snapshot
	var uplinkID, modemID, pathID, directPathID, managementUplinkID, managementModemID, subscriptionID, nodeID sql.NullString
	var methodID, methodKind, qualityClass sql.NullString
	var transitionGeneration sql.NullInt64
	var transitionStartedAt, transitionDeadline sql.NullString
	err := row.Scan(&snapshot.GatewayState, &snapshot.PathState, &uplinkID, &modemID, &pathID, &directPathID,
		&managementUplinkID, &managementModemID, &subscriptionID, &nodeID, &methodID, &methodKind, &qualityClass,
		&snapshot.ConfigGeneration, &transitionGeneration, &transitionStartedAt, &transitionDeadline, &snapshot.UpdatedAt)
	if err != nil {
		return Snapshot{}, fmt.Errorf("scan runtime state: %w", err)
	}
	snapshot.ActiveUplinkID = uplinkID.String
	snapshot.ActiveModemID = modemID.String
	snapshot.ActivePathID = pathID.String
	snapshot.ActiveDirectPathID = directPathID.String
	snapshot.ManagementUplinkID = managementUplinkID.String
	snapshot.ManagementModemID = managementModemID.String
	snapshot.ActiveSubscriptionID = subscriptionID.String
	snapshot.ActiveNodeID = nodeID.String
	snapshot.ActiveMethodID = methodID.String
	snapshot.ActiveMethodKind = methodKind.String
	snapshot.ActiveQualityClass = qualityClass.String
	snapshot.PolicyTransitionGeneration = transitionGeneration.Int64
	snapshot.PolicyTransitionStartedAt = transitionStartedAt.String
	snapshot.PolicyTransitionDeadline = transitionDeadline.String
	return snapshot, nil
}
