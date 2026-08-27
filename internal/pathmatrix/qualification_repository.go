package pathmatrix

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gateway-vpn/internal/store"
)

const (
	NodeBypassQualified = "BYPASS_QUALIFIED"
	NodeBypassLimited   = "BYPASS_LIMITED"
	NodeBypassFailed    = "BYPASS_FAILED"
)

type TargetEvidence struct {
	TargetID   string
	State      string
	LatencyMS  int64
	HTTPStatus int
	ErrorCode  string
}

type NodeEvidence struct {
	NodeID    string
	State     string
	LatencyMS int64
	ErrorCode string
	Targets   []TargetEvidence
}

type QualificationSnapshot struct {
	PathID                   string
	ExpectedPolicyGeneration int64
	ExpectedRouteGeneration  int64
	State                    string
	TransportState           string
	SelectedNodeID           string
	RequiredTargetsPassed    int64
	RequiredTargetsTotal     int64
	OptionalTargetsPassed    int64
	OptionalTargetsTotal     int64
	FunctionalScore          int64
	LatencyMS                int64
	CheckedAt                time.Time
	ExpiresAt                time.Time
	Nodes                    []NodeEvidence
}

type NodeQualificationSnapshot struct {
	PathID                   string
	ExpectedPolicyGeneration int64
	ExpectedRouteGeneration  int64
	CandidateNodes           int64
	RequiredTargetsTotal     int64
	CheckedAt                time.Time
	ExpiresAt                time.Time
	Node                     NodeEvidence
}

// StoreQualification replaces all per-node evidence for a path and updates the
// aggregate cell in the same transaction. A generation mismatch leaves both
// the evidence and aggregate unchanged.
func (repository *Repository) StoreQualification(ctx context.Context, snapshot QualificationSnapshot) error {
	if err := validateQualificationSnapshot(snapshot); err != nil {
		return err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin qualification snapshot: %w", err)
	}
	defer transaction.Rollback()
	var policyGeneration, routeGeneration int64
	var subscriptionID, activeVersionID string
	err = transaction.QueryRowContext(ctx, `
SELECT p.policy_generation, p.route_generation, p.subscription_id, COALESCE(s.active_version_id, '')
FROM subscription_modem_paths AS p
JOIN subscriptions AS s ON s.id=p.subscription_id
WHERE p.id=?`, snapshot.PathID).Scan(&policyGeneration, &routeGeneration, &subscriptionID, &activeVersionID)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read qualification path generation: %w", err)
	}
	if policyGeneration != snapshot.ExpectedPolicyGeneration || routeGeneration != snapshot.ExpectedRouteGeneration {
		return store.ErrStaleGeneration
	}
	if activeVersionID == "" {
		return errors.New("subscription has no active version")
	}
	for _, node := range snapshot.Nodes {
		var valid int
		if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM nodes AS n
JOIN subscription_versions AS v ON v.id=n.version_id
WHERE n.id=? AND v.id=? AND v.subscription_id=?`, node.NodeID, activeVersionID, subscriptionID).Scan(&valid); err != nil {
			return fmt.Errorf("validate qualification node: %w", err)
		}
		if valid != 1 {
			return fmt.Errorf("node %s does not belong to the active subscription version", node.NodeID)
		}
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM path_nodes WHERE path_id=?", snapshot.PathID); err != nil {
		return fmt.Errorf("clear previous path node evidence: %w", err)
	}
	checkedAt := snapshot.CheckedAt.UTC().Format(time.RFC3339Nano)
	expiresAt := snapshot.ExpiresAt.UTC().Format(time.RFC3339Nano)
	for _, node := range snapshot.Nodes {
		lastSuccess, lastFailure := any(nil), any(nil)
		if node.State == NodeBypassQualified || node.State == NodeBypassLimited {
			lastSuccess = checkedAt
		} else {
			lastFailure = checkedAt
		}
		_, err := transaction.ExecContext(ctx, `
INSERT INTO path_nodes (
    path_id, node_id, qualification_state, qualification_generation,
    route_generation, qualification_expires_at, latency_ms,
    last_success_at, last_failure_at, failure_code
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, snapshot.PathID, node.NodeID, node.State, snapshot.ExpectedPolicyGeneration, snapshot.ExpectedRouteGeneration, expiresAt, nullIfZero(node.LatencyMS), lastSuccess, lastFailure, nullIfEmpty(node.ErrorCode))
		if err != nil {
			return fmt.Errorf("insert path node evidence: %w", err)
		}
		for _, target := range node.Targets {
			_, err := transaction.ExecContext(ctx, `
INSERT INTO path_node_target_results (
    path_id, node_id, target_id, state, latency_ms, http_status,
    error_code, checked_at, expires_at, policy_generation, route_generation
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, snapshot.PathID, node.NodeID, target.TargetID, target.State, nullIfZero(target.LatencyMS), nullIfZero(int64(target.HTTPStatus)), nullIfEmpty(target.ErrorCode), checkedAt, expiresAt, snapshot.ExpectedPolicyGeneration, snapshot.ExpectedRouteGeneration)
			if err != nil {
				return fmt.Errorf("insert node target evidence: %w", err)
			}
		}
	}
	qualified := int64(0)
	for _, node := range snapshot.Nodes {
		if node.State == NodeBypassQualified {
			qualified++
		}
	}
	qualityClass, functionalScore := "FAILED", int64(0)
	if snapshot.State == StateQualified {
		qualityClass = "FULL"
		functionalScore = snapshot.RequiredTargetsPassed*1000 + snapshot.OptionalTargetsPassed
	} else if snapshot.State == StateDegraded {
		qualityClass = "LIMITED"
		functionalScore = snapshot.FunctionalScore
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE subscription_modem_paths
SET state=?, transport_state=?, selected_node_id=?, candidate_nodes=?,
    qualified_nodes=?, required_targets_passed=?, required_targets_total=?,
    optional_targets_passed=?, optional_targets_total=?,
    quality_class=?, functional_score=?, latency_ms=?, last_checked_at=?, expires_at=?, updated_at=?
WHERE id=? AND policy_generation=? AND route_generation=?`, snapshot.State, snapshot.TransportState, nullIfEmpty(snapshot.SelectedNodeID), len(snapshot.Nodes), qualified, snapshot.RequiredTargetsPassed, snapshot.RequiredTargetsTotal, snapshot.OptionalTargetsPassed, snapshot.OptionalTargetsTotal, qualityClass, functionalScore, nullIfZero(snapshot.LatencyMS), checkedAt, expiresAt, repository.now().UTC().Format(time.RFC3339Nano), snapshot.PathID, snapshot.ExpectedPolicyGeneration, snapshot.ExpectedRouteGeneration)
	if err != nil {
		return fmt.Errorf("update aggregate qualification path: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read aggregate qualification update count: %w", err)
	}
	if count != 1 {
		return store.ErrStaleGeneration
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit qualification snapshot: %w", err)
	}
	return nil
}

// StoreNodeQualification replaces evidence only for the requested node and
// recomputes the path aggregate from all fresh evidence in the current
// generations. This lets an administrator qualify one exact tuple without
// deleting fresh results for the other candidates in the same path.
func (repository *Repository) StoreNodeQualification(ctx context.Context, snapshot NodeQualificationSnapshot) (Cell, error) {
	if snapshot.PathID == "" || snapshot.CandidateNodes <= 0 || snapshot.RequiredTargetsTotal <= 0 ||
		snapshot.CheckedAt.IsZero() || snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(snapshot.CheckedAt) {
		return Cell{}, errors.New("complete node qualification snapshot is required")
	}
	if snapshot.Node.NodeID == "" || (snapshot.Node.State != NodeBypassQualified && snapshot.Node.State != NodeBypassFailed) || snapshot.Node.LatencyMS < 0 {
		return Cell{}, errors.New("valid node qualification evidence is required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Cell{}, fmt.Errorf("begin node qualification snapshot: %w", err)
	}
	defer transaction.Rollback()
	var policyGeneration, routeGeneration int64
	var subscriptionID, activeVersionID string
	err = transaction.QueryRowContext(ctx, `
SELECT p.policy_generation, p.route_generation, p.subscription_id, COALESCE(s.active_version_id, '')
FROM subscription_modem_paths AS p
JOIN subscriptions AS s ON s.id=p.subscription_id
WHERE p.id=?`, snapshot.PathID).Scan(&policyGeneration, &routeGeneration, &subscriptionID, &activeVersionID)
	if errors.Is(err, sql.ErrNoRows) {
		return Cell{}, store.ErrNotFound
	}
	if err != nil {
		return Cell{}, fmt.Errorf("read node qualification path generation: %w", err)
	}
	if policyGeneration != snapshot.ExpectedPolicyGeneration || routeGeneration != snapshot.ExpectedRouteGeneration {
		return Cell{}, store.ErrStaleGeneration
	}
	var validNode, requiredTargets int64
	if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM nodes AS n
JOIN subscription_versions AS v ON v.id=n.version_id
WHERE n.id=? AND n.enabled=1 AND v.id=? AND v.subscription_id=?`, snapshot.Node.NodeID, activeVersionID, subscriptionID).Scan(&validNode); err != nil {
		return Cell{}, fmt.Errorf("validate exact qualification node: %w", err)
	}
	if validNode != 1 {
		return Cell{}, errors.New("node does not belong to the enabled active subscription candidate set")
	}
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM bypass_probe_targets WHERE enabled=1 AND required=1").Scan(&requiredTargets); err != nil {
		return Cell{}, fmt.Errorf("count current required targets: %w", err)
	}
	if requiredTargets != snapshot.RequiredTargetsTotal {
		return Cell{}, store.ErrStaleGeneration
	}
	checkedAt := snapshot.CheckedAt.UTC().Format(time.RFC3339Nano)
	expiresAt := snapshot.ExpiresAt.UTC().Format(time.RFC3339Nano)
	lastSuccess, lastFailure := any(nil), any(nil)
	if snapshot.Node.State == NodeBypassQualified {
		lastSuccess = checkedAt
	} else {
		lastFailure = checkedAt
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO path_nodes (
    path_id, node_id, qualification_state, qualification_generation,
    route_generation, qualification_expires_at, latency_ms,
    last_success_at, last_failure_at, failure_code
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(path_id, node_id) DO UPDATE SET
    qualification_state=excluded.qualification_state,
    qualification_generation=excluded.qualification_generation,
    route_generation=excluded.route_generation,
    qualification_expires_at=excluded.qualification_expires_at,
    latency_ms=excluded.latency_ms,
    last_success_at=COALESCE(excluded.last_success_at, path_nodes.last_success_at),
    last_failure_at=COALESCE(excluded.last_failure_at, path_nodes.last_failure_at),
    failure_code=excluded.failure_code`, snapshot.PathID, snapshot.Node.NodeID,
		snapshot.Node.State, snapshot.ExpectedPolicyGeneration, snapshot.ExpectedRouteGeneration,
		expiresAt, nullIfZero(snapshot.Node.LatencyMS), lastSuccess, lastFailure,
		nullIfEmpty(snapshot.Node.ErrorCode)); err != nil {
		return Cell{}, fmt.Errorf("upsert exact path node evidence: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM path_node_target_results WHERE path_id=? AND node_id=?", snapshot.PathID, snapshot.Node.NodeID); err != nil {
		return Cell{}, fmt.Errorf("clear exact node target evidence: %w", err)
	}
	seenTargets := make(map[string]struct{}, len(snapshot.Node.Targets))
	for _, target := range snapshot.Node.Targets {
		if target.TargetID == "" || target.LatencyMS < 0 {
			return Cell{}, errors.New("invalid exact node target evidence")
		}
		if _, exists := seenTargets[target.TargetID]; exists {
			return Cell{}, errors.New("duplicate exact node target evidence")
		}
		seenTargets[target.TargetID] = struct{}{}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO path_node_target_results (
    path_id, node_id, target_id, state, latency_ms, http_status,
    error_code, checked_at, expires_at, policy_generation, route_generation
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, snapshot.PathID, snapshot.Node.NodeID,
			target.TargetID, target.State, nullIfZero(target.LatencyMS),
			nullIfZero(int64(target.HTTPStatus)), nullIfEmpty(target.ErrorCode), checkedAt,
			expiresAt, snapshot.ExpectedPolicyGeneration, snapshot.ExpectedRouteGeneration); err != nil {
			return Cell{}, fmt.Errorf("insert exact node target evidence: %w", err)
		}
	}

	var selectedNodeID, selectedExpiry, selectedCheckedAt sql.NullString
	var selectedLatency sql.NullInt64
	err = transaction.QueryRowContext(ctx, `
SELECT pn.node_id, pn.latency_ms, pn.qualification_expires_at,
       COALESCE(pn.last_success_at, pn.last_failure_at)
FROM path_nodes AS pn
JOIN nodes AS n ON n.id=pn.node_id AND n.enabled=1
JOIN subscriptions AS s ON s.active_version_id=n.version_id
JOIN subscription_modem_paths AS p ON p.id=pn.path_id AND p.subscription_id=s.id
WHERE pn.path_id=? AND pn.qualification_state='BYPASS_QUALIFIED'
  AND pn.qualification_generation=? AND pn.route_generation=?
  AND pn.qualification_expires_at>?
ORDER BY COALESCE(pn.latency_ms, 9223372036854775807), pn.node_id
LIMIT 1`, snapshot.PathID, snapshot.ExpectedPolicyGeneration, snapshot.ExpectedRouteGeneration, checkedAt).Scan(&selectedNodeID, &selectedLatency, &selectedExpiry, &selectedCheckedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Cell{}, fmt.Errorf("select aggregate qualified node: %w", err)
	}
	var qualifiedNodes, passedTransport int64
	if err := transaction.QueryRowContext(ctx, `
SELECT
    SUM(CASE WHEN pn.qualification_state='BYPASS_QUALIFIED' THEN 1 ELSE 0 END),
    SUM(CASE WHEN pn.qualification_state='BYPASS_QUALIFIED' OR EXISTS (
        SELECT 1 FROM path_node_target_results AS r
        WHERE r.path_id=pn.path_id AND r.node_id=pn.node_id
          AND r.policy_generation=? AND r.route_generation=? AND r.expires_at>?
    ) THEN 1 ELSE 0 END)
FROM path_nodes AS pn
JOIN nodes AS n ON n.id=pn.node_id AND n.enabled=1
JOIN subscriptions AS s ON s.active_version_id=n.version_id
JOIN subscription_modem_paths AS p ON p.id=pn.path_id AND p.subscription_id=s.id
WHERE pn.path_id=? AND pn.qualification_generation=? AND pn.route_generation=?
  AND pn.qualification_expires_at>?`, snapshot.ExpectedPolicyGeneration,
		snapshot.ExpectedRouteGeneration, checkedAt, snapshot.PathID,
		snapshot.ExpectedPolicyGeneration, snapshot.ExpectedRouteGeneration, checkedAt).Scan(&qualifiedNodes, &passedTransport); err != nil {
		return Cell{}, fmt.Errorf("aggregate exact node qualification: %w", err)
	}
	pathState, transportState := StateFailed, "FAILED"
	requiredPassed, latency := int64(0), int64(0)
	aggregateCheckedAt, aggregateExpiry := checkedAt, expiresAt
	if passedTransport > 0 {
		transportState = "PASSED"
	}
	if selectedNodeID.Valid {
		pathState = StateQualified
		requiredPassed = requiredTargets
		latency = selectedLatency.Int64
		aggregateCheckedAt, aggregateExpiry = selectedCheckedAt.String, selectedExpiry.String
	}
	qualityClass, functionalScore := "FAILED", int64(0)
	if pathState == StateQualified {
		qualityClass = "FULL"
		functionalScore = requiredPassed * 1000
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE subscription_modem_paths
SET state=?, transport_state=?, selected_node_id=?, candidate_nodes=?,
    qualified_nodes=?, required_targets_passed=?, required_targets_total=?,
    quality_class=?, functional_score=?, latency_ms=?, last_checked_at=?, expires_at=?, updated_at=?
WHERE id=? AND policy_generation=? AND route_generation=?`, pathState, transportState,
		nullIfEmpty(selectedNodeID.String), snapshot.CandidateNodes, qualifiedNodes,
		requiredPassed, requiredTargets, qualityClass, functionalScore, nullIfZero(latency), aggregateCheckedAt,
		aggregateExpiry, repository.now().UTC().Format(time.RFC3339Nano), snapshot.PathID,
		snapshot.ExpectedPolicyGeneration, snapshot.ExpectedRouteGeneration)
	if err != nil {
		return Cell{}, fmt.Errorf("update exact node path aggregate: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil {
		return Cell{}, fmt.Errorf("read exact node aggregate update count: %w", countErr)
	} else if count != 1 {
		return Cell{}, store.ErrStaleGeneration
	}
	if err := transaction.Commit(); err != nil {
		return Cell{}, fmt.Errorf("commit exact node qualification: %w", err)
	}
	return repository.GetByID(ctx, snapshot.PathID)
}

// InvalidateVersionEvidence removes qualification written for a subscription
// version whose external runtime promotion is being compensated. Only paths
// that actually contain nodes from that version are made STALE; unrelated
// modem/subscription cells and their evidence are left untouched.
func (repository *Repository) InvalidateVersionEvidence(ctx context.Context, subscriptionID, versionID string) error {
	if subscriptionID == "" || versionID == "" {
		return errors.New("subscription and version ids are required for qualification invalidation")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin qualification version invalidation: %w", err)
	}
	defer transaction.Rollback()
	var valid int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM subscription_versions WHERE id=? AND subscription_id=?", versionID, subscriptionID).Scan(&valid); err != nil {
		return fmt.Errorf("validate qualification version invalidation: %w", err)
	}
	if valid != 1 {
		return store.ErrNotFound
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_modem_paths
SET state='STALE', transport_state='UNKNOWN', selected_node_id=NULL,
    candidate_nodes=0, qualified_nodes=0, required_targets_passed=0,
    required_targets_total=0, latency_ms=NULL, last_checked_at=NULL,
    expires_at=NULL, updated_at=?
WHERE subscription_id=? AND id IN (
    SELECT pn.path_id
    FROM path_nodes AS pn
    JOIN nodes AS n ON n.id=pn.node_id
    WHERE n.version_id=?
)`, now, subscriptionID, versionID); err != nil {
		return fmt.Errorf("stale paths for invalidated qualification version: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
DELETE FROM path_nodes
WHERE node_id IN (SELECT id FROM nodes WHERE version_id=?)`, versionID); err != nil {
		return fmt.Errorf("delete invalidated qualification evidence: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit qualification version invalidation: %w", err)
	}
	return nil
}

func validateQualificationSnapshot(snapshot QualificationSnapshot) error {
	if snapshot.PathID == "" || snapshot.CheckedAt.IsZero() || snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(snapshot.CheckedAt) {
		return errors.New("qualification path, check time, and future expiry are required")
	}
	if !validResultState(snapshot.State) || snapshot.State == StateProbing {
		return fmt.Errorf("invalid final qualification state %q", snapshot.State)
	}
	if snapshot.RequiredTargetsTotal <= 0 || snapshot.RequiredTargetsPassed < 0 || snapshot.RequiredTargetsPassed > snapshot.RequiredTargetsTotal || snapshot.LatencyMS < 0 {
		return errors.New("invalid qualification counters")
	}
	seenNodes := make(map[string]struct{}, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		if node.NodeID == "" || (node.State != NodeBypassQualified && node.State != NodeBypassLimited && node.State != NodeBypassFailed) || node.LatencyMS < 0 {
			return errors.New("invalid node qualification evidence")
		}
		if _, exists := seenNodes[node.NodeID]; exists {
			return errors.New("duplicate node qualification evidence")
		}
		seenNodes[node.NodeID] = struct{}{}
		seenTargets := make(map[string]struct{}, len(node.Targets))
		for _, target := range node.Targets {
			if target.TargetID == "" || target.LatencyMS < 0 {
				return errors.New("invalid target qualification evidence")
			}
			if _, exists := seenTargets[target.TargetID]; exists {
				return errors.New("duplicate target qualification evidence")
			}
			seenTargets[target.TargetID] = struct{}{}
		}
	}
	if snapshot.State == StateQualified {
		if snapshot.TransportState != "PASSED" || snapshot.SelectedNodeID == "" || snapshot.RequiredTargetsPassed != snapshot.RequiredTargetsTotal {
			return errors.New("qualified snapshot requires passed transport, selected node, and all required targets")
		}
		selectedQualified := false
		for _, node := range snapshot.Nodes {
			if node.NodeID == snapshot.SelectedNodeID && node.State == NodeBypassQualified {
				selectedQualified = true
			}
		}
		if !selectedQualified {
			return errors.New("selected node is not qualified in this snapshot")
		}
	} else if snapshot.State == StateDegraded {
		if snapshot.TransportState != "PASSED" || snapshot.SelectedNodeID == "" || snapshot.FunctionalScore <= 0 || snapshot.RequiredTargetsPassed >= snapshot.RequiredTargetsTotal {
			return errors.New("degraded snapshot requires passed transport, selected node, and partial target access")
		}
		selectedLimited := false
		for _, node := range snapshot.Nodes {
			if node.NodeID == snapshot.SelectedNodeID && node.State == NodeBypassLimited {
				selectedLimited = true
			}
		}
		if !selectedLimited {
			return errors.New("selected node is not limited in this snapshot")
		}
	}
	return nil
}
