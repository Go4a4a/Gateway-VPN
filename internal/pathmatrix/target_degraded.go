package pathmatrix

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gateway-vpn/internal/store"
)

// MarkTargetDegraded keeps the exact active node selected only when every
// currently-required failure is already classified TARGET_SUSPECT and all
// other required targets passed through that node. Exact node evidence must
// have been stored first in the same operation-lock critical section.
func (repository *Repository) MarkTargetDegraded(ctx context.Context, pathID, nodeID string, expectedPolicyGeneration, expectedRouteGeneration int64, at time.Time) (Cell, error) {
	if pathID == "" || nodeID == "" || at.IsZero() {
		return Cell{}, errors.New("path, node, and current time are required for target degradation")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Cell{}, fmt.Errorf("begin target-degraded path update: %w", err)
	}
	defer transaction.Rollback()
	formattedNow := at.UTC().Format(time.RFC3339Nano)
	var policyGeneration, routeGeneration, candidateNodes int64
	var nodeState, nodeExpiry string
	var nodeLatency sql.NullInt64
	err = transaction.QueryRowContext(ctx, `
SELECT p.policy_generation, p.route_generation, p.candidate_nodes,
       pn.qualification_state, pn.qualification_expires_at, pn.latency_ms
FROM subscription_modem_paths AS p
JOIN runtime_state AS rs ON rs.active_path_id=p.id AND rs.active_node_id=? AND rs.path_state='PATH_ACTIVE'
JOIN path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=?
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN nodes AS n ON n.id=pn.node_id AND n.enabled=1 AND n.version_id=s.active_version_id
WHERE p.id=? AND pn.qualification_generation=p.policy_generation
  AND pn.route_generation=p.route_generation AND pn.qualification_expires_at>?`,
		nodeID, nodeID, pathID, formattedNow).Scan(
		&policyGeneration, &routeGeneration, &candidateNodes,
		&nodeState, &nodeExpiry, &nodeLatency,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Cell{}, store.ErrStaleGeneration
	}
	if err != nil {
		return Cell{}, fmt.Errorf("validate target-degraded active node: %w", err)
	}
	if policyGeneration != expectedPolicyGeneration || routeGeneration != expectedRouteGeneration || nodeState != NodeBypassFailed {
		return Cell{}, store.ErrStaleGeneration
	}
	rows, err := transaction.QueryContext(ctx, `
SELECT t.state, r.state, r.checked_at
FROM bypass_probe_targets AS t
LEFT JOIN path_node_target_results AS r
  ON r.path_id=? AND r.node_id=? AND r.target_id=t.id
  AND r.policy_generation=? AND r.route_generation=? AND r.expires_at>?
WHERE t.enabled=1 AND t.required=1
ORDER BY t.priority, t.id`, pathID, nodeID, expectedPolicyGeneration, expectedRouteGeneration, formattedNow)
	if err != nil {
		return Cell{}, fmt.Errorf("read required target degradation evidence: %w", err)
	}
	requiredTotal, requiredPassed := int64(0), int64(0)
	suspectFailure := false
	lastCheckedAt := ""
	for rows.Next() {
		var targetState string
		var resultState, checkedAt sql.NullString
		if err := rows.Scan(&targetState, &resultState, &checkedAt); err != nil {
			rows.Close()
			return Cell{}, fmt.Errorf("scan required target degradation evidence: %w", err)
		}
		requiredTotal++
		if !resultState.Valid {
			rows.Close()
			return Cell{}, store.ErrStaleGeneration
		}
		if resultState.String == "PASSED" {
			requiredPassed++
		} else if targetState == "TARGET_SUSPECT" {
			suspectFailure = true
		} else {
			rows.Close()
			return Cell{}, errors.New("required target failure is not outage-suppressed")
		}
		if checkedAt.String > lastCheckedAt {
			lastCheckedAt = checkedAt.String
		}
	}
	if err := rows.Close(); err != nil {
		return Cell{}, fmt.Errorf("close target degradation evidence: %w", err)
	}
	if err := rows.Err(); err != nil {
		return Cell{}, fmt.Errorf("iterate target degradation evidence: %w", err)
	}
	if requiredTotal == 0 || !suspectFailure || lastCheckedAt == "" {
		return Cell{}, errors.New("target degradation requires a suspect required failure")
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE subscription_modem_paths
SET state='DEGRADED', transport_state='PASSED', selected_node_id=?,
    candidate_nodes=?, qualified_nodes=0, required_targets_passed=?,
    required_targets_total=?, latency_ms=?, last_checked_at=?, expires_at=?, updated_at=?
WHERE id=? AND policy_generation=? AND route_generation=?`, nodeID, candidateNodes,
		requiredPassed, requiredTotal, nodeLatency, lastCheckedAt, nodeExpiry,
		repository.now().UTC().Format(time.RFC3339Nano), pathID,
		expectedPolicyGeneration, expectedRouteGeneration)
	if err != nil {
		return Cell{}, fmt.Errorf("mark path target-degraded: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil {
		return Cell{}, countErr
	} else if count != 1 {
		return Cell{}, store.ErrStaleGeneration
	}
	if err := transaction.Commit(); err != nil {
		return Cell{}, fmt.Errorf("commit target-degraded path: %w", err)
	}
	return repository.GetByID(ctx, pathID)
}
