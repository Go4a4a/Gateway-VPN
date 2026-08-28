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
	EvidenceUntested = "UNTESTED"
	EvidenceStale    = "STALE"
)

type PathNodeDetail struct {
	PathID                  string
	NodeID                  string
	ExternalName            string
	ProxyType               string
	CandidateSource         string
	QualificationState      string
	QualificationGeneration int64
	RouteGeneration         int64
	QualificationExpiresAt  string
	LatencyMS               int64
	LastSuccessAt           string
	LastFailureAt           string
	FailureCode             string
	Selected                bool
	Active                  bool
	CurrentEvidence         bool
	TargetResultCount       int64
}

type PathNodePage struct {
	Items           []PathNodeDetail
	NextAfterNodeID string
}

type TargetCursor struct {
	Priority int64
	ID       string
}

type NodeTargetDetail struct {
	TargetID         string
	Name             string
	Priority         int64
	Required         bool
	SuccessMode      string
	State            string
	LatencyMS        int64
	HTTPStatus       int64
	ErrorCode        string
	CheckedAt        string
	ExpiresAt        string
	PolicyGeneration int64
	RouteGeneration  int64
	CurrentEvidence  bool
}

type NodeTargetPage struct {
	Items      []NodeTargetDetail
	NextCursor *TargetCursor
}

// ListPathNodes returns the active-LKG candidate inventory for one exact path.
// Evidence is labelled STALE unless both generations and expiry match the
// current path, so old results can never look activatable in the Web UI.
func (repository *Repository) ListPathNodes(ctx context.Context, pathID string, limit int, afterNodeID string, at time.Time) (PathNodePage, error) {
	if pathID == "" || limit <= 0 || limit > 200 || len(afterNodeID) > 256 || at.IsZero() {
		return PathNodePage{}, errors.New("path id, limit 1..200, bounded cursor, and current time are required")
	}
	var exists int
	if err := repository.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM subscription_uplink_paths WHERE id=?", pathID).Scan(&exists); err != nil {
		return PathNodePage{}, fmt.Errorf("validate path node page: %w", err)
	}
	if exists != 1 {
		return PathNodePage{}, store.ErrNotFound
	}
	formattedNow := at.UTC().Format(time.RFC3339Nano)
	rows, err := repository.database.QueryContext(ctx, `
SELECT p.id, n.id, n.external_name, n.proxy_type, n.candidate_source,
       pn.qualification_state, pn.qualification_generation, pn.route_generation,
       pn.qualification_expires_at, pn.latency_ms, pn.last_success_at,
       pn.last_failure_at, pn.failure_code,
       CASE WHEN p.selected_node_id=n.id THEN 1 ELSE 0 END,
       CASE WHEN rs.active_path_id=p.id AND rs.active_node_id=n.id THEN 1 ELSE 0 END,
       p.policy_generation, p.route_generation,
       (
           SELECT COUNT(*) FROM uplink_path_node_target_results AS r
           WHERE r.path_id=p.id AND r.node_id=n.id
             AND r.policy_generation=p.policy_generation
             AND r.route_generation=p.route_generation AND r.expires_at>?
       )
FROM subscription_uplink_paths AS p
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN subscription_versions AS v ON v.id=s.active_version_id
JOIN nodes AS n ON n.version_id=v.id AND n.enabled=1
LEFT JOIN uplink_path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=n.id
CROSS JOIN runtime_state AS rs
WHERE p.id=? AND n.id>?
ORDER BY n.id
LIMIT ?`, formattedNow, pathID, afterNodeID, limit+1)
	if err != nil {
		return PathNodePage{}, fmt.Errorf("list path nodes: %w", err)
	}
	defer rows.Close()
	result := PathNodePage{Items: make([]PathNodeDetail, 0, limit)}
	for rows.Next() {
		var item PathNodeDetail
		var qualificationState, qualificationExpiresAt sql.NullString
		var qualificationGeneration, routeGeneration, latencyMS sql.NullInt64
		var lastSuccessAt, lastFailureAt, failureCode sql.NullString
		var selected, active int
		var currentPolicyGeneration, currentRouteGeneration int64
		if err := rows.Scan(
			&item.PathID, &item.NodeID, &item.ExternalName, &item.ProxyType, &item.CandidateSource,
			&qualificationState, &qualificationGeneration, &routeGeneration,
			&qualificationExpiresAt, &latencyMS, &lastSuccessAt, &lastFailureAt,
			&failureCode, &selected, &active, &currentPolicyGeneration,
			&currentRouteGeneration, &item.TargetResultCount,
		); err != nil {
			return PathNodePage{}, fmt.Errorf("scan path node detail: %w", err)
		}
		item.QualificationGeneration = qualificationGeneration.Int64
		item.RouteGeneration = routeGeneration.Int64
		item.QualificationExpiresAt = qualificationExpiresAt.String
		item.LatencyMS = latencyMS.Int64
		item.LastSuccessAt = lastSuccessAt.String
		item.LastFailureAt = lastFailureAt.String
		item.FailureCode = failureCode.String
		item.Selected, item.Active = selected == 1, active == 1
		item.QualificationState = EvidenceUntested
		if qualificationState.Valid {
			item.QualificationState = EvidenceStale
			expiresAt, parseErr := time.Parse(time.RFC3339Nano, qualificationExpiresAt.String)
			item.CurrentEvidence = qualificationGeneration.Int64 == currentPolicyGeneration &&
				routeGeneration.Int64 == currentRouteGeneration && parseErr == nil && expiresAt.After(at)
			if item.CurrentEvidence {
				item.QualificationState = qualificationState.String
			}
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return PathNodePage{}, fmt.Errorf("iterate path node details: %w", err)
	}
	if len(result.Items) > limit {
		result.NextAfterNodeID = result.Items[limit-1].NodeID
		result.Items = result.Items[:limit]
	}
	return result, nil
}

// ListNodeTargets lazily returns the latest target evidence for one exact
// path/node tuple. The keyset cursor follows the user-defined target priority.
func (repository *Repository) ListNodeTargets(ctx context.Context, pathID, nodeID string, limit int, after *TargetCursor, at time.Time) (NodeTargetPage, error) {
	if pathID == "" || nodeID == "" || limit <= 0 || limit > 200 || at.IsZero() {
		return NodeTargetPage{}, errors.New("path, node, limit 1..200, and current time are required")
	}
	if after != nil && (after.Priority < 0 || after.ID == "" || len(after.ID) > 256) {
		return NodeTargetPage{}, errors.New("invalid target cursor")
	}
	var valid int
	if err := repository.database.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM subscription_uplink_paths AS p
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN nodes AS n ON n.version_id=s.active_version_id AND n.enabled=1
WHERE p.id=? AND n.id=?`, pathID, nodeID).Scan(&valid); err != nil {
		return NodeTargetPage{}, fmt.Errorf("validate path node target page: %w", err)
	}
	if valid != 1 {
		return NodeTargetPage{}, store.ErrNotFound
	}
	query := `
SELECT t.id, t.name, t.priority, t.required, t.success_mode,
       r.state, r.latency_ms, r.http_status, r.error_code, r.checked_at,
       r.expires_at, r.policy_generation, r.route_generation,
       p.policy_generation, p.route_generation
FROM subscription_uplink_paths AS p
JOIN bypass_probe_targets AS t ON t.enabled=1
	AND t.target_class IN ('GLOBAL_REQUIRED','GLOBAL_OPTIONAL')
LEFT JOIN uplink_path_node_target_results AS r
  ON r.path_id=p.id AND r.node_id=? AND r.target_id=t.id
WHERE p.id=?`
	args := []any{nodeID, pathID}
	if after != nil {
		query += " AND (t.priority>? OR (t.priority=? AND t.id>?))"
		args = append(args, after.Priority, after.Priority, after.ID)
	}
	query += " ORDER BY t.priority, t.id LIMIT ?"
	args = append(args, limit+1)
	rows, err := repository.database.QueryContext(ctx, query, args...)
	if err != nil {
		return NodeTargetPage{}, fmt.Errorf("list node target evidence: %w", err)
	}
	defer rows.Close()
	result := NodeTargetPage{Items: make([]NodeTargetDetail, 0, limit)}
	for rows.Next() {
		var item NodeTargetDetail
		var required int
		var storedState, errorCode, checkedAt, expiresAt sql.NullString
		var latencyMS, httpStatus, policyGeneration, routeGeneration sql.NullInt64
		var currentPolicyGeneration, currentRouteGeneration int64
		if err := rows.Scan(
			&item.TargetID, &item.Name, &item.Priority, &required, &item.SuccessMode,
			&storedState, &latencyMS, &httpStatus, &errorCode, &checkedAt,
			&expiresAt, &policyGeneration, &routeGeneration,
			&currentPolicyGeneration, &currentRouteGeneration,
		); err != nil {
			return NodeTargetPage{}, fmt.Errorf("scan node target evidence: %w", err)
		}
		item.Required = required == 1
		item.LatencyMS, item.HTTPStatus = latencyMS.Int64, httpStatus.Int64
		item.ErrorCode, item.CheckedAt, item.ExpiresAt = errorCode.String, checkedAt.String, expiresAt.String
		item.PolicyGeneration, item.RouteGeneration = policyGeneration.Int64, routeGeneration.Int64
		item.State = EvidenceUntested
		if storedState.Valid {
			item.State = EvidenceStale
			parsedExpiry, parseErr := time.Parse(time.RFC3339Nano, expiresAt.String)
			item.CurrentEvidence = policyGeneration.Int64 == currentPolicyGeneration &&
				routeGeneration.Int64 == currentRouteGeneration && parseErr == nil && parsedExpiry.After(at)
			if item.CurrentEvidence {
				item.State = storedState.String
			}
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return NodeTargetPage{}, fmt.Errorf("iterate node target evidence: %w", err)
	}
	if len(result.Items) > limit {
		last := result.Items[limit-1]
		result.NextCursor = &TargetCursor{Priority: last.Priority, ID: last.TargetID}
		result.Items = result.Items[:limit]
	}
	return result, nil
}
