// Package pathmatrix stores the canonical uplink-by-subscription status matrix.
package pathmatrix

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"gateway-vpn/internal/store"
)

const (
	StateUplinkOffline        = "UPLINK_OFFLINE"
	StateUplinkDisabled       = "UPLINK_DISABLED"
	StateModemOffline         = StateUplinkOffline  // deprecated compatibility name
	StateModemDisabled        = StateUplinkDisabled // deprecated compatibility name
	StateSubscriptionDisabled = "SUBSCRIPTION_DISABLED"
	StateUntested             = "UNTESTED"
	StateProbing              = "PROBING"
	StateQualified            = "QUALIFIED"
	StateDegraded             = "DEGRADED"
	StateFailed               = "FAILED"
	StateStale                = "STALE"
)

type Repository struct {
	database *sql.DB
	now      func() time.Time
}

type Cell struct {
	ID                  string
	UplinkID            string
	UplinkDisplayNumber int64
	UplinkType          string
	UplinkName          string
	UplinkPriority      int64
	// Deprecated modem aliases remain populated during the bounded API migration.
	ModemID               string
	ModemDisplayNumber    int64
	ModemName             string
	ModemPriority         int64
	SubscriptionID        string
	SubscriptionName      string
	SubscriptionPriority  int64
	State                 string
	TransportState        string
	SelectedNodeID        string
	CandidateNodes        int64
	QualifiedNodes        int64
	RequiredTargetsPassed int64
	RequiredTargetsTotal  int64
	OptionalTargetsPassed int64
	OptionalTargetsTotal  int64
	QualityClass          string
	FunctionalScore       int64
	LatencyMS             int64
	PolicyGeneration      int64
	RouteGeneration       int64
	LastCheckedAt         string
	ExpiresAt             string
	CreatedAt             string
	UpdatedAt             string
}

type ResultUpdate struct {
	PathID                   string
	ExpectedPolicyGeneration int64
	ExpectedRouteGeneration  int64
	State                    string
	TransportState           string
	SelectedNodeID           string
	CandidateNodes           int64
	QualifiedNodes           int64
	RequiredTargetsPassed    int64
	RequiredTargetsTotal     int64
	OptionalTargetsPassed    int64
	OptionalTargetsTotal     int64
	QualityClass             string
	FunctionalScore          int64
	LatencyMS                int64
	LastCheckedAt            time.Time
	ExpiresAt                time.Time
}

func NewRepository(database *sql.DB) *Repository {
	return &Repository{database: database, now: time.Now}
}

func (repository *Repository) ReconcileCells(ctx context.Context) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin path matrix reconcile: %w", err)
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	policyGeneration := int64(0)
	var nextPolicyGeneration string
	err = transaction.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key='next_policy_generation'").Scan(&nextPolicyGeneration)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("read current path policy generation: %w", err)
	default:
		next, parseErr := strconv.ParseInt(nextPolicyGeneration, 10, 64)
		if parseErr != nil || next < 1 {
			return fmt.Errorf("invalid next path policy generation %q", nextPolicyGeneration)
		}
		policyGeneration = next - 1
	}

	_, err = transaction.ExecContext(ctx, `
INSERT INTO subscription_uplink_paths (
    id, uplink_id, subscription_id, state, transport_state,
    policy_generation, route_generation, created_at, updated_at
)
SELECT
	'path:' || u.id || ':' || s.id,
	u.id,
    s.id,
    CASE
		WHEN u.enabled=0 THEN 'UPLINK_DISABLED'
        WHEN s.enabled=0 THEN 'SUBSCRIPTION_DISABLED'
		WHEN u.state<>'UPLINK_READY' THEN 'UPLINK_OFFLINE'
        ELSE 'UNTESTED'
    END,
    'UNKNOWN',
	?,
	u.route_generation,
    ?,
    ?
FROM uplinks AS u
CROSS JOIN subscriptions AS s
WHERE 1=1
ON CONFLICT(uplink_id, subscription_id) DO NOTHING`, policyGeneration, now, now)
	if err != nil {
		return fmt.Errorf("create path matrix cells: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths AS p
SET state = CASE
		WHEN u.enabled=0 THEN 'UPLINK_DISABLED'
        WHEN s.enabled=0 THEN 'SUBSCRIPTION_DISABLED'
		WHEN u.state<>'UPLINK_READY' THEN 'UPLINK_OFFLINE'
		WHEN p.state IN ('UPLINK_DISABLED', 'SUBSCRIPTION_DISABLED', 'UPLINK_OFFLINE') THEN 'UNTESTED'
        ELSE p.state
    END,
    transport_state = CASE
		WHEN u.enabled=0 OR s.enabled=0 OR u.state<>'UPLINK_READY' THEN 'UNKNOWN'
        ELSE p.transport_state
    END,
    selected_node_id = CASE
		WHEN u.enabled=0 OR s.enabled=0 OR u.state<>'UPLINK_READY' THEN NULL
        ELSE p.selected_node_id
    END,
    qualified_nodes = CASE
		WHEN u.enabled=0 OR s.enabled=0 OR u.state<>'UPLINK_READY' THEN 0
        ELSE p.qualified_nodes
    END,
    required_targets_passed = CASE
		WHEN u.enabled=0 OR s.enabled=0 OR u.state<>'UPLINK_READY' THEN 0
        ELSE p.required_targets_passed
    END,
    quality_class = CASE
		WHEN u.enabled=0 OR s.enabled=0 OR u.state<>'UPLINK_READY' THEN 'UNKNOWN'
        ELSE p.quality_class
    END,
    functional_score = CASE
		WHEN u.enabled=0 OR s.enabled=0 OR u.state<>'UPLINK_READY' THEN 0
        ELSE p.functional_score
    END,
    optional_targets_passed = CASE
		WHEN u.enabled=0 OR s.enabled=0 OR u.state<>'UPLINK_READY' THEN 0
        ELSE p.optional_targets_passed
    END,
    expires_at = CASE
		WHEN u.enabled=0 OR s.enabled=0 OR u.state<>'UPLINK_READY' THEN NULL
        ELSE p.expires_at
    END,
    updated_at = ?
FROM uplinks AS u, subscriptions AS s
WHERE p.uplink_id=u.id AND p.subscription_id=s.id`, now); err != nil {
		return fmt.Errorf("refresh disabled path states: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit path matrix reconcile: %w", err)
	}
	return nil
}

func (repository *Repository) List(ctx context.Context) ([]Cell, error) {
	rows, err := repository.database.QueryContext(ctx, cellSelect+` ORDER BY u.priority, s.priority, u.display_number`)
	if err != nil {
		return nil, fmt.Errorf("list path matrix: %w", err)
	}
	defer rows.Close()
	var result []Cell
	for rows.Next() {
		item, err := scanCell(rows)
		if err != nil {
			return nil, fmt.Errorf("scan path matrix cell: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate path matrix: %w", err)
	}
	return result, nil
}

func (repository *Repository) Get(ctx context.Context, uplinkID, subscriptionID string) (Cell, error) {
	item, err := scanCell(repository.database.QueryRowContext(ctx, cellSelect+" WHERE p.uplink_id=? AND p.subscription_id=?", uplinkID, subscriptionID))
	if errors.Is(err, sql.ErrNoRows) {
		return Cell{}, store.ErrNotFound
	}
	if err != nil {
		return Cell{}, fmt.Errorf("get path matrix cell: %w", err)
	}
	return item, nil
}

func (repository *Repository) GetByID(ctx context.Context, pathID string) (Cell, error) {
	if pathID == "" {
		return Cell{}, errors.New("path id is required")
	}
	item, err := scanCell(repository.database.QueryRowContext(ctx, cellSelect+" WHERE p.id=?", pathID))
	if errors.Is(err, sql.ErrNoRows) {
		return Cell{}, store.ErrNotFound
	}
	if err != nil {
		return Cell{}, fmt.Errorf("get path matrix cell by id: %w", err)
	}
	return item, nil
}

func (repository *Repository) UpdateResult(ctx context.Context, update ResultUpdate) error {
	if err := validateResultUpdate(update); err != nil {
		return err
	}
	qualityClass, functionalScore := resultQuality(update)
	result, err := repository.database.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET state=?, transport_state=?, selected_node_id=?, candidate_nodes=?,
    qualified_nodes=?, required_targets_passed=?, required_targets_total=?,
    optional_targets_passed=?, optional_targets_total=?,
    quality_class=?, functional_score=?,
    latency_ms=?, last_checked_at=?, expires_at=?, updated_at=?
WHERE id=? AND policy_generation=? AND route_generation=?`,
		update.State,
		update.TransportState,
		nullIfEmpty(update.SelectedNodeID),
		update.CandidateNodes,
		update.QualifiedNodes,
		update.RequiredTargetsPassed,
		update.RequiredTargetsTotal,
		update.OptionalTargetsPassed,
		update.OptionalTargetsTotal,
		qualityClass,
		functionalScore,
		nullIfZero(update.LatencyMS),
		formatOptionalTime(update.LastCheckedAt),
		formatOptionalTime(update.ExpiresAt),
		repository.now().UTC().Format(time.RFC3339Nano),
		update.PathID,
		update.ExpectedPolicyGeneration,
		update.ExpectedRouteGeneration,
	)
	if err != nil {
		return fmt.Errorf("update path result: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read path update count: %w", err)
	}
	if count != 1 {
		return store.ErrStaleGeneration
	}
	return nil
}

func (repository *Repository) BumpRouteGeneration(ctx context.Context, uplinkID string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin uplink route generation bump: %w", err)
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	uplinkResult, err := transaction.ExecContext(ctx, `
UPDATE uplinks SET route_generation=route_generation+1, updated_at=? WHERE id=?`, now, uplinkID)
	if err != nil {
		return fmt.Errorf("bump uplink route generation: %w", err)
	}
	if count, countErr := uplinkResult.RowsAffected(); countErr != nil || count != 1 {
		return store.ErrNotFound
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET route_generation=(SELECT route_generation FROM uplinks WHERE id=?),
    state='STALE', transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, optional_targets_passed=0,
    quality_class='UNKNOWN', functional_score=0,
    last_checked_at=NULL, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, uplinkID, now, uplinkID)
	if err != nil {
		return fmt.Errorf("bump uplink route generation: %w", err)
	}
	if _, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("read route generation update count: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE direct_uplink_paths
SET route_generation=(SELECT route_generation FROM uplinks WHERE id=?),
    state='STALE', transport_state='UNKNOWN', quality_class='UNKNOWN',
    functional_score=0, required_targets_passed=0, optional_targets_passed=0,
    last_checked_at=NULL, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, uplinkID, now, uplinkID); err != nil {
		return fmt.Errorf("invalidate direct uplink route generation: %w", err)
	}
	return transaction.Commit()
}

func (repository *Repository) BumpPolicyGeneration(ctx context.Context) (int64, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin policy generation bump: %w", err)
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	generation, err := store.InvalidatePathPolicy(ctx, transaction, now)
	if err != nil {
		return 0, fmt.Errorf("bump path policy generation: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit policy generation bump: %w", err)
	}
	return generation, nil
}

func (repository *Repository) MarkUplinkOffline(ctx context.Context, uplinkID string) error {
	result, err := repository.database.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET state='UPLINK_OFFLINE', transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, optional_targets_passed=0,
    quality_class='UNKNOWN', functional_score=0, expires_at=NULL, updated_at=?
WHERE uplink_id=?`, repository.now().UTC().Format(time.RFC3339Nano), uplinkID)
	if err != nil {
		return fmt.Errorf("mark uplink paths offline: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read offline update count: %w", err)
	}
	if count == 0 {
		return store.ErrNotFound
	}
	return nil
}

// MarkModemOffline is retained while HiLink callers migrate to uplink terminology.
func (repository *Repository) MarkModemOffline(ctx context.Context, modemID string) error {
	return repository.MarkUplinkOffline(ctx, modemID)
}

func validResultState(state string) bool {
	switch state {
	case StateProbing, StateQualified, StateDegraded, StateFailed, StateStale:
		return true
	default:
		return false
	}
}

func validateResultUpdate(update ResultUpdate) error {
	if update.PathID == "" {
		return errors.New("path id is required")
	}
	if !validResultState(update.State) {
		return fmt.Errorf("invalid path result state %q", update.State)
	}
	if update.CandidateNodes < 0 || update.QualifiedNodes < 0 || update.RequiredTargetsPassed < 0 || update.RequiredTargetsTotal < 0 || update.OptionalTargetsPassed < 0 || update.OptionalTargetsTotal < 0 || update.FunctionalScore < 0 || update.LatencyMS < 0 {
		return errors.New("path result counters cannot be negative")
	}
	if update.QualifiedNodes > update.CandidateNodes {
		return errors.New("qualified node count cannot exceed candidate node count")
	}
	if update.RequiredTargetsPassed > update.RequiredTargetsTotal {
		return errors.New("passed target count cannot exceed total target count")
	}
	if update.OptionalTargetsPassed > update.OptionalTargetsTotal {
		return errors.New("passed optional target count cannot exceed total target count")
	}
	if update.QualityClass != "" && update.QualityClass != "UNKNOWN" && update.QualityClass != "FULL" && update.QualityClass != "LIMITED" && update.QualityClass != "FAILED" {
		return errors.New("path result quality class is invalid")
	}
	if update.QualityClass == "FULL" && update.State != StateQualified {
		return errors.New("FULL path result requires QUALIFIED state")
	}
	if update.QualityClass == "LIMITED" && (update.State != StateDegraded || update.TransportState != "PASSED" || update.SelectedNodeID == "" || update.FunctionalScore <= 0 || update.RequiredTargetsPassed == update.RequiredTargetsTotal) {
		return errors.New("LIMITED path result requires a selected degraded path with partial access and positive score")
	}
	if update.QualityClass == "FAILED" && update.State != StateFailed {
		return errors.New("FAILED path result requires FAILED state")
	}
	if !update.ExpiresAt.IsZero() && !update.LastCheckedAt.IsZero() && !update.ExpiresAt.After(update.LastCheckedAt) {
		return errors.New("path result expiry must be after check time")
	}
	if update.State == StateQualified {
		if update.TransportState != "PASSED" || update.SelectedNodeID == "" || update.QualifiedNodes == 0 || update.RequiredTargetsTotal == 0 || update.RequiredTargetsPassed != update.RequiredTargetsTotal {
			return errors.New("qualified path requires passed transport, selected node, qualified candidate, and all required targets")
		}
	}
	return nil
}

func resultQuality(update ResultUpdate) (string, int64) {
	if update.QualityClass != "" {
		return update.QualityClass, update.FunctionalScore
	}
	switch update.State {
	case StateQualified:
		return "FULL", update.RequiredTargetsPassed*1000 + update.OptionalTargetsPassed
	case StateDegraded:
		score := update.RequiredTargetsPassed*1000 + update.OptionalTargetsPassed
		if score == 0 && update.TransportState == "PASSED" {
			score = 1
		}
		return "LIMITED", score
	case StateFailed:
		return "FAILED", 0
	default:
		return "UNKNOWN", 0
	}
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullIfZero(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func formatOptionalTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

const cellSelect = `
SELECT p.id, p.uplink_id, u.display_number, u.type, u.name, u.priority,
       p.subscription_id, s.name, s.priority, p.state, p.transport_state,
       p.selected_node_id, p.candidate_nodes, p.qualified_nodes,
       p.required_targets_passed, p.required_targets_total,
       p.optional_targets_passed, p.optional_targets_total,
       p.quality_class, p.functional_score, p.latency_ms,
       p.policy_generation, p.route_generation, p.last_checked_at,
       p.expires_at, p.created_at, p.updated_at
FROM subscription_uplink_paths AS p
JOIN uplinks AS u ON u.id=p.uplink_id
JOIN subscriptions AS s ON s.id=p.subscription_id`

type scanner interface {
	Scan(dest ...any) error
}

func scanCell(row scanner) (Cell, error) {
	var item Cell
	var selectedNodeID, lastCheckedAt, expiresAt sql.NullString
	var latencyMS sql.NullInt64
	err := row.Scan(
		&item.ID,
		&item.UplinkID,
		&item.UplinkDisplayNumber,
		&item.UplinkType,
		&item.UplinkName,
		&item.UplinkPriority,
		&item.SubscriptionID,
		&item.SubscriptionName,
		&item.SubscriptionPriority,
		&item.State,
		&item.TransportState,
		&selectedNodeID,
		&item.CandidateNodes,
		&item.QualifiedNodes,
		&item.RequiredTargetsPassed,
		&item.RequiredTargetsTotal,
		&item.OptionalTargetsPassed,
		&item.OptionalTargetsTotal,
		&item.QualityClass,
		&item.FunctionalScore,
		&latencyMS,
		&item.PolicyGeneration,
		&item.RouteGeneration,
		&lastCheckedAt,
		&expiresAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	item.SelectedNodeID = selectedNodeID.String
	if item.UplinkType == "HILINK" {
		item.ModemID, item.ModemDisplayNumber, item.ModemName, item.ModemPriority = item.UplinkID, item.UplinkDisplayNumber, item.UplinkName, item.UplinkPriority
	}
	item.LatencyMS = latencyMS.Int64
	item.LastCheckedAt = lastCheckedAt.String
	item.ExpiresAt = expiresAt.String
	return item, err
}
