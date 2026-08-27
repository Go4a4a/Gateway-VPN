package accesspolicy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

type DirectPathRepository struct {
	database *sql.DB
	now      func() time.Time
}

type DirectPath struct {
	ID                    string
	ModemID               string
	ModemNumber           int64
	ModemName             string
	ModemPriority         int64
	MethodEnabled         bool
	MethodPriority        int64
	State                 string
	TransportState        string
	QualityClass          string
	FunctionalScore       int64
	RequiredTargetsPassed int64
	RequiredTargetsTotal  int64
	OptionalTargetsPassed int64
	OptionalTargetsTotal  int64
	LatencyMS             int64
	PolicyGeneration      int64
	RouteGeneration       int64
	LastCheckedAt         string
	ExpiresAt             string
	FailureCode           string
	UpdatedAt             string
}

type DirectTargetResult struct {
	TargetID   string
	State      string
	LatencyMS  int64
	HTTPStatus int
	ErrorCode  string
	CheckedAt  time.Time
	ExpiresAt  time.Time
}

type DirectResultUpdate struct {
	PathID                   string
	ExpectedPolicyGeneration int64
	ExpectedRouteGeneration  int64
	TransportState           string
	QualityClass             string
	FunctionalScore          int64
	RequiredTargetsPassed    int64
	RequiredTargetsTotal     int64
	OptionalTargetsPassed    int64
	OptionalTargetsTotal     int64
	LatencyMS                int64
	FailureCode              string
	CheckedAt                time.Time
	ExpiresAt                time.Time
	Targets                  []DirectTargetResult
}

func NewDirectPathRepository(database *sql.DB) *DirectPathRepository {
	return &DirectPathRepository{database: database, now: time.Now}
}

func (repository *DirectPathRepository) Reconcile(ctx context.Context) error {
	if repository == nil || repository.database == nil {
		return errors.New("direct path database is required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin direct path reconcile: %w", err)
	}
	defer transaction.Rollback()
	policyGeneration, err := currentPolicyGeneration(ctx, transaction)
	if err != nil {
		return err
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO direct_modem_paths (
    id, modem_id, state, transport_state, quality_class,
    policy_generation, route_generation, created_at, updated_at
)
SELECT
    'direct:path:' || m.id,
    m.id,
    CASE
        WHEN m.enabled=0 THEN 'MODEM_DISABLED'
        WHEN m.state='MODEM_SUBNET_CONFLICT' THEN 'SUBNET_CONFLICT'
        WHEN m.state<>'MODEM_READY' THEN 'MODEM_OFFLINE'
        ELSE 'UNTESTED'
    END,
    'UNKNOWN', 'UNKNOWN', ?, m.route_generation, ?, ?
FROM modems AS m
WHERE 1=1
ON CONFLICT(modem_id) DO NOTHING`, policyGeneration, now, now); err != nil {
		return fmt.Errorf("create direct modem paths: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE direct_modem_paths AS p
SET state=CASE
        WHEN m.enabled=0 THEN 'MODEM_DISABLED'
        WHEN m.state='MODEM_SUBNET_CONFLICT' THEN 'SUBNET_CONFLICT'
        WHEN m.state<>'MODEM_READY' THEN 'MODEM_OFFLINE'
        WHEN p.policy_generation<>? OR p.route_generation<>m.route_generation THEN 'STALE'
        WHEN p.state IN ('MODEM_DISABLED', 'SUBNET_CONFLICT', 'MODEM_OFFLINE') THEN 'UNTESTED'
        ELSE p.state
    END,
    transport_state=CASE WHEN m.enabled=0 OR m.state<>'MODEM_READY' OR p.policy_generation<>? OR p.route_generation<>m.route_generation THEN 'UNKNOWN' ELSE p.transport_state END,
    quality_class=CASE WHEN m.enabled=0 OR m.state<>'MODEM_READY' OR p.policy_generation<>? OR p.route_generation<>m.route_generation THEN 'UNKNOWN' ELSE p.quality_class END,
    functional_score=CASE WHEN m.enabled=0 OR m.state<>'MODEM_READY' OR p.policy_generation<>? OR p.route_generation<>m.route_generation THEN 0 ELSE p.functional_score END,
    required_targets_passed=CASE WHEN m.enabled=0 OR m.state<>'MODEM_READY' OR p.policy_generation<>? OR p.route_generation<>m.route_generation THEN 0 ELSE p.required_targets_passed END,
    optional_targets_passed=CASE WHEN m.enabled=0 OR m.state<>'MODEM_READY' OR p.policy_generation<>? OR p.route_generation<>m.route_generation THEN 0 ELSE p.optional_targets_passed END,
    latency_ms=CASE WHEN m.enabled=0 OR m.state<>'MODEM_READY' OR p.policy_generation<>? OR p.route_generation<>m.route_generation THEN NULL ELSE p.latency_ms END,
    last_checked_at=CASE WHEN m.enabled=0 OR m.state<>'MODEM_READY' OR p.policy_generation<>? OR p.route_generation<>m.route_generation THEN NULL ELSE p.last_checked_at END,
    expires_at=CASE WHEN m.enabled=0 OR m.state<>'MODEM_READY' OR p.policy_generation<>? OR p.route_generation<>m.route_generation THEN NULL ELSE p.expires_at END,
    failure_code=CASE WHEN p.policy_generation<>? OR p.route_generation<>m.route_generation THEN NULL ELSE p.failure_code END,
    policy_generation=?,
    route_generation=m.route_generation,
    updated_at=?
FROM modems AS m
WHERE p.modem_id=m.id`,
		policyGeneration, policyGeneration, policyGeneration, policyGeneration, policyGeneration,
		policyGeneration, policyGeneration, policyGeneration, policyGeneration, policyGeneration,
		policyGeneration, now); err != nil {
		return fmt.Errorf("refresh direct modem path states: %w", err)
	}
	return transaction.Commit()
}

func (repository *DirectPathRepository) List(ctx context.Context) ([]DirectPath, error) {
	rows, err := repository.database.QueryContext(ctx, directPathSelect+" ORDER BY m.enabled DESC, m.priority, m.display_number")
	if err != nil {
		return nil, fmt.Errorf("list direct modem paths: %w", err)
	}
	defer rows.Close()
	result := []DirectPath{}
	for rows.Next() {
		item, err := scanDirectPath(rows)
		if err != nil {
			return nil, fmt.Errorf("scan direct modem path: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (repository *DirectPathRepository) Get(ctx context.Context, pathID string) (DirectPath, error) {
	if repository == nil || repository.database == nil || strings.TrimSpace(pathID) == "" {
		return DirectPath{}, errors.New("direct path database and id are required")
	}
	item, err := scanDirectPath(repository.database.QueryRowContext(ctx, directPathSelect+" WHERE p.id=?", pathID))
	if errors.Is(err, sql.ErrNoRows) {
		return DirectPath{}, store.ErrNotFound
	}
	if err != nil {
		return DirectPath{}, fmt.Errorf("get direct modem path: %w", err)
	}
	return item, nil
}

func (repository *DirectPathRepository) Publish(ctx context.Context, update DirectResultUpdate) error {
	if err := validateDirectResult(update); err != nil {
		return err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin direct path result: %w", err)
	}
	defer transaction.Rollback()
	policyGeneration, err := currentPolicyGeneration(ctx, transaction)
	if err != nil {
		return err
	}
	if update.ExpectedPolicyGeneration != policyGeneration {
		return store.ErrStaleGeneration
	}
	state := "FAILED"
	switch update.QualityClass {
	case QualityFull:
		state = "QUALIFIED"
	case QualityLimited:
		state = "DEGRADED"
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE direct_modem_paths
SET state=?, transport_state=?, quality_class=?, functional_score=?,
    required_targets_passed=?, required_targets_total=?,
    optional_targets_passed=?, optional_targets_total=?, latency_ms=?,
    last_checked_at=?, expires_at=?, failure_code=?, updated_at=?
WHERE id=? AND policy_generation=? AND route_generation=?
  AND route_generation=(
      SELECT m.route_generation
      FROM modems AS m
      WHERE m.id=direct_modem_paths.modem_id
  )`,
		state, update.TransportState, update.QualityClass, update.FunctionalScore,
		update.RequiredTargetsPassed, update.RequiredTargetsTotal,
		update.OptionalTargetsPassed, update.OptionalTargetsTotal, nullInt(update.LatencyMS),
		update.CheckedAt.UTC().Format(time.RFC3339Nano), update.ExpiresAt.UTC().Format(time.RFC3339Nano), nullText(update.FailureCode), now,
		update.PathID, update.ExpectedPolicyGeneration, update.ExpectedRouteGeneration)
	if err != nil {
		return fmt.Errorf("publish direct path result: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return store.ErrStaleGeneration
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM direct_path_target_results WHERE path_id=?", update.PathID); err != nil {
		return fmt.Errorf("replace direct target results: %w", err)
	}
	seen := make(map[string]struct{}, len(update.Targets))
	for _, target := range update.Targets {
		if _, exists := seen[target.TargetID]; exists {
			return errors.New("duplicate direct target result")
		}
		seen[target.TargetID] = struct{}{}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO direct_path_target_results (
    path_id, target_id, state, latency_ms, http_status, error_code,
    checked_at, expires_at, policy_generation, route_generation
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			update.PathID, target.TargetID, target.State, nullInt(target.LatencyMS), nullInt(int64(target.HTTPStatus)), nullText(target.ErrorCode),
			target.CheckedAt.UTC().Format(time.RFC3339Nano), target.ExpiresAt.UTC().Format(time.RFC3339Nano), update.ExpectedPolicyGeneration, update.ExpectedRouteGeneration); err != nil {
			return fmt.Errorf("insert direct target result: %w", err)
		}
	}
	var requiredPassed, requiredTotal, optionalPassed, optionalTotal int64
	if err := transaction.QueryRowContext(ctx, `
SELECT
    COALESCE(SUM(CASE WHEN t.required=1 AND r.state='PASSED' THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN t.required=1 THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN t.required=0 AND r.state='PASSED' THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN t.required=0 THEN 1 ELSE 0 END), 0)
FROM direct_path_target_results AS r
JOIN bypass_probe_targets AS t ON t.id=r.target_id AND t.enabled=1
WHERE r.path_id=? AND r.policy_generation=? AND r.route_generation=?`,
		update.PathID, update.ExpectedPolicyGeneration, update.ExpectedRouteGeneration,
	).Scan(&requiredPassed, &requiredTotal, &optionalPassed, &optionalTotal); err != nil {
		return fmt.Errorf("verify direct target evidence: %w", err)
	}
	if requiredPassed != update.RequiredTargetsPassed || requiredTotal != update.RequiredTargetsTotal ||
		optionalPassed != update.OptionalTargetsPassed || optionalTotal != update.OptionalTargetsTotal {
		return errors.New("direct target evidence does not match the active target policy")
	}
	var activeRequiredTotal, activeOptionalTotal int64
	if err := transaction.QueryRowContext(ctx, `
SELECT
    COALESCE(SUM(CASE WHEN required=1 THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN required=0 THEN 1 ELSE 0 END), 0)
FROM bypass_probe_targets
WHERE enabled=1`).Scan(&activeRequiredTotal, &activeOptionalTotal); err != nil {
		return fmt.Errorf("read active direct target policy: %w", err)
	}
	if requiredTotal != activeRequiredTotal || optionalTotal != activeOptionalTotal {
		return errors.New("direct target evidence does not cover every active target")
	}
	return transaction.Commit()
}

// Candidates returns one coherent fresh snapshot for unified ranking. VPN
// cells use the same access-method priority table as direct and join durable
// node preference ranks by fingerprint.
func (repository *DirectPathRepository) Candidates(ctx context.Context, directOnly bool) ([]Candidate, error) {
	if repository == nil || repository.database == nil {
		return nil, errors.New("direct path database is required")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	policyGeneration, err := currentPolicyGeneration(ctx, repository.database)
	if err != nil {
		return nil, err
	}
	result := []Candidate{}
	directRows, err := repository.database.QueryContext(ctx, `
SELECT p.id, p.id, a.id, p.modem_id, p.quality_class, p.functional_score,
       a.priority, m.priority, p.policy_generation, p.route_generation
FROM direct_modem_paths AS p
JOIN modems AS m ON m.id=p.modem_id
JOIN access_methods AS a ON a.id='access:direct'
WHERE a.enabled=1 AND m.enabled=1 AND m.state='MODEM_READY'
	AND ((p.quality_class='FULL' AND p.state='QUALIFIED')
	     OR (p.quality_class='LIMITED' AND p.state='DEGRADED'))
	AND p.transport_state='PASSED' AND julianday(p.expires_at)>julianday(?)
  AND p.policy_generation=? AND p.route_generation=m.route_generation`, now, policyGeneration)
	if err != nil {
		return nil, fmt.Errorf("list direct access candidates: %w", err)
	}
	for directRows.Next() {
		var item Candidate
		if err := directRows.Scan(&item.Key, &item.PathID, &item.MethodID, &item.ModemID, &item.Quality, &item.FunctionalScore, &item.MethodPriority, &item.ModemPriority, &item.PolicyGeneration, &item.RouteGeneration); err != nil {
			directRows.Close()
			return nil, err
		}
		item.MethodKind = MethodDirect
		item.MethodEnabled, item.ModemReady, item.NodeAllowed, item.Fresh = true, true, true, true
		result = append(result, item)
	}
	if err := directRows.Err(); err != nil {
		directRows.Close()
		return nil, err
	}
	if err := directRows.Close(); err != nil {
		return nil, err
	}
	if directOnly {
		return result, nil
	}
	vpnRows, err := repository.database.QueryContext(ctx, `
SELECT p.id || ':' || n.id, p.id, a.id, p.modem_id, p.subscription_id, n.id,
       p.quality_class, p.functional_score, a.priority, m.priority,
       COALESCE(pref.preferred_rank, 1000000000), p.policy_generation, p.route_generation
FROM subscription_modem_paths AS p
JOIN modems AS m ON m.id=p.modem_id
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN access_methods AS a ON a.subscription_id=s.id AND a.kind='SUBSCRIPTION'
JOIN nodes AS n ON n.id=p.selected_node_id AND n.version_id=s.active_version_id
JOIN path_nodes AS pn ON pn.path_id=p.id AND pn.node_id=n.id
LEFT JOIN subscription_node_preferences AS pref
       ON pref.subscription_id=s.id AND pref.fingerprint=n.fingerprint
WHERE a.enabled=1 AND s.enabled=1 AND m.enabled=1 AND m.state='MODEM_READY'
  AND n.enabled=1 AND n.selection_override<>'exclude'
	AND p.transport_state='PASSED' AND julianday(p.expires_at)>julianday(?)
  AND pn.qualification_generation=p.policy_generation
  AND pn.route_generation=p.route_generation AND julianday(pn.qualification_expires_at)>julianday(?)
  AND ((p.quality_class='FULL' AND p.state='QUALIFIED' AND pn.qualification_state='BYPASS_QUALIFIED')
       OR (p.quality_class='LIMITED' AND p.state='DEGRADED' AND pn.qualification_state='BYPASS_LIMITED'))
  AND p.policy_generation=? AND p.route_generation=m.route_generation`, now, now, policyGeneration)
	if err != nil {
		return nil, fmt.Errorf("list VPN access candidates: %w", err)
	}
	defer vpnRows.Close()
	for vpnRows.Next() {
		var item Candidate
		if err := vpnRows.Scan(&item.Key, &item.PathID, &item.MethodID, &item.ModemID, &item.SubscriptionID, &item.NodeID, &item.Quality, &item.FunctionalScore, &item.MethodPriority, &item.ModemPriority, &item.NodePriority, &item.PolicyGeneration, &item.RouteGeneration); err != nil {
			return nil, err
		}
		item.MethodKind = MethodSubscription
		item.MethodEnabled, item.ModemReady, item.NodeAllowed, item.Fresh = true, true, true, true
		result = append(result, item)
	}
	return result, vpnRows.Err()
}

func (repository *DirectPathRepository) BestCandidate(ctx context.Context, directOnly bool, currentKey string) (Decision, error) {
	items, err := repository.Candidates(ctx, directOnly)
	if err != nil {
		return Decision{}, err
	}
	return Rank(items, currentKey)
}

func validateDirectResult(update DirectResultUpdate) error {
	if strings.TrimSpace(update.PathID) == "" || update.ExpectedPolicyGeneration < 0 || update.ExpectedRouteGeneration < 0 || update.CheckedAt.IsZero() || !update.ExpiresAt.After(update.CheckedAt) {
		return errors.New("direct result identity, generations, or freshness is invalid")
	}
	if update.TransportState != "PASSED" && update.TransportState != "FAILED" {
		return errors.New("direct result transport state is invalid")
	}
	if update.QualityClass != QualityFull && update.QualityClass != QualityLimited && update.QualityClass != QualityFailed {
		return errors.New("direct result quality class is invalid")
	}
	if update.FunctionalScore < 0 || update.RequiredTargetsPassed < 0 || update.RequiredTargetsTotal < 0 || update.OptionalTargetsPassed < 0 || update.OptionalTargetsTotal < 0 || update.LatencyMS < 0 || update.RequiredTargetsPassed > update.RequiredTargetsTotal || update.OptionalTargetsPassed > update.OptionalTargetsTotal {
		return errors.New("direct result counters are invalid")
	}
	if len(update.Targets) != int(update.RequiredTargetsTotal+update.OptionalTargetsTotal) {
		return errors.New("direct target evidence count does not match result totals")
	}
	if update.QualityClass == QualityFull && (update.TransportState != "PASSED" || update.RequiredTargetsTotal == 0 || update.RequiredTargetsPassed != update.RequiredTargetsTotal) {
		return errors.New("FULL direct result requires passed transport and every required target")
	}
	if update.QualityClass == QualityLimited && (update.TransportState != "PASSED" || update.FunctionalScore <= 0 || update.RequiredTargetsTotal > 0 && update.RequiredTargetsPassed == update.RequiredTargetsTotal) {
		return errors.New("LIMITED direct result requires partial target access and positive score")
	}
	for _, target := range update.Targets {
		if target.TargetID == "" || (target.State != "PASSED" && target.State != "FAILED") || target.LatencyMS < 0 || target.CheckedAt.IsZero() || !target.ExpiresAt.After(target.CheckedAt) {
			return errors.New("direct target evidence is invalid")
		}
	}
	return nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func currentPolicyGeneration(ctx context.Context, queryer queryRower) (int64, error) {
	var value string
	err := queryer.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key='next_policy_generation'").Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read current direct policy generation: %w", err)
	}
	next, err := strconv.ParseInt(value, 10, 64)
	if err != nil || next < 1 {
		return 0, errors.New("stored direct policy generation is invalid")
	}
	return next - 1, nil
}

const directPathSelect = `
SELECT p.id, p.modem_id, m.display_number, m.name, m.priority,
       a.enabled, a.priority, p.state, p.transport_state, p.quality_class,
       p.functional_score, p.required_targets_passed, p.required_targets_total,
       p.optional_targets_passed, p.optional_targets_total, p.latency_ms,
       p.policy_generation, p.route_generation, p.last_checked_at, p.expires_at,
       p.failure_code, p.updated_at
FROM direct_modem_paths AS p
JOIN modems AS m ON m.id=p.modem_id
JOIN access_methods AS a ON a.id='access:direct'`

type scanner interface {
	Scan(...any) error
}

func scanDirectPath(row scanner) (DirectPath, error) {
	var item DirectPath
	var enabled int
	var latency sql.NullInt64
	var lastChecked, expires, failure sql.NullString
	err := row.Scan(
		&item.ID, &item.ModemID, &item.ModemNumber, &item.ModemName, &item.ModemPriority,
		&enabled, &item.MethodPriority, &item.State, &item.TransportState, &item.QualityClass,
		&item.FunctionalScore, &item.RequiredTargetsPassed, &item.RequiredTargetsTotal,
		&item.OptionalTargetsPassed, &item.OptionalTargetsTotal, &latency,
		&item.PolicyGeneration, &item.RouteGeneration, &lastChecked, &expires, &failure, &item.UpdatedAt,
	)
	item.MethodEnabled = enabled != 0
	item.LatencyMS = latency.Int64
	item.LastCheckedAt = lastChecked.String
	item.ExpiresAt = expires.String
	item.FailureCode = failure.String
	return item, err
}

func nullInt(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
