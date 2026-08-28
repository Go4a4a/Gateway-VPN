package accesspolicy

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

const DirectMethodID = "access:direct"

type Repository struct {
	database *sql.DB
	now      func() time.Time
}

type Method struct {
	ID             string
	Kind           string
	SubscriptionID string
	Name           string
	Enabled        bool
	Priority       int64
	Immutable      bool
	CreatedAt      string
	UpdatedAt      string
}

type Policy struct {
	StartupBlockUntilQualified bool   `json:"startup_block_until_qualified"`
	DirectServiceRefresh       bool   `json:"direct_service_refresh_enabled"`
	FailureHoldSeconds         int64  `json:"failure_hold_seconds"`
	RecoveryStableSeconds      int64  `json:"recovery_stable_seconds"`
	SwitchCooldownSeconds      int64  `json:"switch_cooldown_seconds"`
	RankingGeneration          int64  `json:"ranking_generation"`
	UpdatedAt                  string `json:"updated_at"`
}

type PolicyUpdate struct {
	StartupBlockUntilQualified bool
	DirectServiceRefresh       bool
	FailureHoldSeconds         int64
	RecoveryStableSeconds      int64
	SwitchCooldownSeconds      int64
}

func NewRepository(database *sql.DB) *Repository {
	return &Repository{database: database, now: time.Now}
}

func (repository *Repository) ListMethods(ctx context.Context) ([]Method, error) {
	if repository == nil || repository.database == nil {
		return nil, errors.New("access policy database is required")
	}
	rows, err := repository.database.QueryContext(ctx, `
SELECT a.id, a.kind, a.subscription_id,
       CASE WHEN a.kind='DIRECT' THEN 'Прямой интернет' ELSE s.name END,
       a.enabled, a.priority, a.immutable, a.created_at, a.updated_at
FROM access_methods AS a
LEFT JOIN subscriptions AS s ON s.id=a.subscription_id
ORDER BY a.enabled DESC, a.priority, a.id`)
	if err != nil {
		return nil, fmt.Errorf("list access methods: %w", err)
	}
	defer rows.Close()
	result := []Method{}
	for rows.Next() {
		var item Method
		var subscriptionID sql.NullString
		var enabled, immutable int
		if err := rows.Scan(&item.ID, &item.Kind, &subscriptionID, &item.Name, &enabled, &item.Priority, &immutable, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan access method: %w", err)
		}
		item.SubscriptionID = subscriptionID.String
		item.Enabled = enabled != 0
		item.Immutable = immutable != 0
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access methods: %w", err)
	}
	return result, nil
}

func (repository *Repository) SetMethodEnabled(ctx context.Context, id string, enabled bool) error {
	if repository == nil || repository.database == nil || strings.TrimSpace(id) == "" {
		return errors.New("access policy database and method id are required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin access method update: %w", err)
	}
	defer transaction.Rollback()
	var kind string
	var subscriptionID sql.NullString
	var currentEnabled int
	var priority int64
	err = transaction.QueryRowContext(ctx, "SELECT kind, subscription_id, enabled, priority FROM access_methods WHERE id=?", id).Scan(&kind, &subscriptionID, &currentEnabled, &priority)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read access method: %w", err)
	}
	if enabled == (currentEnabled != 0) {
		return transaction.Commit()
	}
	if enabled {
		if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM access_methods WHERE enabled=1").Scan(&priority); err != nil {
			return fmt.Errorf("allocate access method priority: %w", err)
		}
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, "UPDATE access_methods SET enabled=?, priority=?, updated_at=? WHERE id=?", boolInt(enabled), priority, now, id); err != nil {
		return fmt.Errorf("update access method: %w", err)
	}
	if kind == MethodSubscription {
		status, pathState := "DISABLED", "SUBSCRIPTION_DISABLED"
		if enabled {
			status, pathState = "UNKNOWN", "UNTESTED"
		}
		if _, err := transaction.ExecContext(ctx, "UPDATE subscriptions SET enabled=?, status=?, updated_at=? WHERE id=?", boolInt(enabled), status, now, subscriptionID.String); err != nil {
			return fmt.Errorf("synchronize subscription routing state: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_uplink_paths
SET state=?, transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, expires_at=NULL, updated_at=?
WHERE subscription_id=?`, pathState, now, subscriptionID.String); err != nil {
			return fmt.Errorf("synchronize subscription paths: %w", err)
		}
	}
	if err := bumpRankingGeneration(ctx, transaction, now); err != nil {
		return err
	}
	if err := appendAccessEvent(ctx, transaction, now, "ACCESS_METHOD_ENABLED_CHANGED", map[string]any{"method_id": id, "kind": kind, "enabled": enabled, "priority": priority}); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *Repository) ReorderEnabled(ctx context.Context, orderedIDs []string) error {
	if repository == nil || repository.database == nil {
		return errors.New("access policy database is required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin access method reorder: %w", err)
	}
	defer transaction.Rollback()
	if err := validateEnabledMethods(ctx, transaction, orderedIDs); err != nil {
		return err
	}
	var maximum int64
	if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) FROM access_methods").Scan(&maximum); err != nil {
		return fmt.Errorf("read access method priority ceiling: %w", err)
	}
	for index, id := range orderedIDs {
		temporary := maximum + int64(index) + 1
		if _, err := transaction.ExecContext(ctx, "UPDATE access_methods SET priority=? WHERE id=? AND enabled=1", temporary, id); err != nil {
			return fmt.Errorf("stage access method priority: %w", err)
		}
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	for index, id := range orderedIDs {
		result, err := transaction.ExecContext(ctx, "UPDATE access_methods SET priority=?, updated_at=? WHERE id=? AND enabled=1", int64(index+1)*10, now, id)
		if err != nil {
			return fmt.Errorf("set access method priority: %w", err)
		}
		if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
			return store.ErrPrioritySetMismatch
		}
	}
	if err := bumpRankingGeneration(ctx, transaction, now); err != nil {
		return err
	}
	if err := appendAccessEvent(ctx, transaction, now, "ACCESS_METHODS_REORDERED", map[string]any{"ordered_method_ids": orderedIDs}); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *Repository) GetPolicy(ctx context.Context) (Policy, error) {
	if repository == nil || repository.database == nil {
		return Policy{}, errors.New("access policy database is required")
	}
	var result Policy
	var startup, direct int
	err := repository.database.QueryRowContext(ctx, `
SELECT startup_block_until_qualified, direct_service_refresh_enabled,
       failure_hold_seconds, recovery_stable_seconds, switch_cooldown_seconds,
       ranking_generation, updated_at
FROM access_policy WHERE singleton_id=1`).Scan(
		&startup, &direct, &result.FailureHoldSeconds, &result.RecoveryStableSeconds,
		&result.SwitchCooldownSeconds, &result.RankingGeneration, &result.UpdatedAt,
	)
	if err != nil {
		return Policy{}, fmt.Errorf("read access policy: %w", err)
	}
	result.StartupBlockUntilQualified = startup != 0
	result.DirectServiceRefresh = direct != 0
	return result, nil
}

func (repository *Repository) UpdatePolicy(ctx context.Context, input PolicyUpdate) (Policy, error) {
	if err := validatePolicyUpdate(input); err != nil {
		return Policy{}, err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, fmt.Errorf("begin access policy update: %w", err)
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE access_policy
SET startup_block_until_qualified=?, direct_service_refresh_enabled=?,
    failure_hold_seconds=?, recovery_stable_seconds=?, switch_cooldown_seconds=?,
    ranking_generation=ranking_generation+1, updated_at=?
WHERE singleton_id=1`, boolInt(input.StartupBlockUntilQualified), boolInt(input.DirectServiceRefresh),
		input.FailureHoldSeconds, input.RecoveryStableSeconds, input.SwitchCooldownSeconds, now)
	if err != nil {
		return Policy{}, fmt.Errorf("update access policy: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return Policy{}, errors.New("access policy singleton is missing")
	}
	if err := appendAccessEvent(ctx, transaction, now, "ACCESS_POLICY_UPDATED", map[string]any{
		"startup_block_until_qualified":  input.StartupBlockUntilQualified,
		"direct_service_refresh_enabled": input.DirectServiceRefresh,
		"failure_hold_seconds":           input.FailureHoldSeconds,
		"recovery_stable_seconds":        input.RecoveryStableSeconds,
		"switch_cooldown_seconds":        input.SwitchCooldownSeconds,
	}); err != nil {
		return Policy{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Policy{}, fmt.Errorf("commit access policy update: %w", err)
	}
	return repository.GetPolicy(ctx)
}

func validatePolicyUpdate(input PolicyUpdate) error {
	if input.FailureHoldSeconds < 0 || input.FailureHoldSeconds > 300 ||
		input.RecoveryStableSeconds < 0 || input.RecoveryStableSeconds > 3600 ||
		input.SwitchCooldownSeconds < 0 || input.SwitchCooldownSeconds > 3600 {
		return errors.New("access policy intervals are outside safe bounds")
	}
	return nil
}

func validateEnabledMethods(ctx context.Context, transaction *sql.Tx, orderedIDs []string) error {
	seen := make(map[string]struct{}, len(orderedIDs))
	for _, id := range orderedIDs {
		if strings.TrimSpace(id) == "" {
			return store.ErrPrioritySetMismatch
		}
		if _, exists := seen[id]; exists {
			return store.ErrPrioritySetMismatch
		}
		seen[id] = struct{}{}
	}
	rows, err := transaction.QueryContext(ctx, "SELECT id FROM access_methods WHERE enabled=1")
	if err != nil {
		return fmt.Errorf("read enabled access methods: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan enabled access method: %w", err)
		}
		if _, exists := seen[id]; !exists {
			return store.ErrPrioritySetMismatch
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate enabled access methods: %w", err)
	}
	if count != len(orderedIDs) {
		return store.ErrPrioritySetMismatch
	}
	return nil
}

func bumpRankingGeneration(ctx context.Context, transaction *sql.Tx, now string) error {
	result, err := transaction.ExecContext(ctx, "UPDATE access_policy SET ranking_generation=ranking_generation+1, updated_at=? WHERE singleton_id=1", now)
	if err != nil {
		return fmt.Errorf("advance access ranking generation: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return errors.New("access policy singleton is missing")
	}
	return nil
}

func appendAccessEvent(ctx context.Context, transaction *sql.Tx, now, eventType string, details map[string]any) error {
	payload, err := json.Marshal(details)
	if err != nil {
		return errors.New("encode access policy audit event failed")
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, 'INFO', ?, ?)`, now, eventType, string(payload)); err != nil {
		return fmt.Errorf("append access policy audit event: %w", err)
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
