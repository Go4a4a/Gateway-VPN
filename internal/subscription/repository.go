// Package subscription owns subscription configuration and ordering. Source
// credentials are referenced by secret path and never returned as a URL.
package subscription

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

type Repository struct {
	database *sql.DB
	now      func() time.Time
}

type CreateInput struct {
	ID              string
	Name            string
	SourceType      string
	SourceSecretRef string
	RefreshInterval time.Duration
}

type UpdateInput struct {
	Name                            string
	AutoRefresh                     bool
	RefreshInterval                 time.Duration
	FallbackWhenNamedCandidatesFail bool
}

type Subscription struct {
	ID                              string
	DisplayNumber                   int64
	Name                            string
	SourceType                      string
	SourceSecretRef                 string
	Enabled                         bool
	Priority                        int64
	AutoRefresh                     bool
	RefreshIntervalSeconds          int64
	FallbackWhenNamedCandidatesFail bool
	Status                          string
	ActiveVersionID                 string
	LastRefreshAt                   string
	LastSuccessAt                   string
	CreatedAt                       string
	UpdatedAt                       string
}

func NewRepository(database *sql.DB) *Repository {
	return &Repository{database: database, now: time.Now}
}

func (repository *Repository) Create(ctx context.Context, input CreateInput) (Subscription, error) {
	if err := validateCreateInput(input); err != nil {
		return Subscription{}, err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Subscription{}, fmt.Errorf("begin subscription create: %w", err)
	}
	defer transaction.Rollback()

	var priority int64
	if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM subscriptions WHERE enabled=1").Scan(&priority); err != nil {
		return Subscription{}, fmt.Errorf("allocate subscription priority: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	displayNumber, err := store.AllocateCounter(ctx, transaction, "next_subscription_display_number", 1, now)
	if err != nil {
		return Subscription{}, err
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO subscriptions (
    id, display_number, name, source_type, source_secret_ref, enabled, priority, auto_refresh,
    refresh_interval_seconds, fallback_when_named_candidates_fail, status,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, 1, ?, 1, ?, 0, 'UNKNOWN', ?, ?)`,
		input.ID,
		displayNumber,
		strings.TrimSpace(input.Name),
		input.SourceType,
		input.SourceSecretRef,
		priority,
		int64(input.RefreshInterval/time.Second),
		now,
		now,
	)
	if err != nil {
		return Subscription{}, fmt.Errorf("insert subscription: %w", err)
	}
	if err := appendSubscriptionEventTx(ctx, transaction, now, "SUBSCRIPTION_CREATED", input.ID, map[string]any{"display_number": displayNumber, "name": strings.TrimSpace(input.Name), "source_type": input.SourceType, "refresh_interval_seconds": int64(input.RefreshInterval / time.Second)}); err != nil {
		return Subscription{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Subscription{}, fmt.Errorf("commit subscription create: %w", err)
	}
	return repository.Get(ctx, input.ID)
}

func (repository *Repository) Get(ctx context.Context, id string) (Subscription, error) {
	item, err := scanSubscription(repository.database.QueryRowContext(ctx, subscriptionSelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Subscription{}, store.ErrNotFound
	}
	if err != nil {
		return Subscription{}, fmt.Errorf("get subscription: %w", err)
	}
	return item, nil
}

func (repository *Repository) List(ctx context.Context) ([]Subscription, error) {
	rows, err := repository.database.QueryContext(ctx, subscriptionSelect+" ORDER BY enabled DESC, priority, display_number")
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}
	defer rows.Close()
	var result []Subscription
	for rows.Next() {
		item, err := scanSubscription(rows)
		if err != nil {
			return nil, fmt.Errorf("scan subscription: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscriptions: %w", err)
	}
	return result, nil
}

func (repository *Repository) ReorderEnabled(ctx context.Context, orderedIDs []string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription reorder: %w", err)
	}
	defer transaction.Rollback()

	if err := validateEnabledSet(ctx, transaction, orderedIDs); err != nil {
		return err
	}
	// rowid is unique and stable for this transaction, so negative temporary
	// priorities cannot collide with enabled positive priorities.
	if _, err := transaction.ExecContext(ctx, "UPDATE subscriptions SET priority=-rowid WHERE enabled=1"); err != nil {
		return fmt.Errorf("temporarily clear subscription priorities: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	for index, id := range orderedIDs {
		result, err := transaction.ExecContext(ctx, "UPDATE subscriptions SET priority=?, updated_at=? WHERE id=? AND enabled=1", (index+1)*10, now, id)
		if err != nil {
			return fmt.Errorf("set subscription priority: %w", err)
		}
		updated, err := result.RowsAffected()
		if err != nil || updated != 1 {
			return store.ErrPrioritySetMismatch
		}
	}
	if err := appendSubscriptionEventTx(ctx, transaction, now, "SUBSCRIPTION_PRIORITY_REORDERED", "", map[string]any{"ordered_subscription_ids": orderedIDs}); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit subscription reorder: %w", err)
	}
	return nil
}

func (repository *Repository) Update(ctx context.Context, id string, input UpdateInput) error {
	if err := validateUpdateInput(input); err != nil {
		return err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription update: %w", err)
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE subscriptions
SET name=?, auto_refresh=?, refresh_interval_seconds=?, fallback_when_named_candidates_fail=?, updated_at=?
WHERE id=?`, strings.TrimSpace(input.Name), boolToInt(input.AutoRefresh), int64(input.RefreshInterval/time.Second), boolToInt(input.FallbackWhenNamedCandidatesFail), now, id)
	if err != nil {
		return fmt.Errorf("update subscription: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return store.ErrNotFound
	}
	if err := appendSubscriptionEventTx(ctx, transaction, now, "SUBSCRIPTION_UPDATED", id, map[string]any{"name": strings.TrimSpace(input.Name), "auto_refresh": input.AutoRefresh, "refresh_interval_seconds": int64(input.RefreshInterval / time.Second), "fallback_when_named_candidates_fail": input.FallbackWhenNamedCandidatesFail}); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *Repository) SetEnabled(ctx context.Context, id string, enabled bool) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription enabled update: %w", err)
	}
	defer transaction.Rollback()
	var currentEnabled int
	var priority int64
	if err := transaction.QueryRowContext(ctx, "SELECT enabled, priority FROM subscriptions WHERE id=?", id).Scan(&currentEnabled, &priority); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return err
	}
	if enabled == (currentEnabled != 0) {
		return transaction.Commit()
	}
	if enabled {
		if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM subscriptions WHERE enabled=1").Scan(&priority); err != nil {
			return err
		}
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	status := "DISABLED"
	pathState := "SUBSCRIPTION_DISABLED"
	if enabled {
		status = "UNKNOWN"
		pathState = "UNTESTED"
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE subscriptions SET enabled=?, priority=?, status=?, updated_at=? WHERE id=?", boolToInt(enabled), priority, status, now, id); err != nil {
		return fmt.Errorf("update subscription enabled state: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_modem_paths
SET state=?, transport_state='UNKNOWN', selected_node_id=NULL,
    qualified_nodes=0, required_targets_passed=0, expires_at=NULL, updated_at=?
WHERE subscription_id=?`, pathState, now, id); err != nil {
		return fmt.Errorf("update subscription path enabled state: %w", err)
	}
	if err := appendSubscriptionEventTx(ctx, transaction, now, "SUBSCRIPTION_ENABLED_CHANGED", id, map[string]any{"enabled": enabled, "priority": priority}); err != nil {
		return err
	}
	return transaction.Commit()
}

func (repository *Repository) Delete(ctx context.Context, id string) (string, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin subscription delete: %w", err)
	}
	defer transaction.Rollback()
	var enabled int
	var secretRef string
	if err := transaction.QueryRowContext(ctx, "SELECT enabled, COALESCE(source_secret_ref, '') FROM subscriptions WHERE id=?", id).Scan(&enabled, &secretRef); errors.Is(err, sql.ErrNoRows) {
		return "", store.ErrNotFound
	} else if err != nil {
		return "", err
	}
	if enabled != 0 {
		return "", errors.New("subscription must be disabled before deletion")
	}
	var activeID sql.NullString
	if err := transaction.QueryRowContext(ctx, "SELECT active_subscription_id FROM runtime_state WHERE singleton_id=1").Scan(&activeID); err != nil {
		return "", err
	}
	if activeID.String == id {
		return "", errors.New("active subscription cannot be deleted")
	}
	result, err := transaction.ExecContext(ctx, "DELETE FROM subscriptions WHERE id=?", id)
	if err != nil {
		return "", fmt.Errorf("delete subscription: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return "", store.ErrNotFound
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if err := appendSubscriptionEventTx(ctx, transaction, now, "SUBSCRIPTION_DELETED", id, nil); err != nil {
		return "", err
	}
	if err := transaction.Commit(); err != nil {
		return "", fmt.Errorf("commit subscription delete: %w", err)
	}
	return secretRef, nil
}

func validateCreateInput(input CreateInput) error {
	if strings.TrimSpace(input.ID) == "" {
		return errors.New("subscription id is required")
	}
	if strings.TrimSpace(input.Name) == "" || len(strings.TrimSpace(input.Name)) > 128 {
		return errors.New("subscription name is required")
	}
	if input.SourceType != "url" && input.SourceType != "upload" {
		return errors.New("subscription source type must be url or upload")
	}
	if strings.TrimSpace(input.SourceSecretRef) == "" {
		return errors.New("subscription source secret reference is required")
	}
	if input.RefreshInterval < time.Minute || input.RefreshInterval > 30*24*time.Hour {
		return errors.New("subscription refresh interval must be 1 minute..30 days")
	}
	return nil
}

func validateUpdateInput(input UpdateInput) error {
	if strings.TrimSpace(input.Name) == "" || len(strings.TrimSpace(input.Name)) > 128 {
		return errors.New("subscription name is required and limited to 128 characters")
	}
	if input.RefreshInterval < time.Minute || input.RefreshInterval > 30*24*time.Hour {
		return errors.New("subscription refresh interval must be 1 minute..30 days")
	}
	return nil
}

func appendSubscriptionEventTx(ctx context.Context, transaction *sql.Tx, now, eventType, subscriptionID string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	content, err := json.Marshal(details)
	if err != nil {
		return errors.New("encode subscription audit event failed")
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, subscription_id, details_json)
VALUES (?, 'INFO', ?, ?, ?)`, now, eventType, nullIfEmpty(subscriptionID), string(content)); err != nil {
		return fmt.Errorf("append subscription audit event: %w", err)
	}
	return nil
}

func nullIfEmpty(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

func validateEnabledSet(ctx context.Context, transaction *sql.Tx, orderedIDs []string) error {
	seen := make(map[string]struct{}, len(orderedIDs))
	for _, id := range orderedIDs {
		if id == "" {
			return store.ErrPrioritySetMismatch
		}
		if _, exists := seen[id]; exists {
			return store.ErrPrioritySetMismatch
		}
		seen[id] = struct{}{}
	}
	rows, err := transaction.QueryContext(ctx, "SELECT id FROM subscriptions WHERE enabled=1")
	if err != nil {
		return fmt.Errorf("read enabled subscriptions: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan enabled subscription: %w", err)
		}
		if _, exists := seen[id]; !exists {
			return store.ErrPrioritySetMismatch
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate enabled subscriptions: %w", err)
	}
	if count != len(orderedIDs) {
		return store.ErrPrioritySetMismatch
	}
	return nil
}

const subscriptionSelect = `
SELECT id, display_number, name, source_type, source_secret_ref, enabled, priority,
       auto_refresh, refresh_interval_seconds,
       fallback_when_named_candidates_fail, status, active_version_id,
       last_refresh_at, last_success_at, created_at, updated_at
FROM subscriptions`

type scanner interface {
	Scan(dest ...any) error
}

func scanSubscription(row scanner) (Subscription, error) {
	var item Subscription
	var sourceSecretRef, activeVersionID, lastRefreshAt, lastSuccessAt sql.NullString
	var enabled, autoRefresh, fallback int64
	err := row.Scan(
		&item.ID,
		&item.DisplayNumber,
		&item.Name,
		&item.SourceType,
		&sourceSecretRef,
		&enabled,
		&item.Priority,
		&autoRefresh,
		&item.RefreshIntervalSeconds,
		&fallback,
		&item.Status,
		&activeVersionID,
		&lastRefreshAt,
		&lastSuccessAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	item.SourceSecretRef = sourceSecretRef.String
	item.Enabled = enabled != 0
	item.AutoRefresh = autoRefresh != 0
	item.FallbackWhenNamedCandidatesFail = fallback != 0
	item.ActiveVersionID = activeVersionID.String
	item.LastRefreshAt = lastRefreshAt.String
	item.LastSuccessAt = lastSuccessAt.String
	return item, err
}
