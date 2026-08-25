package subscription

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

type MatcherRepository struct {
	database *sql.DB
	now      func() time.Time
}

type MatcherCreateInput struct {
	ID      string
	Pattern string
	Type    string
}

type MatcherUpdateInput struct {
	Pattern string
	Type    string
	Enabled bool
}

func NewMatcherRepository(database *sql.DB) *MatcherRepository {
	return &MatcherRepository{database: database, now: time.Now}
}

// EnsureDefaults seeds the initial marker policy once. Deleting every matcher
// later is respected and does not silently restore defaults on restart.
func (repository *MatcherRepository) EnsureDefaults(ctx context.Context) (bool, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin default matcher seed: %w", err)
	}
	defer transaction.Rollback()
	var marker string
	err = transaction.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key='node_matcher_defaults_initialized'").Scan(&marker)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("read default matcher marker: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	for _, matcher := range DefaultMatchers() {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO node_matchers(id, pattern, match_type, enabled, priority, created_at, updated_at)
VALUES (?, ?, ?, 1, ?, ?, ?)`, matcher.ID, matcher.Pattern, matcher.Type, matcher.Priority, now, now); err != nil {
			return false, fmt.Errorf("insert default matcher: %w", err)
		}
	}
	if _, err := transaction.ExecContext(ctx, "INSERT INTO settings(key, value_json, updated_at) VALUES ('node_matcher_defaults_initialized', 'true', ?)", now); err != nil {
		return false, fmt.Errorf("record default matcher seed: %w", err)
	}
	if err := reclassifyAllActiveNodesTx(ctx, transaction); err != nil {
		return false, fmt.Errorf("reclassify active nodes after default matcher seed: %w", err)
	}
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return false, fmt.Errorf("invalidate policy after default matcher seed: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return false, fmt.Errorf("commit default matcher seed: %w", err)
	}
	return true, nil
}

func (repository *MatcherRepository) Create(ctx context.Context, input MatcherCreateInput) (Matcher, error) {
	matcher := Matcher{ID: strings.TrimSpace(input.ID), Pattern: strings.TrimSpace(input.Pattern), Type: input.Type, Enabled: true}
	if _, err := CompileMatchers([]Matcher{matcher}); err != nil {
		return Matcher{}, err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Matcher{}, fmt.Errorf("begin matcher create: %w", err)
	}
	defer transaction.Rollback()
	if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM node_matchers WHERE enabled=1").Scan(&matcher.Priority); err != nil {
		return Matcher{}, fmt.Errorf("allocate matcher priority: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO node_matchers(id, pattern, match_type, enabled, priority, created_at, updated_at)
VALUES (?, ?, ?, 1, ?, ?, ?)`, matcher.ID, matcher.Pattern, matcher.Type, matcher.Priority, now, now); err != nil {
		return Matcher{}, fmt.Errorf("insert matcher: %w", err)
	}
	if err := reclassifyAllActiveNodesTx(ctx, transaction); err != nil {
		return Matcher{}, fmt.Errorf("reclassify active nodes after matcher create: %w", err)
	}
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return Matcher{}, fmt.Errorf("invalidate policy after matcher create: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Matcher{}, fmt.Errorf("commit matcher create: %w", err)
	}
	return matcher, nil
}

func (repository *MatcherRepository) List(ctx context.Context) ([]Matcher, error) {
	rows, err := repository.database.QueryContext(ctx, "SELECT id, pattern, match_type, priority, enabled FROM node_matchers ORDER BY enabled DESC, priority, id")
	if err != nil {
		return nil, fmt.Errorf("list node matchers: %w", err)
	}
	defer rows.Close()
	var result []Matcher
	for rows.Next() {
		var matcher Matcher
		var enabled int
		if err := rows.Scan(&matcher.ID, &matcher.Pattern, &matcher.Type, &matcher.Priority, &enabled); err != nil {
			return nil, fmt.Errorf("scan node matcher: %w", err)
		}
		matcher.Enabled = enabled != 0
		result = append(result, matcher)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node matchers: %w", err)
	}
	return result, nil
}

func (repository *MatcherRepository) Update(ctx context.Context, id string, input MatcherUpdateInput) error {
	matcher := Matcher{ID: id, Pattern: strings.TrimSpace(input.Pattern), Type: input.Type, Enabled: input.Enabled}
	if _, err := CompileMatchers([]Matcher{matcher}); err != nil {
		return err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin matcher update: %w", err)
	}
	defer transaction.Rollback()
	var wasEnabled int
	var priority int
	if err := transaction.QueryRowContext(ctx, "SELECT enabled, priority FROM node_matchers WHERE id=?", id).Scan(&wasEnabled, &priority); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("read matcher for update: %w", err)
	}
	if input.Enabled && wasEnabled == 0 {
		if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM node_matchers WHERE enabled=1").Scan(&priority); err != nil {
			return fmt.Errorf("allocate re-enabled matcher priority: %w", err)
		}
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, "UPDATE node_matchers SET pattern=?, match_type=?, enabled=?, priority=?, updated_at=? WHERE id=?", matcher.Pattern, matcher.Type, boolToInt(input.Enabled), priority, now, id); err != nil {
		return fmt.Errorf("update matcher: %w", err)
	}
	if err := reclassifyAllActiveNodesTx(ctx, transaction); err != nil {
		return fmt.Errorf("reclassify active nodes after matcher update: %w", err)
	}
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return fmt.Errorf("invalidate policy after matcher update: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit matcher update: %w", err)
	}
	return nil
}

func (repository *MatcherRepository) Delete(ctx context.Context, id string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin matcher delete: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, "DELETE FROM node_matchers WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("delete matcher: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read matcher delete count: %w", err)
	}
	if count != 1 {
		return store.ErrNotFound
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if err := reclassifyAllActiveNodesTx(ctx, transaction); err != nil {
		return fmt.Errorf("reclassify active nodes after matcher delete: %w", err)
	}
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return fmt.Errorf("invalidate policy after matcher delete: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit matcher delete: %w", err)
	}
	return nil
}

func (repository *MatcherRepository) ReorderEnabled(ctx context.Context, orderedIDs []string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin matcher reorder: %w", err)
	}
	defer transaction.Rollback()
	if err := validateMatcherEnabledSet(ctx, transaction, orderedIDs); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE node_matchers SET priority=-rowid WHERE enabled=1"); err != nil {
		return fmt.Errorf("temporarily clear matcher priorities: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	for index, id := range orderedIDs {
		if _, err := transaction.ExecContext(ctx, "UPDATE node_matchers SET priority=?, updated_at=? WHERE id=? AND enabled=1", (index+1)*10, now, id); err != nil {
			return fmt.Errorf("set matcher priority: %w", err)
		}
	}
	if err := reclassifyAllActiveNodesTx(ctx, transaction); err != nil {
		return fmt.Errorf("reclassify active nodes after matcher reorder: %w", err)
	}
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return fmt.Errorf("invalidate policy after matcher reorder: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit matcher reorder: %w", err)
	}
	return nil
}

func validateMatcherEnabledSet(ctx context.Context, transaction *sql.Tx, ids []string) error {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id == "" {
			return store.ErrPrioritySetMismatch
		}
		if _, exists := seen[id]; exists {
			return store.ErrPrioritySetMismatch
		}
		seen[id] = struct{}{}
	}
	rows, err := transaction.QueryContext(ctx, "SELECT id FROM node_matchers WHERE enabled=1")
	if err != nil {
		return fmt.Errorf("read enabled matcher ids: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if _, exists := seen[id]; !exists {
			return store.ErrPrioritySetMismatch
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != len(ids) {
		return store.ErrPrioritySetMismatch
	}
	return nil
}
