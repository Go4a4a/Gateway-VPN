package bypass

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"gateway-vpn/internal/store"
)

var ErrLastRequiredConfirmation = errors.New("removing the last enabled required target requires confirmation")

const (
	TargetClassGlobalRequired     = "GLOBAL_REQUIRED"
	TargetClassGlobalOptional     = "GLOBAL_OPTIONAL"
	TargetClassWhitelistIndicator = "WHITELIST_INDICATOR"
	TargetClassServiceEndpoint    = "SERVICE_ENDPOINT"
)

type Repository struct {
	database *sql.DB
	now      func() time.Time
}

type CreateInput struct {
	ID                    string
	Name                  string
	Kind                  string
	Value                 string
	Required              bool
	TargetClass           string
	Timeout               time.Duration
	SuccessMode           string
	ExpectedStatus        string
	ExpectedBodySubstring string
}

type UpdateInput struct {
	Name                  string
	Kind                  string
	Value                 string
	Enabled               bool
	Required              bool
	TargetClass           string
	Timeout               time.Duration
	SuccessMode           string
	ExpectedStatus        string
	ExpectedBodySubstring string
	AllowNoRequired       bool
}

type Target struct {
	ID                    string
	Name                  string
	Kind                  string
	Value                 string
	NormalizedURL         string
	Enabled               bool
	Required              bool
	TargetClass           string
	Priority              int64
	TimeoutSeconds        int64
	SuccessMode           string
	ExpectedStatus        string
	ExpectedBodySubstring string
	State                 string
	CreatedAt             string
	UpdatedAt             string
}

func NewRepository(database *sql.DB) *Repository {
	return &Repository{database: database, now: time.Now}
}

func (repository *Repository) Create(ctx context.Context, input CreateInput) (Target, error) {
	if strings.TrimSpace(input.ID) == "" {
		return Target{}, errors.New("probe target id is required")
	}
	name, err := validateTargetName(input.Name)
	if err != nil {
		return Target{}, err
	}
	normalized, successMode, expectedStatus, expectedBody, err := validateTargetPolicy(input.Kind, input.Value, input.Timeout, input.SuccessMode, input.ExpectedStatus, input.ExpectedBodySubstring)
	if err != nil {
		return Target{}, err
	}
	targetClass, err := normalizeTargetClass(input.TargetClass, input.Required)
	if err != nil {
		return Target{}, err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Target{}, fmt.Errorf("begin target create: %w", err)
	}
	defer transaction.Rollback()
	var priority int64
	if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM bypass_probe_targets WHERE enabled=1").Scan(&priority); err != nil {
		return Target{}, fmt.Errorf("allocate target priority: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
INSERT INTO bypass_probe_targets (
    id, name, target_kind, target_value, normalized_url, enabled, required,
    priority, timeout_seconds, success_mode, expected_status,
    expected_body_substring, state, created_at, updated_at, target_class
) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 'UNKNOWN', ?, ?, ?)`,
		input.ID,
		name,
		input.Kind,
		strings.TrimSpace(input.Value),
		normalized,
		boolInt(input.Required),
		priority,
		int64(input.Timeout/time.Second),
		successMode,
		nullIfEmpty(expectedStatus),
		nullIfEmpty(expectedBody),
		now,
		now,
		targetClass,
	)
	if err != nil {
		return Target{}, fmt.Errorf("insert probe target: %w", err)
	}
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return Target{}, fmt.Errorf("invalidate policy after target create: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Target{}, fmt.Errorf("commit target create: %w", err)
	}
	return repository.Get(ctx, input.ID)
}

func (repository *Repository) Update(ctx context.Context, id string, input UpdateInput) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("probe target id is required")
	}
	name, err := validateTargetName(input.Name)
	if err != nil {
		return err
	}
	normalized, successMode, expectedStatus, expectedBody, err := validateTargetPolicy(input.Kind, input.Value, input.Timeout, input.SuccessMode, input.ExpectedStatus, input.ExpectedBodySubstring)
	if err != nil {
		return err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin target update: %w", err)
	}
	defer transaction.Rollback()
	var wasEnabled, wasRequired int
	var currentClass string
	var priority int64
	if err := transaction.QueryRowContext(ctx, "SELECT enabled, required, priority, target_class FROM bypass_probe_targets WHERE id=?", id).Scan(&wasEnabled, &wasRequired, &priority, &currentClass); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("read target for update: %w", err)
	}
	if input.Enabled && wasEnabled == 0 {
		if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(priority), 0) + 10 FROM bypass_probe_targets WHERE enabled=1").Scan(&priority); err != nil {
			return fmt.Errorf("allocate re-enabled target priority: %w", err)
		}
	}
	targetClass := input.TargetClass
	if strings.TrimSpace(targetClass) == "" {
		targetClass = currentClass
	}
	targetClass, err = normalizeTargetClass(targetClass, input.Required)
	if err != nil {
		return err
	}
	if wasEnabled != 0 && wasRequired != 0 && (!input.Enabled || !input.Required) && !input.AllowNoRequired {
		var remaining int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM bypass_probe_targets WHERE enabled=1 AND required=1 AND id<>?", id).Scan(&remaining); err != nil {
			return fmt.Errorf("count remaining required targets: %w", err)
		}
		if remaining == 0 {
			return ErrLastRequiredConfirmation
		}
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
UPDATE bypass_probe_targets
SET name=?, target_kind=?, target_value=?, normalized_url=?, enabled=?, required=?,
    priority=?, timeout_seconds=?, success_mode=?, expected_status=?,
    expected_body_substring=?, target_class=?, state='UNKNOWN', updated_at=?
WHERE id=?`, name, input.Kind, strings.TrimSpace(input.Value), normalized, boolInt(input.Enabled), boolInt(input.Required), priority, int64(input.Timeout/time.Second), successMode, nullIfEmpty(expectedStatus), nullIfEmpty(expectedBody), targetClass, now, id)
	if err != nil {
		return fmt.Errorf("update probe target: %w", err)
	}
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return fmt.Errorf("invalidate policy after target update: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit target update: %w", err)
	}
	return nil
}

func (repository *Repository) Delete(ctx context.Context, id string, allowNoRequired bool) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin target delete: %w", err)
	}
	defer transaction.Rollback()
	var enabled, required int
	if err := transaction.QueryRowContext(ctx, "SELECT enabled, required FROM bypass_probe_targets WHERE id=?", id).Scan(&enabled, &required); errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("read target for delete: %w", err)
	}
	if enabled != 0 && required != 0 && !allowNoRequired {
		var remaining int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM bypass_probe_targets WHERE enabled=1 AND required=1 AND id<>?", id).Scan(&remaining); err != nil {
			return fmt.Errorf("count remaining required targets: %w", err)
		}
		if remaining == 0 {
			return ErrLastRequiredConfirmation
		}
	}
	result, err := transaction.ExecContext(ctx, "DELETE FROM bypass_probe_targets WHERE id=?", id)
	if err != nil {
		return fmt.Errorf("delete probe target: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read target delete count: %w", err)
	}
	if count != 1 {
		return store.ErrNotFound
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return fmt.Errorf("invalidate policy after target delete: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit target delete: %w", err)
	}
	return nil
}

func (repository *Repository) Get(ctx context.Context, id string) (Target, error) {
	item, err := scanTarget(repository.database.QueryRowContext(ctx, targetSelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, store.ErrNotFound
	}
	if err != nil {
		return Target{}, fmt.Errorf("get probe target: %w", err)
	}
	return item, nil
}

func (repository *Repository) List(ctx context.Context) ([]Target, error) {
	rows, err := repository.database.QueryContext(ctx, targetSelect+" ORDER BY enabled DESC, priority, name")
	if err != nil {
		return nil, fmt.Errorf("list probe targets: %w", err)
	}
	defer rows.Close()
	result := make([]Target, 0)
	for rows.Next() {
		item, err := scanTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("scan probe target: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate probe targets: %w", err)
	}
	return result, nil
}

func (repository *Repository) ReorderEnabled(ctx context.Context, orderedIDs []string) error {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin target reorder: %w", err)
	}
	defer transaction.Rollback()
	if err := validateEnabledSet(ctx, transaction, orderedIDs); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE bypass_probe_targets SET priority=-rowid WHERE enabled=1"); err != nil {
		return fmt.Errorf("temporarily clear target priorities: %w", err)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	for index, id := range orderedIDs {
		result, err := transaction.ExecContext(ctx, "UPDATE bypass_probe_targets SET priority=?, updated_at=? WHERE id=? AND enabled=1", (index+1)*10, now, id)
		if err != nil {
			return fmt.Errorf("set target priority: %w", err)
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return store.ErrPrioritySetMismatch
		}
	}
	if _, err := store.InvalidatePathPolicy(ctx, transaction, now); err != nil {
		return fmt.Errorf("invalidate policy after target reorder: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit target reorder: %w", err)
	}
	return nil
}

func validateTargetPolicy(kind, value string, timeout time.Duration, successMode, expectedStatus, expectedBody string) (string, string, string, string, error) {
	normalized, err := NormalizeTarget(kind, value)
	if err != nil {
		return "", "", "", "", err
	}
	if timeout < time.Second || timeout > 60*time.Second {
		return "", "", "", "", errors.New("probe target timeout must be between 1 and 60 seconds")
	}
	if successMode == "" {
		successMode = SuccessAnyHTTPResponse
	}
	if successMode != SuccessAnyHTTPResponse && successMode != SuccessExpectedStatus && successMode != SuccessExpectedBody {
		return "", "", "", "", errors.New("unsupported probe target success mode")
	}
	if !utf8.ValidString(expectedBody) || len(expectedBody) > MaxExpectedBodyBytes || strings.ContainsRune(expectedBody, '\x00') {
		return "", "", "", "", fmt.Errorf("expected body substring must be valid UTF-8 without NUL and at most %d bytes", MaxExpectedBodyBytes)
	}
	canonicalStatus := ""
	if strings.TrimSpace(expectedStatus) != "" {
		canonicalStatus, err = NormalizeStatusExpression(expectedStatus)
		if err != nil {
			return "", "", "", "", err
		}
	}
	switch successMode {
	case SuccessAnyHTTPResponse:
		if canonicalStatus != "" || expectedBody != "" {
			return "", "", "", "", errors.New("any_http_response mode cannot contain status or body expectations")
		}
	case SuccessExpectedStatus:
		if canonicalStatus == "" {
			return "", "", "", "", errors.New("expected_status mode requires a status expression")
		}
		if expectedBody != "" {
			return "", "", "", "", errors.New("expected_status mode cannot contain a body expectation")
		}
	case SuccessExpectedBody:
		if strings.TrimSpace(expectedBody) == "" {
			return "", "", "", "", errors.New("expected_body mode requires a non-blank body substring")
		}
	}
	return normalized, successMode, canonicalStatus, expectedBody, nil
}

func validateTargetName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return "", errors.New("probe target name is empty, invalid, or exceeds 128 bytes")
	}
	return value, nil
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
	rows, err := transaction.QueryContext(ctx, "SELECT id FROM bypass_probe_targets WHERE enabled=1")
	if err != nil {
		return fmt.Errorf("read enabled targets: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan enabled target: %w", err)
		}
		if _, exists := seen[id]; !exists {
			return store.ErrPrioritySetMismatch
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate enabled targets: %w", err)
	}
	if count != len(orderedIDs) {
		return store.ErrPrioritySetMismatch
	}
	return nil
}

const targetSelect = `
SELECT id, name, target_kind, target_value, normalized_url, enabled, required,
       priority, timeout_seconds, success_mode, expected_status,
       expected_body_substring, state, created_at, updated_at, target_class
FROM bypass_probe_targets`

type scanner interface {
	Scan(...any) error
}

func scanTarget(row scanner) (Target, error) {
	var item Target
	var enabled, required int64
	var expectedStatus, expectedBody sql.NullString
	err := row.Scan(
		&item.ID,
		&item.Name,
		&item.Kind,
		&item.Value,
		&item.NormalizedURL,
		&enabled,
		&required,
		&item.Priority,
		&item.TimeoutSeconds,
		&item.SuccessMode,
		&expectedStatus,
		&expectedBody,
		&item.State,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.TargetClass,
	)
	item.Enabled = enabled != 0
	item.Required = required != 0
	item.ExpectedStatus = expectedStatus.String
	item.ExpectedBodySubstring = expectedBody.String
	return item, err
}

func normalizeTargetClass(value string, required bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return TargetClassGlobalRequired, nil
		}
		return TargetClassGlobalOptional, nil
	}
	switch value {
	case TargetClassGlobalRequired:
		if !required {
			return "", errors.New("GLOBAL_REQUIRED target must be required")
		}
	case TargetClassGlobalOptional, TargetClassWhitelistIndicator, TargetClassServiceEndpoint:
		if required {
			return "", errors.New("only GLOBAL_REQUIRED target can be required")
		}
	default:
		return "", errors.New("probe target class is invalid")
	}
	return value, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}
