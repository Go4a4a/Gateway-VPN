package networkapply

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

const (
	StatePreparing  = "PREPARING"
	StateArmed      = "ARMED"
	StateApplied    = "APPLIED"
	StateConfirming = "CONFIRMING"
	StateConfirmed  = "CONFIRMED"
	StateRolledBack = "ROLLED_BACK"
	StateFailed     = "FAILED"
)

var (
	ErrApplyInProgress = errors.New("another network apply is in progress")
	ErrApplyState      = errors.New("network apply state changed")
	ErrApplyExpired    = errors.New("network apply confirmation deadline expired")
	ErrConfirmToken    = errors.New("network apply confirmation token is invalid")
	ErrConfirmSource   = errors.New("network apply must be confirmed through the new address or WireGuard")
)

type Transaction struct {
	ID                 string
	State              string
	ConfirmTokenSHA256 string
	InterfaceName      string
	OldLANCIDR         string
	NewLANCIDR         string
	OldURL             string
	NewURL             string
	NewDestinationIP   string
	RollbackDeadline   string
	TransactionDir     string
	ErrorCode          string
	CreatedAt          string
	UpdatedAt          string
	ConfirmedAt        string
	RolledBackAt       string
}

type Repository struct {
	database *sql.DB
	now      func() time.Time
}

func NewRepository(database *sql.DB) *Repository {
	return &Repository{database: database, now: time.Now}
}

func (repository *Repository) Create(ctx context.Context, transaction Transaction) error {
	if repository == nil || repository.database == nil || !safeID(transaction.ID) || transaction.State != StatePreparing || transaction.ConfirmTokenSHA256 == "" || transaction.TransactionDir == "" {
		return errors.New("complete preparing network transaction is required")
	}
	databaseTransaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin network apply create: %w", err)
	}
	defer databaseTransaction.Rollback()
	var unfinished int
	if err := databaseTransaction.QueryRowContext(ctx, `
SELECT COUNT(*) FROM network_apply_transactions
WHERE state IN (?, ?, ?, ?)`, StatePreparing, StateArmed, StateApplied, StateConfirming).Scan(&unfinished); err != nil {
		return fmt.Errorf("count unfinished network apply: %w", err)
	}
	if unfinished != 0 {
		return ErrApplyInProgress
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	_, err = databaseTransaction.ExecContext(ctx, `
INSERT INTO network_apply_transactions(
    id, state, confirm_token_sha256, interface_name, old_lan_cidr,
    new_lan_cidr, old_url, new_url, new_destination_ip,
    rollback_deadline, transaction_dir, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transaction.ID, transaction.State, transaction.ConfirmTokenSHA256,
		transaction.InterfaceName, transaction.OldLANCIDR, transaction.NewLANCIDR,
		transaction.OldURL, transaction.NewURL, transaction.NewDestinationIP,
		transaction.RollbackDeadline, transaction.TransactionDir, now, now)
	if err != nil {
		return fmt.Errorf("insert network apply: %w", err)
	}
	if err := databaseTransaction.Commit(); err != nil {
		return fmt.Errorf("commit network apply create: %w", err)
	}
	return nil
}

func (repository *Repository) Get(ctx context.Context, id string) (Transaction, error) {
	item, err := scanTransaction(repository.database.QueryRowContext(ctx, transactionSelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Transaction{}, store.ErrNotFound
	}
	if err != nil {
		return Transaction{}, fmt.Errorf("get network apply transaction: %w", err)
	}
	return item, nil
}

func (repository *Repository) UpdateDeadline(ctx context.Context, id string, deadline time.Time) error {
	if !safeID(id) || deadline.IsZero() {
		return errors.New("safe network apply id and deadline are required")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := repository.database.ExecContext(ctx, `
UPDATE network_apply_transactions
SET rollback_deadline=?, updated_at=?
WHERE id=? AND state=?`, deadline.UTC().Format(time.RFC3339Nano), now, id, StatePreparing)
	if err != nil {
		return fmt.Errorf("update network apply deadline: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrApplyState
	}
	return nil
}

func (repository *Repository) Transition(ctx context.Context, id string, expected []string, next, errorCode string) error {
	if !safeID(id) || len(expected) == 0 || !validState(next) || (errorCode != "" && !safeErrorCode(errorCode)) {
		return errors.New("valid network apply transition is required")
	}
	for _, state := range expected {
		if !validState(state) {
			return errors.New("network apply expected state is invalid")
		}
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(expected)), ",")
	now := repository.now().UTC().Format(time.RFC3339Nano)
	query := "UPDATE network_apply_transactions SET state=?, error_code=?, updated_at=?"
	args := []any{next, nullable(errorCode), now}
	if next == StateConfirmed {
		query += ", confirmed_at=?"
		args = append(args, now)
	}
	if next == StateRolledBack {
		query += ", rolled_back_at=?"
		args = append(args, now)
	}
	query += " WHERE id=? AND state IN (" + placeholders + ")"
	args = append(args, id)
	for _, state := range expected {
		args = append(args, state)
	}
	result, err := repository.database.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("transition network apply: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read network apply transition count: %w", err)
	}
	if count != 1 {
		return ErrApplyState
	}
	return nil
}

func (repository *Repository) ListUnfinished(ctx context.Context) ([]Transaction, error) {
	rows, err := repository.database.QueryContext(ctx, transactionSelect+" WHERE state IN (?, ?, ?, ?) ORDER BY created_at", StatePreparing, StateArmed, StateApplied, StateConfirming)
	if err != nil {
		return nil, fmt.Errorf("list unfinished network applies: %w", err)
	}
	defer rows.Close()
	var result []Transaction
	for rows.Next() {
		item, err := scanTransaction(rows)
		if err != nil {
			return nil, fmt.Errorf("scan unfinished network apply: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unfinished network applies: %w", err)
	}
	return result, nil
}

const transactionSelect = `
SELECT id, state, confirm_token_sha256, interface_name, old_lan_cidr,
       new_lan_cidr, old_url, new_url, new_destination_ip,
       rollback_deadline, transaction_dir, error_code, created_at, updated_at,
       confirmed_at, rolled_back_at
FROM network_apply_transactions`

type rowScanner interface {
	Scan(...any) error
}

func scanTransaction(row rowScanner) (Transaction, error) {
	var item Transaction
	var errorCode, confirmed, rolledBack sql.NullString
	err := row.Scan(
		&item.ID, &item.State, &item.ConfirmTokenSHA256, &item.InterfaceName,
		&item.OldLANCIDR, &item.NewLANCIDR, &item.OldURL, &item.NewURL,
		&item.NewDestinationIP, &item.RollbackDeadline, &item.TransactionDir,
		&errorCode, &item.CreatedAt, &item.UpdatedAt, &confirmed, &rolledBack,
	)
	item.ErrorCode = errorCode.String
	item.ConfirmedAt = confirmed.String
	item.RolledBackAt = rolledBack.String
	return item, err
}

func validState(value string) bool {
	switch value {
	case StatePreparing, StateArmed, StateApplied, StateConfirming, StateConfirmed, StateRolledBack, StateFailed:
		return true
	default:
		return false
	}
}

func safeID(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
			continue
		}
		return false
	}
	return true
}

func safeErrorCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' {
			continue
		}
		return false
	}
	return true
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
