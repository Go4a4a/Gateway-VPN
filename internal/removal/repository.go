package removal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/operations"
	"gateway-vpn/internal/store"
)

const OperationKind = "SYSTEM_UNINSTALL"

type Repository struct {
	Database *sql.DB
	Now      func() time.Time
}

func (repository Repository) Start(ctx context.Context, actorUserID string, mode Mode) (operations.Operation, error) {
	if repository.Database == nil || strings.TrimSpace(actorUserID) == "" {
		return operations.Operation{}, errors.New("uninstall operation database and actor are required")
	}
	request := Request{OperationID: "uninstall-" + strings.Repeat("0", 32), Mode: mode}
	if err := request.Validate(); err != nil {
		return operations.Operation{}, err
	}
	id, err := newOperationID()
	if err != nil {
		return operations.Operation{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return operations.Operation{}, fmt.Errorf("begin uninstall operation: %w", err)
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(ctx, `
INSERT INTO operations(
    id, kind, scope_type, scope_id, status, requested_by,
    created_at, started_at, updated_at
) VALUES (?, 'SYSTEM_UNINSTALL', 'HOST', ?, 'RUNNING', ?, ?, ?, ?)`,
		id, string(mode), "USER:"+actorUserID, now, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return operations.Operation{}, ErrOperationInProgress
		}
		return operations.Operation{}, fmt.Errorf("insert uninstall operation: %w", err)
	}
	details, _ := json.Marshal(map[string]any{"mode": mode, "actor_user_id": actorUserID})
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO operation_steps(operation_id, sequence, occurred_at, severity, stage, code, message, details_json)
VALUES (?, 1, ?, 'WARNING', 'AUTHORIZE', 'UNINSTALL_AUTHORIZED', 'Пароль, предупреждения и точная фраза подтверждены', ?)`, id, now, string(details)); err != nil {
		return operations.Operation{}, fmt.Errorf("record uninstall authorization: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, 'WARNING', 'SYSTEM_UNINSTALL_REQUESTED', ?)`, now, string(details)); err != nil {
		return operations.Operation{}, fmt.Errorf("record uninstall audit: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return operations.Operation{}, fmt.Errorf("commit uninstall operation: %w", err)
	}
	return operations.NewRepository(repository.Database).Get(ctx, id, true)
}

func (repository Repository) Finish(ctx context.Context, id string, dispatched bool, reasonCode string) (operations.Operation, error) {
	if repository.Database == nil || strings.TrimSpace(id) == "" {
		return operations.Operation{}, errors.New("uninstall operation database and id are required")
	}
	status, summary, severity, eventType, message := operations.StatusFailed, reasonCode, "ERROR", "SYSTEM_UNINSTALL_FAILED", "Удаление не было передано root guardian"
	if dispatched {
		status, summary, severity, eventType, message = operations.StatusSucceeded, "UNINSTALL_DISPATCHED", "WARNING", "SYSTEM_UNINSTALL_DISPATCHED", "Удаление передано root guardian; итог подтверждает внешний receipt"
	}
	if summary == "" {
		summary = "UNINSTALL_DISPATCH_FAILED"
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return operations.Operation{}, fmt.Errorf("begin uninstall finish: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `
UPDATE operations SET status=?, summary_code=?, finished_at=?, updated_at=?
WHERE id=? AND kind='SYSTEM_UNINSTALL' AND status='RUNNING'`, status, summary, now, now, id)
	if err != nil {
		return operations.Operation{}, fmt.Errorf("finish uninstall operation: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return operations.Operation{}, store.ErrNotFound
	}
	var mode string
	if err := transaction.QueryRowContext(ctx, "SELECT scope_id FROM operations WHERE id=?", id).Scan(&mode); err != nil {
		return operations.Operation{}, fmt.Errorf("read finished uninstall mode: %w", err)
	}
	details, _ := json.Marshal(map[string]any{"mode": mode, "reason_code": summary})
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO operation_steps(operation_id, sequence, occurred_at, severity, stage, code, message, details_json)
VALUES (?, 2, ?, ?, 'DISPATCH', ?, ?, ?)`, id, now, severity, summary, message, string(details)); err != nil {
		return operations.Operation{}, fmt.Errorf("record uninstall dispatch: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, ?, ?, ?)`, now, severity, eventType, string(details)); err != nil {
		return operations.Operation{}, fmt.Errorf("record uninstall dispatch audit: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return operations.Operation{}, fmt.Errorf("commit uninstall finish: %w", err)
	}
	return operations.NewRepository(repository.Database).Get(ctx, id, true)
}

func (repository Repository) Latest(ctx context.Context) (operations.Operation, bool, error) {
	if repository.Database == nil {
		return operations.Operation{}, false, errors.New("uninstall operation database is required")
	}
	var id string
	err := repository.Database.QueryRowContext(ctx, `
SELECT id FROM operations WHERE kind='SYSTEM_UNINSTALL' ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return operations.Operation{}, false, nil
	}
	if err != nil {
		return operations.Operation{}, false, fmt.Errorf("read latest uninstall operation: %w", err)
	}
	item, err := operations.NewRepository(repository.Database).Get(ctx, id, true)
	return item, err == nil, err
}

// RecoverInterrupted is called only after the privileged impact endpoint has
// confirmed that no root uninstall marker exists. A RUNNING row can otherwise
// survive the expected WebUI disconnect between durable dispatch and SQLite
// acknowledgement, especially when PRESERVE_DATA is reinstalled later.
func (repository Repository) RecoverInterrupted(ctx context.Context) (int64, error) {
	if repository.Database == nil {
		return 0, errors.New("uninstall operation database is required")
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin interrupted uninstall recovery: %w", err)
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, `SELECT id, scope_id FROM operations WHERE kind='SYSTEM_UNINSTALL' AND status IN ('QUEUED','RUNNING') ORDER BY created_at, id`)
	if err != nil {
		return 0, fmt.Errorf("read interrupted uninstall operations: %w", err)
	}
	type interrupted struct{ id, mode string }
	var items []interrupted
	for rows.Next() {
		var item interrupted
		if err := rows.Scan(&item.id, &item.mode); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan interrupted uninstall operation: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close interrupted uninstall operations: %w", err)
	}
	for _, item := range items {
		if _, err := transaction.ExecContext(ctx, `UPDATE operations SET status='FAILED', summary_code='UNINSTALL_OUTCOME_UNKNOWN_NO_ROOT_MARKER', finished_at=?, updated_at=? WHERE id=? AND status IN ('QUEUED','RUNNING')`, now, now, item.id); err != nil {
			return 0, fmt.Errorf("recover interrupted uninstall operation: %w", err)
		}
		details, _ := json.Marshal(map[string]any{"mode": item.mode, "reason_code": "UNINSTALL_OUTCOME_UNKNOWN_NO_ROOT_MARKER"})
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO operation_steps(operation_id, sequence, occurred_at, severity, stage, code, message, details_json)
SELECT ?, COALESCE(MAX(sequence),0)+1, ?, 'WARNING', 'RECOVERY', 'UNINSTALL_OUTCOME_UNKNOWN_NO_ROOT_MARKER', 'Root marker отсутствует; итог нужно сверить с внешним receipt и состоянием хоста', ? FROM operation_steps WHERE operation_id=?`, item.id, now, string(details), item.id); err != nil {
			return 0, fmt.Errorf("record interrupted uninstall recovery: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit interrupted uninstall recovery: %w", err)
	}
	return int64(len(items)), nil
}

func (repository Repository) now() time.Time {
	if repository.Now != nil {
		return repository.Now().UTC()
	}
	return time.Now().UTC()
}

func newOperationID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate uninstall operation id failed")
	}
	return "uninstall-" + hex.EncodeToString(value), nil
}
