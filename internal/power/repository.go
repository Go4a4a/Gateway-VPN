package power

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

const OperationKind = "SYSTEM_POWER"

type Repository struct {
	Database *sql.DB
	Now      func() time.Time
}

func (repository Repository) Start(ctx context.Context, actorUserID string, command Command) (operations.Operation, error) {
	if repository.Database == nil || strings.TrimSpace(actorUserID) == "" {
		return operations.Operation{}, errors.New("power operation database and actor are required")
	}
	if err := command.Validate(); err != nil {
		return operations.Operation{}, err
	}
	id, err := newOperationID()
	if err != nil {
		return operations.Operation{}, err
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return operations.Operation{}, fmt.Errorf("begin power operation: %w", err)
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(ctx, `
INSERT INTO operations(
    id, kind, scope_type, scope_id, status, requested_by,
    created_at, started_at, updated_at
) VALUES (?, 'SYSTEM_POWER', 'HOST', ?, 'RUNNING', ?, ?, ?, ?)`,
		id, string(command.Action), "USER:"+actorUserID, now, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return operations.Operation{}, ErrOperationInProgress
		}
		return operations.Operation{}, fmt.Errorf("insert power operation: %w", err)
	}
	details, _ := json.Marshal(map[string]any{"action": command.Action, "delay_seconds": command.DelaySeconds, "actor_user_id": actorUserID})
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO operation_steps(operation_id, sequence, occurred_at, severity, stage, code, message, details_json)
VALUES (?, 1, ?, 'INFO', 'AUTHORIZE', 'POWER_ACTION_AUTHORIZED', 'Пароль и точное подтверждение приняты', ?)`, id, now, string(details)); err != nil {
		return operations.Operation{}, fmt.Errorf("record power operation authorization: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, 'WARNING', 'SYSTEM_POWER_REQUESTED', ?)`, now, string(details)); err != nil {
		return operations.Operation{}, fmt.Errorf("record power request audit: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return operations.Operation{}, fmt.Errorf("commit power operation: %w", err)
	}
	return operations.NewRepository(repository.Database).Get(ctx, id, true)
}

func (repository Repository) Finish(ctx context.Context, id string, dispatched bool, reasonCode string) (operations.Operation, error) {
	if repository.Database == nil || strings.TrimSpace(id) == "" {
		return operations.Operation{}, errors.New("power operation database and id are required")
	}
	status, summary, severity, eventType, message := operations.StatusFailed, reasonCode, "ERROR", "SYSTEM_POWER_FAILED", "Команда питания не отправлена"
	if dispatched {
		status, summary, severity, eventType, message = operations.StatusSucceeded, "POWER_ACTION_DISPATCHED", "WARNING", "SYSTEM_POWER_DISPATCHED", "Команда питания отправлена systemd"
	}
	if summary == "" {
		summary = "POWER_ACTION_FAILED"
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return operations.Operation{}, fmt.Errorf("begin power operation finish: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `
UPDATE operations SET status=?, summary_code=?, finished_at=?, updated_at=?
WHERE id=? AND kind='SYSTEM_POWER' AND status='RUNNING'`, status, summary, now, now, id)
	if err != nil {
		return operations.Operation{}, fmt.Errorf("finish power operation: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return operations.Operation{}, store.ErrNotFound
	}
	var action string
	if err := transaction.QueryRowContext(ctx, "SELECT scope_id FROM operations WHERE id=?", id).Scan(&action); err != nil {
		return operations.Operation{}, fmt.Errorf("read finished power action: %w", err)
	}
	details, _ := json.Marshal(map[string]any{"action": action, "reason_code": summary})
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO operation_steps(operation_id, sequence, occurred_at, severity, stage, code, message, details_json)
VALUES (?, 2, ?, ?, 'DISPATCH', ?, ?, ?)`, id, now, severity, summary, message, string(details)); err != nil {
		return operations.Operation{}, fmt.Errorf("record power dispatch step: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, ?, ?, ?)`, now, severity, eventType, string(details)); err != nil {
		return operations.Operation{}, fmt.Errorf("record power dispatch audit: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return operations.Operation{}, fmt.Errorf("commit power operation finish: %w", err)
	}
	return operations.NewRepository(repository.Database).Get(ctx, id, true)
}

func (repository Repository) RecoverInterrupted(ctx context.Context) (int64, error) {
	if repository.Database == nil {
		return 0, errors.New("power operation database is required")
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin interrupted power recovery: %w", err)
	}
	defer transaction.Rollback()
	var id, action string
	err = transaction.QueryRowContext(ctx, `
SELECT id, scope_id FROM operations
WHERE kind='SYSTEM_POWER' AND status IN ('QUEUED','RUNNING')
ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&id, &action)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read interrupted power operation: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE operations
SET status='FAILED', summary_code='POWER_OUTCOME_UNKNOWN_AFTER_PROCESS_RESTART', finished_at=?, updated_at=?
WHERE id=? AND kind='SYSTEM_POWER' AND status IN ('QUEUED','RUNNING')`, now, now, id)
	if err != nil {
		return 0, fmt.Errorf("recover interrupted power operation: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read interrupted power recovery count: %w", err)
	}
	if count != 1 {
		return 0, errors.New("interrupted power recovery state changed")
	}
	details, _ := json.Marshal(map[string]any{"action": action, "reason_code": "POWER_OUTCOME_UNKNOWN_AFTER_PROCESS_RESTART"})
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO operation_steps(operation_id, sequence, occurred_at, severity, stage, code, message, details_json)
SELECT ?, COALESCE(MAX(sequence),0)+1, ?, 'WARNING', 'RECOVERY',
       'POWER_OUTCOME_UNKNOWN_AFTER_PROCESS_RESTART',
       'Процесс перезапустился до подтверждения результата команды питания', ?
FROM operation_steps WHERE operation_id=?`, id, now, string(details), id); err != nil {
		return 0, fmt.Errorf("record interrupted power step: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, 'WARNING', 'SYSTEM_POWER_OUTCOME_UNKNOWN', ?)`, now, string(details)); err != nil {
		return 0, fmt.Errorf("record interrupted power audit: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit interrupted power recovery: %w", err)
	}
	return 1, nil
}

func (repository Repository) Latest(ctx context.Context) (operations.Operation, bool, error) {
	if repository.Database == nil {
		return operations.Operation{}, false, errors.New("power operation database is required")
	}
	var id string
	err := repository.Database.QueryRowContext(ctx, `
SELECT id FROM operations WHERE kind='SYSTEM_POWER' ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return operations.Operation{}, false, nil
	}
	if err != nil {
		return operations.Operation{}, false, fmt.Errorf("read latest power operation: %w", err)
	}
	item, err := operations.NewRepository(repository.Database).Get(ctx, id, true)
	return item, err == nil, err
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
		return "", errors.New("generate power operation id failed")
	}
	return "power-" + hex.EncodeToString(value), nil
}
