// Package operations persists bounded, redacted progress for asynchronous UI
// actions such as subscription refresh, probes, qualification and switching.
package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	loggingpkg "gateway-vpn/internal/logging"
	"gateway-vpn/internal/store"
)

const (
	StatusQueued    = "QUEUED"
	StatusRunning   = "RUNNING"
	StatusSucceeded = "SUCCEEDED"
	StatusFailed    = "FAILED"
	StatusCancelled = "CANCELLED"
)

type Repository struct {
	database *sql.DB
	now      func() time.Time
}

type CreateInput struct {
	ID          string
	Kind        string
	ScopeType   string
	ScopeID     string
	RequestedBy string
}

type Operation struct {
	ID          string
	Kind        string
	ScopeType   string
	ScopeID     string
	Status      string
	RequestedBy string
	SummaryCode string
	CreatedAt   string
	StartedAt   string
	FinishedAt  string
	UpdatedAt   string
	Steps       []Step
}

type Step struct {
	ID          int64
	OperationID string
	Sequence    int64
	OccurredAt  string
	Severity    string
	Stage       string
	Code        string
	Message     string
	DetailsJSON string
}

type StepInput struct {
	Severity string
	Stage    string
	Code     string
	Message  string
	Details  map[string]any
}

func NewRepository(database *sql.DB) *Repository {
	return &Repository{database: database, now: time.Now}
}

func (repository *Repository) Create(ctx context.Context, input CreateInput) (Operation, error) {
	if repository == nil || repository.database == nil {
		return Operation{}, errors.New("operation database is required")
	}
	input.ID = strings.TrimSpace(input.ID)
	input.Kind = strings.TrimSpace(input.Kind)
	input.ScopeType = strings.TrimSpace(input.ScopeType)
	input.ScopeID = strings.TrimSpace(input.ScopeID)
	input.RequestedBy = strings.TrimSpace(input.RequestedBy)
	if input.RequestedBy == "" {
		input.RequestedBy = "SYSTEM"
	}
	if input.ID == "" || !boundedToken(input.Kind, 64) || !boundedToken(input.ScopeType, 64) ||
		len(input.ID) > 128 || len(input.ScopeID) > 256 || len(input.RequestedBy) > 128 {
		return Operation{}, errors.New("operation identity or scope is invalid")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	_, err := repository.database.ExecContext(ctx, `
INSERT INTO operations (
    id, kind, scope_type, scope_id, status, requested_by,
    created_at, updated_at
) VALUES (?, ?, ?, ?, 'QUEUED', ?, ?, ?)`,
		input.ID, input.Kind, input.ScopeType, input.ScopeID, input.RequestedBy, now, now)
	if err != nil {
		return Operation{}, fmt.Errorf("create operation: %w", err)
	}
	return repository.Get(ctx, input.ID, false)
}

func (repository *Repository) Start(ctx context.Context, id string, step StepInput) (Operation, error) {
	transaction, err := repository.begin(ctx)
	if err != nil {
		return Operation{}, err
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE operations
SET status='RUNNING', started_at=COALESCE(started_at, ?), updated_at=?
WHERE id=? AND status='QUEUED'`, now, now, id)
	if err != nil {
		return Operation{}, fmt.Errorf("start operation: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Operation{}, err
	}
	if count == 0 {
		var status string
		if err := transaction.QueryRowContext(ctx, "SELECT status FROM operations WHERE id=?", id).Scan(&status); errors.Is(err, sql.ErrNoRows) {
			return Operation{}, store.ErrNotFound
		} else if err != nil {
			return Operation{}, err
		}
		if status != StatusRunning {
			return Operation{}, fmt.Errorf("operation cannot start from status %s", status)
		}
	}
	if err := appendStepTx(ctx, transaction, id, now, step); err != nil {
		return Operation{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Operation{}, fmt.Errorf("commit operation start: %w", err)
	}
	return repository.Get(ctx, id, true)
}

func (repository *Repository) AppendStep(ctx context.Context, id string, input StepInput) (Step, error) {
	transaction, err := repository.begin(ctx)
	if err != nil {
		return Step{}, err
	}
	defer transaction.Rollback()
	var status string
	if err := transaction.QueryRowContext(ctx, "SELECT status FROM operations WHERE id=?", id).Scan(&status); errors.Is(err, sql.ErrNoRows) {
		return Step{}, store.ErrNotFound
	} else if err != nil {
		return Step{}, err
	}
	if status != StatusRunning {
		return Step{}, fmt.Errorf("operation step cannot be added in status %s", status)
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	step, err := appendStepTxResult(ctx, transaction, id, now, input)
	if err != nil {
		return Step{}, err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE operations SET updated_at=? WHERE id=?", now, id); err != nil {
		return Step{}, fmt.Errorf("touch operation after step: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Step{}, fmt.Errorf("commit operation step: %w", err)
	}
	return step, nil
}

func (repository *Repository) Finish(ctx context.Context, id, status, summaryCode string, step StepInput) (Operation, error) {
	if status != StatusSucceeded && status != StatusFailed && status != StatusCancelled {
		return Operation{}, errors.New("operation terminal status is invalid")
	}
	if summaryCode != "" && !boundedToken(summaryCode, 128) {
		return Operation{}, errors.New("operation summary code is invalid")
	}
	transaction, err := repository.begin(ctx)
	if err != nil {
		return Operation{}, err
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE operations
SET status=?, summary_code=?, finished_at=?, updated_at=?
WHERE id=? AND status IN ('QUEUED', 'RUNNING')`, status, summaryCode, now, now, id)
	if err != nil {
		return Operation{}, fmt.Errorf("finish operation: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil {
		return Operation{}, countErr
	} else if count != 1 {
		return Operation{}, store.ErrNotFound
	}
	if err := appendStepTx(ctx, transaction, id, now, step); err != nil {
		return Operation{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Operation{}, fmt.Errorf("commit operation finish: %w", err)
	}
	return repository.Get(ctx, id, true)
}

func (repository *Repository) Get(ctx context.Context, id string, includeSteps bool) (Operation, error) {
	if repository == nil || repository.database == nil || strings.TrimSpace(id) == "" {
		return Operation{}, errors.New("operation database and id are required")
	}
	item, err := scanOperation(repository.database.QueryRowContext(ctx, operationSelect+" WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, store.ErrNotFound
	}
	if err != nil {
		return Operation{}, fmt.Errorf("get operation: %w", err)
	}
	if includeSteps {
		item.Steps, err = repository.listSteps(ctx, id)
	}
	return item, err
}

func (repository *Repository) List(ctx context.Context, limit int) ([]Operation, error) {
	if repository == nil || repository.database == nil || limit <= 0 || limit > 200 {
		return nil, errors.New("operation database and list limit 1..200 are required")
	}
	rows, err := repository.database.QueryContext(ctx, operationSelect+" ORDER BY created_at DESC, id DESC LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("list operations: %w", err)
	}
	defer rows.Close()
	result := []Operation{}
	for rows.Next() {
		item, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (repository *Repository) ClearCompleted(ctx context.Context, limit int) (int64, error) {
	if repository == nil || repository.database == nil || limit <= 0 || limit > 200 {
		return 0, errors.New("operation database and clear limit 1..200 are required")
	}
	result, err := repository.database.ExecContext(ctx, `
DELETE FROM operations
WHERE id IN (
    SELECT id FROM operations
    WHERE status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
    ORDER BY finished_at, id
    LIMIT ?
)`, limit)
	if err != nil {
		return 0, fmt.Errorf("clear completed operations: %w", err)
	}
	return result.RowsAffected()
}

func (repository *Repository) begin(ctx context.Context) (*sql.Tx, error) {
	if repository == nil || repository.database == nil {
		return nil, errors.New("operation database is required")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin operation transaction: %w", err)
	}
	return transaction, nil
}

func appendStepTx(ctx context.Context, transaction *sql.Tx, operationID, occurredAt string, input StepInput) error {
	_, err := appendStepTxResult(ctx, transaction, operationID, occurredAt, input)
	return err
}

func appendStepTxResult(ctx context.Context, transaction *sql.Tx, operationID, occurredAt string, input StepInput) (Step, error) {
	if input.Severity != "DEBUG" && input.Severity != "INFO" && input.Severity != "WARNING" && input.Severity != "ERROR" {
		return Step{}, errors.New("operation step severity is invalid")
	}
	if !boundedToken(input.Stage, 64) || !boundedToken(input.Code, 128) {
		return Step{}, errors.New("operation step stage or code is invalid")
	}
	message := boundedText(loggingpkg.SanitizeText(input.Message), 512)
	details, err := json.Marshal(loggingpkg.SanitizeValue(input.Details))
	if err != nil || len(details) > 4096 {
		return Step{}, errors.New("operation step details are invalid or too large")
	}
	var sequence int64
	if err := transaction.QueryRowContext(ctx, "SELECT COALESCE(MAX(sequence), 0) + 1 FROM operation_steps WHERE operation_id=?", operationID).Scan(&sequence); err != nil {
		return Step{}, fmt.Errorf("allocate operation step sequence: %w", err)
	}
	result, err := transaction.ExecContext(ctx, `
INSERT INTO operation_steps (
    operation_id, sequence, occurred_at, severity, stage, code, message, details_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, operationID, sequence, occurredAt, input.Severity, input.Stage, input.Code, message, string(details))
	if err != nil {
		return Step{}, fmt.Errorf("append operation step: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Step{}, fmt.Errorf("read operation step id: %w", err)
	}
	return Step{ID: id, OperationID: operationID, Sequence: sequence, OccurredAt: occurredAt, Severity: input.Severity, Stage: input.Stage, Code: input.Code, Message: message, DetailsJSON: string(details)}, nil
}

func (repository *Repository) listSteps(ctx context.Context, operationID string) ([]Step, error) {
	rows, err := repository.database.QueryContext(ctx, `
SELECT id, operation_id, sequence, occurred_at, severity, stage, code, message, details_json
FROM operation_steps WHERE operation_id=? ORDER BY sequence`, operationID)
	if err != nil {
		return nil, fmt.Errorf("list operation steps: %w", err)
	}
	defer rows.Close()
	result := []Step{}
	for rows.Next() {
		var item Step
		if err := rows.Scan(&item.ID, &item.OperationID, &item.Sequence, &item.OccurredAt, &item.Severity, &item.Stage, &item.Code, &item.Message, &item.DetailsJSON); err != nil {
			return nil, fmt.Errorf("scan operation step: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

const operationSelect = `
SELECT id, kind, scope_type, scope_id, status, requested_by, summary_code,
       created_at, started_at, finished_at, updated_at
FROM operations`

type scanner interface {
	Scan(...any) error
}

func scanOperation(row scanner) (Operation, error) {
	var item Operation
	var startedAt, finishedAt sql.NullString
	err := row.Scan(&item.ID, &item.Kind, &item.ScopeType, &item.ScopeID, &item.Status, &item.RequestedBy, &item.SummaryCode, &item.CreatedAt, &startedAt, &finishedAt, &item.UpdatedAt)
	item.StartedAt = startedAt.String
	item.FinishedAt = finishedAt.String
	return item, err
}

func boundedToken(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return false
	}
	for _, current := range value {
		if current >= 'A' && current <= 'Z' || current >= '0' && current <= '9' || current == '_' || current == '-' {
			continue
		}
		return false
	}
	return true
}

func boundedText(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) <= maximum {
		return value
	}
	for len(value) > maximum || !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
