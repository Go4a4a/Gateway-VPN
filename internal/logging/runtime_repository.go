package logging

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	RetentionUnknown  = "UNKNOWN"
	RetentionPending  = "PENDING"
	RetentionApplying = "APPLYING"
	RetentionApplied  = "APPLIED"
	RetentionFailed   = "FAILED"
)

var safeRetentionErrorCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

type RetentionStatus struct {
	DesiredSHA256 string
	AppliedSHA256 string
	State         string
	AppliedAt     string
	LastErrorCode string
	UpdatedAt     string
}

type RuntimeRepository struct {
	Database *sql.DB
	Now      func() time.Time
}

func (repository RuntimeRepository) Get(ctx context.Context) (RetentionStatus, error) {
	if repository.Database == nil {
		return RetentionStatus{}, errors.New("logging runtime database is required")
	}
	var result RetentionStatus
	var appliedAt, errorCode sql.NullString
	err := repository.Database.QueryRowContext(ctx, `
SELECT desired_sha256, applied_sha256, state, applied_at, last_error_code, updated_at
FROM logging_runtime WHERE singleton_id=1`).Scan(
		&result.DesiredSHA256, &result.AppliedSHA256, &result.State,
		&appliedAt, &errorCode, &result.UpdatedAt,
	)
	if err != nil {
		return RetentionStatus{}, fmt.Errorf("read logging runtime: %w", err)
	}
	result.AppliedAt, result.LastErrorCode = appliedAt.String, errorCode.String
	return result, nil
}

func (repository RuntimeRepository) MarkApplying(ctx context.Context, desiredSHA256 string) error {
	if len(desiredSHA256) != 64 {
		return errors.New("complete logging retention fingerprint is required")
	}
	return repository.update(ctx, `
UPDATE logging_runtime
SET desired_sha256=?, state='APPLYING', last_error_code=NULL, updated_at=?
WHERE singleton_id=1`, desiredSHA256, repository.now().Format(time.RFC3339Nano))
}

func (repository RuntimeRepository) MarkApplied(ctx context.Context, desiredSHA256 string) error {
	if len(desiredSHA256) != 64 {
		return errors.New("complete logging retention fingerprint is required")
	}
	now := repository.now().Format(time.RFC3339Nano)
	return repository.update(ctx, `
UPDATE logging_runtime
SET applied_sha256=?, state='APPLIED', applied_at=?, last_error_code=NULL, updated_at=?
WHERE singleton_id=1 AND desired_sha256=?`, desiredSHA256, now, now, desiredSHA256)
}

func (repository RuntimeRepository) MarkFailed(ctx context.Context, desiredSHA256, errorCode string) error {
	if len(desiredSHA256) != 64 || !safeRetentionErrorCode.MatchString(errorCode) {
		return errors.New("logging retention fingerprint and stable error code are required")
	}
	return repository.update(ctx, `
UPDATE logging_runtime
SET state='FAILED', last_error_code=?, updated_at=?
WHERE singleton_id=1 AND desired_sha256=?`, errorCode, repository.now().Format(time.RFC3339Nano), desiredSHA256)
}

func (repository RuntimeRepository) update(ctx context.Context, query string, arguments ...any) error {
	if repository.Database == nil {
		return errors.New("logging runtime database is required")
	}
	result, err := repository.Database.ExecContext(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("update logging runtime: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil {
		return countErr
	} else if count != 1 {
		return errors.New("logging runtime update lost desired generation")
	}
	return nil
}

func (repository RuntimeRepository) now() time.Time {
	if repository.Now != nil {
		return repository.Now().UTC()
	}
	return time.Now().UTC()
}
