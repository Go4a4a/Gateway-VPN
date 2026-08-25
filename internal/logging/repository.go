package logging

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

type Repository struct {
	Database *sql.DB
	Now      func() time.Time
}

func (repository Repository) Get(ctx context.Context) (Settings, error) {
	if repository.Database == nil {
		return Settings{}, errors.New("logging settings database is required")
	}
	return readSettings(ctx, repository.Database)
}

func (repository Repository) Update(ctx context.Context, input UpdateInput) (Settings, error) {
	if repository.Database == nil {
		return Settings{}, errors.New("logging settings database is required")
	}
	now := repository.now()
	next, err := normalizeUpdate(input, now)
	if err != nil {
		return Settings{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Settings{}, fmt.Errorf("begin logging settings update: %w", err)
	}
	defer transaction.Rollback()
	previous, err := readSettings(ctx, transaction)
	if err != nil {
		return Settings{}, err
	}
	if err := writeSettings(ctx, transaction, next); err != nil {
		return Settings{}, err
	}
	desiredFingerprint := RetentionFingerprint(next)
	if _, err := transaction.ExecContext(ctx, `
UPDATE logging_runtime
SET desired_sha256=?,
    state=CASE WHEN applied_sha256=? THEN 'APPLIED' ELSE 'PENDING' END,
    last_error_code=NULL,
    updated_at=?
WHERE singleton_id=1`, desiredFingerprint, desiredFingerprint, now.Format(time.RFC3339Nano)); err != nil {
		return Settings{}, fmt.Errorf("mark logging retention desired: %w", err)
	}
	if err := appendSettingsEvent(ctx, transaction, now, "LOGGING_SETTINGS_CHANGED", map[string]any{
		"previous": settingsMetadata(previous),
		"current":  settingsMetadata(next),
	}); err != nil {
		return Settings{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Settings{}, fmt.Errorf("commit logging settings update: %w", err)
	}
	return next, nil
}

func (repository Repository) ExpireDebug(ctx context.Context) (Settings, bool, error) {
	if repository.Database == nil {
		return Settings{}, false, errors.New("logging settings database is required")
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Settings{}, false, fmt.Errorf("begin debug expiry: %w", err)
	}
	defer transaction.Rollback()
	current, err := readSettings(ctx, transaction)
	if err != nil {
		return Settings{}, false, err
	}
	if current.DebugUntil == "" || len(current.DebugComponents) == 0 {
		return current, false, transaction.Commit()
	}
	deadline, err := time.Parse(time.RFC3339Nano, current.DebugUntil)
	if err != nil {
		return Settings{}, false, errors.New("stored debug deadline is invalid")
	}
	now := repository.now()
	if deadline.After(now) {
		return current, false, transaction.Commit()
	}
	expiredComponents := append([]string(nil), current.DebugComponents...)
	current.DebugComponents = []string{}
	current.DebugUntil = ""
	current.UpdatedAt = now.Format(time.RFC3339Nano)
	if err := writeSettings(ctx, transaction, current); err != nil {
		return Settings{}, false, err
	}
	if err := appendSettingsEvent(ctx, transaction, now, "LOGGING_DEBUG_EXPIRED", map[string]any{
		"debug_components": expiredComponents,
		"expired_at":       deadline.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return Settings{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Settings{}, false, fmt.Errorf("commit debug expiry: %w", err)
	}
	return current, true, nil
}

type settingsQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readSettings(ctx context.Context, query settingsQuery) (Settings, error) {
	var payload, updatedAt string
	if err := query.QueryRowContext(ctx, "SELECT value_json, updated_at FROM settings WHERE key='logging'").Scan(&payload, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Settings{}, errors.New("logging settings row is missing")
		}
		return Settings{}, fmt.Errorf("read logging settings: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(payload)))
	decoder.DisallowUnknownFields()
	var settings Settings
	if err := decoder.Decode(&settings); err != nil {
		return Settings{}, fmt.Errorf("decode logging settings: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Settings{}, errors.New("logging settings contain trailing JSON")
	}
	settings.UpdatedAt = updatedAt
	if settings.ComponentLevels == nil {
		settings.ComponentLevels = map[string]string{}
	}
	if settings.DebugComponents == nil {
		settings.DebugComponents = []string{}
	}
	if err := settings.Validate(); err != nil {
		return Settings{}, fmt.Errorf("validate stored logging settings: %w", err)
	}
	return settings, nil
}

func writeSettings(ctx context.Context, transaction *sql.Tx, settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("encode logging settings: %w", err)
	}
	result, err := transaction.ExecContext(ctx, "UPDATE settings SET value_json=?, updated_at=? WHERE key='logging'", string(payload), settings.UpdatedAt)
	if err != nil {
		return fmt.Errorf("write logging settings: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil {
		return fmt.Errorf("read logging settings update count: %w", countErr)
	} else if count != 1 {
		return errors.New("logging settings row is missing")
	}
	return nil
}

func appendSettingsEvent(ctx context.Context, transaction *sql.Tx, now time.Time, eventType string, details map[string]any) error {
	payload, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode logging audit event: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, 'INFO', ?, ?)`, now.UTC().Format(time.RFC3339Nano), eventType, string(payload)); err != nil {
		return fmt.Errorf("record logging audit event: %w", err)
	}
	return nil
}

func settingsMetadata(settings Settings) map[string]any {
	return map[string]any{
		"global_level": settings.GlobalLevel, "component_levels": settings.ComponentLevels,
		"debug_components": settings.DebugComponents, "debug_until": settings.DebugUntil,
		"retention_days": settings.RetentionDays, "max_disk_usage_bytes": settings.MaxDiskUsageBytes,
		"diagnostic_excerpt_bytes":         settings.DiagnosticExcerptBytes,
		"health_error_aggregation_seconds": settings.HealthErrorAggregationSeconds,
	}
}

func (repository Repository) now() time.Time {
	if repository.Now != nil {
		return repository.Now().UTC()
	}
	return time.Now().UTC()
}
