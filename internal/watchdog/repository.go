package watchdog

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

func (repository Repository) Get(ctx context.Context) (Policy, error) {
	if repository.Database == nil {
		return Policy{}, errors.New("watchdog settings database is required")
	}
	return ReadPolicy(ctx, repository.Database)
}

func (repository Repository) Update(ctx context.Context, input UpdateInput) (Policy, error) {
	if repository.Database == nil {
		return Policy{}, errors.New("watchdog settings database is required")
	}
	now := repository.now()
	next, err := NormalizeUpdate(input, now)
	if err != nil {
		return Policy{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, fmt.Errorf("begin watchdog policy update: %w", err)
	}
	defer transaction.Rollback()
	previous, err := ReadPolicy(ctx, transaction)
	if err != nil {
		return Policy{}, err
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return Policy{}, fmt.Errorf("encode watchdog policy: %w", err)
	}
	result, err := transaction.ExecContext(ctx, "UPDATE settings SET value_json=?, updated_at=? WHERE key='watchdog'", string(payload), next.UpdatedAt)
	if err != nil {
		return Policy{}, fmt.Errorf("write watchdog policy: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		if countErr != nil {
			return Policy{}, fmt.Errorf("read watchdog policy update count: %w", countErr)
		}
		return Policy{}, errors.New("watchdog settings row is missing")
	}
	details, err := json.Marshal(map[string]any{
		"previous":              policyAuditMetadata(previous),
		"current":               policyAuditMetadata(next),
		"durable_budgets_reset": false,
	})
	if err != nil {
		return Policy{}, fmt.Errorf("encode watchdog policy audit: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, 'INFO', 'WATCHDOG_SETTINGS_CHANGED', ?)`, now.Format(time.RFC3339Nano), string(details)); err != nil {
		return Policy{}, fmt.Errorf("record watchdog policy audit: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Policy{}, fmt.Errorf("commit watchdog policy update: %w", err)
	}
	return next, nil
}

type policyQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// ReadPolicy is intentionally compatible with a query-only SQLite handle used
// by the privileged watchdog. It never creates tables, WAL or runtime rows.
func ReadPolicy(ctx context.Context, query policyQuery) (Policy, error) {
	var payload, updatedAt string
	if err := query.QueryRowContext(ctx, "SELECT value_json, updated_at FROM settings WHERE key='watchdog'").Scan(&payload, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Policy{}, errors.New("watchdog settings row is missing")
		}
		return Policy{}, fmt.Errorf("read watchdog policy: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(payload)))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("decode watchdog policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("watchdog policy contains trailing JSON")
	}
	policy.UpdatedAt = updatedAt
	if err := policy.Validate(); err != nil {
		return Policy{}, fmt.Errorf("validate stored watchdog policy: %w", err)
	}
	return policy, nil
}

func policyAuditMetadata(policy Policy) map[string]any {
	return map[string]any{
		"enabled": policy.Enabled, "check_interval_seconds": policy.CheckIntervalSeconds,
		"failure_threshold": policy.FailureThreshold, "success_threshold": policy.SuccessThreshold,
		"reconcile_enabled": policy.ReconcileEnabled, "component_restart_enabled": policy.ComponentRestartEnabled,
		"restart_cooldown_seconds":          policy.RestartCooldownSeconds,
		"max_restarts_per_component":        policy.MaxRestartsPerComponent,
		"restart_window_seconds":            policy.RestartWindowSeconds,
		"host_reboot_enabled":               policy.HostRebootEnabled,
		"reboot_after_critical_seconds":     policy.RebootAfterCriticalSeconds,
		"max_reboots_per_24h":               policy.MaxRebootsPer24h,
		"reboot_grace_seconds":              policy.RebootGraceSeconds,
		"worker_stale_seconds":              policy.WorkerStaleSeconds,
		"wireguard_handshake_stale_seconds": policy.WireGuardHandshakeStaleSeconds,
		"backup_max_age_hours":              policy.BackupMaxAgeHours,
		"database_wal_max_bytes":            policy.DatabaseWALMaxBytes,
		"minimum_disk_free_bytes":           policy.MinimumDiskFreeBytes,
		"minimum_disk_free_percent":         policy.MinimumDiskFreePercent,
		"minimum_memory_available_bytes":    policy.MinimumMemoryAvailableBytes,
		"minimum_memory_available_percent":  policy.MinimumMemoryAvailablePercent,
		"component_recovery_modes":          cloneRecoveryModes(policy.ComponentRecoveryModes),
	}
}

func (repository Repository) now() time.Time {
	if repository.Now != nil {
		return repository.Now().UTC()
	}
	return time.Now().UTC()
}
