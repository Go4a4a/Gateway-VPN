package update

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

const (
	AutomationPolicySchemaVersion = 2
	MinimumCheckIntervalHours     = 1
	MaximumCheckIntervalHours     = 24 * 7
	MaximumJitterMinutes          = 6 * 60
	MinimumMaintenanceMinutes     = 15
	MaximumMaintenanceMinutes     = 12 * 60
	MinimumApplyDelayHours        = 1
	MaximumApplyDelayHours        = 30 * 24
	MinimumRetentionAgeDays       = 1
	MaximumRetentionAgeDays       = 10 * 365
)

type AutomationPolicy struct {
	SchemaVersion              int    `json:"schema_version"`
	Channel                    string `json:"channel"`
	AutomaticCheckEnabled      bool   `json:"automatic_check_enabled"`
	AutomaticDownloadEnabled   bool   `json:"automatic_download_enabled"`
	AutomaticApplyEnabled      bool   `json:"automatic_apply_enabled"`
	CheckIntervalHours         int    `json:"check_interval_hours"`
	JitterMinutes              int    `json:"jitter_minutes"`
	MaintenanceWindowEnabled   bool   `json:"maintenance_window_enabled"`
	MaintenanceStartMinuteUTC  int    `json:"maintenance_start_minute_utc"`
	MaintenanceDurationMinutes int    `json:"maintenance_duration_minutes"`
	MaximumApplyDelayHours     int    `json:"maximum_apply_delay_hours"`
	RetentionMaximumPoints     int    `json:"retention_maximum_points"`
	RetentionMaximumBytes      int64  `json:"retention_maximum_bytes"`
	RetentionMaximumAgeDays    int    `json:"retention_maximum_age_days"`
	RetentionMinimumOldPoints  int    `json:"retention_minimum_old_points"`
	UpdatedAt                  string `json:"updated_at"`
}

type AutomationPolicyInput struct {
	Channel                    string
	AutomaticCheckEnabled      bool
	AutomaticDownloadEnabled   bool
	AutomaticApplyEnabled      bool
	CheckIntervalHours         int
	JitterMinutes              int
	MaintenanceWindowEnabled   bool
	MaintenanceStartMinuteUTC  int
	MaintenanceDurationMinutes int
	MaximumApplyDelayHours     int
	RetentionMaximumPoints     int
	RetentionMaximumBytes      int64
	RetentionMaximumAgeDays    int
	RetentionMinimumOldPoints  int
}

type AutomationPolicyRepository struct {
	Database *sql.DB
	Now      func() time.Time
}

func DefaultAutomationPolicy() AutomationPolicy {
	return AutomationPolicy{
		SchemaVersion: AutomationPolicySchemaVersion, Channel: "stable", AutomaticCheckEnabled: true,
		CheckIntervalHours: 24, JitterMinutes: 30,
		MaintenanceStartMinuteUTC: 180, MaintenanceDurationMinutes: 120,
		MaximumApplyDelayHours: 72,
		RetentionMaximumPoints: 4, RetentionMaximumBytes: 8 << 30,
		RetentionMaximumAgeDays: 365, RetentionMinimumOldPoints: 2,
	}
}

func (policy AutomationPolicy) Validate() error {
	if policy.SchemaVersion != AutomationPolicySchemaVersion || policy.Channel != "stable" && policy.Channel != "testing" {
		return errors.New("software update policy schema or channel is invalid")
	}
	if policy.AutomaticApplyEnabled && (!policy.AutomaticDownloadEnabled || !policy.AutomaticCheckEnabled || !policy.MaintenanceWindowEnabled) || policy.AutomaticDownloadEnabled && !policy.AutomaticCheckEnabled {
		return errors.New("automatic apply requires check, download and a maintenance window")
	}
	if policy.CheckIntervalHours < MinimumCheckIntervalHours || policy.CheckIntervalHours > MaximumCheckIntervalHours || policy.JitterMinutes < 0 || policy.JitterMinutes > MaximumJitterMinutes || policy.JitterMinutes >= policy.CheckIntervalHours*60 {
		return errors.New("software update interval or jitter is outside the supported range")
	}
	if policy.MaintenanceStartMinuteUTC < 0 || policy.MaintenanceStartMinuteUTC >= 24*60 || policy.MaintenanceDurationMinutes < MinimumMaintenanceMinutes || policy.MaintenanceDurationMinutes > MaximumMaintenanceMinutes {
		return errors.New("software update maintenance window is outside the supported range")
	}
	if policy.MaximumApplyDelayHours < MinimumApplyDelayHours || policy.MaximumApplyDelayHours > MaximumApplyDelayHours {
		return errors.New("software update maximum apply delay is outside the supported range")
	}
	retention := policy.RetentionPolicy()
	if !validRestorePointPolicy(retention) || policy.RetentionMaximumAgeDays < MinimumRetentionAgeDays || policy.RetentionMaximumAgeDays > MaximumRetentionAgeDays {
		return errors.New("software update retention policy is outside the supported range")
	}
	if policy.UpdatedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, policy.UpdatedAt); err != nil {
			return errors.New("software update policy timestamp is invalid")
		}
	}
	return nil
}

func (policy AutomationPolicy) RetentionPolicy() RestorePointPolicy {
	return RestorePointPolicy{
		MaximumPoints: policy.RetentionMaximumPoints, MaximumBytes: policy.RetentionMaximumBytes,
		MaximumAge:       time.Duration(policy.RetentionMaximumAgeDays) * 24 * time.Hour,
		MinimumOldPoints: policy.RetentionMinimumOldPoints,
	}
}

func NormalizeAutomationPolicy(input AutomationPolicyInput, now time.Time) (AutomationPolicy, error) {
	policy := AutomationPolicy{
		SchemaVersion: AutomationPolicySchemaVersion, Channel: input.Channel,
		AutomaticCheckEnabled: input.AutomaticCheckEnabled, AutomaticDownloadEnabled: input.AutomaticDownloadEnabled,
		AutomaticApplyEnabled: input.AutomaticApplyEnabled, CheckIntervalHours: input.CheckIntervalHours,
		JitterMinutes: input.JitterMinutes, MaintenanceWindowEnabled: input.MaintenanceWindowEnabled,
		MaintenanceStartMinuteUTC: input.MaintenanceStartMinuteUTC, MaintenanceDurationMinutes: input.MaintenanceDurationMinutes,
		MaximumApplyDelayHours: input.MaximumApplyDelayHours,
		RetentionMaximumPoints: input.RetentionMaximumPoints, RetentionMaximumBytes: input.RetentionMaximumBytes,
		RetentionMaximumAgeDays: input.RetentionMaximumAgeDays, RetentionMinimumOldPoints: input.RetentionMinimumOldPoints,
		UpdatedAt: now.UTC().Format(time.RFC3339Nano),
	}
	if err := policy.Validate(); err != nil {
		return AutomationPolicy{}, err
	}
	return policy, nil
}

func (repository AutomationPolicyRepository) Get(ctx context.Context) (AutomationPolicy, error) {
	if repository.Database == nil {
		return AutomationPolicy{}, errors.New("software update policy database is required")
	}
	return ReadAutomationPolicy(ctx, repository.Database)
}

func (repository AutomationPolicyRepository) Update(ctx context.Context, input AutomationPolicyInput) (AutomationPolicy, error) {
	if repository.Database == nil {
		return AutomationPolicy{}, errors.New("software update policy database is required")
	}
	now := time.Now().UTC()
	if repository.Now != nil {
		now = repository.Now().UTC()
	}
	next, err := NormalizeAutomationPolicy(input, now)
	if err != nil {
		return AutomationPolicy{}, err
	}
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return AutomationPolicy{}, fmt.Errorf("begin software update policy transaction: %w", err)
	}
	defer transaction.Rollback()
	previous, err := ReadAutomationPolicy(ctx, transaction)
	if err != nil {
		return AutomationPolicy{}, err
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return AutomationPolicy{}, err
	}
	result, err := transaction.ExecContext(ctx, "UPDATE settings SET value_json=?,updated_at=? WHERE key='software_update_policy'", string(payload), next.UpdatedAt)
	if err != nil {
		return AutomationPolicy{}, fmt.Errorf("write software update policy: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
		return AutomationPolicy{}, errors.New("software update policy row is missing")
	}
	details, err := json.Marshal(map[string]any{"previous": automationPolicyAudit(previous), "current": automationPolicyAudit(next)})
	if err != nil {
		return AutomationPolicy{}, err
	}
	if _, err := transaction.ExecContext(ctx, "INSERT INTO events(occurred_at,severity,type,details_json) VALUES(?,'WARNING','SOFTWARE_UPDATE_POLICY_CHANGED',?)", next.UpdatedAt, string(details)); err != nil {
		return AutomationPolicy{}, fmt.Errorf("record software update policy audit: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return AutomationPolicy{}, fmt.Errorf("commit software update policy: %w", err)
	}
	return next, nil
}

type automationPolicyQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func ReadAutomationPolicy(ctx context.Context, query automationPolicyQuery) (AutomationPolicy, error) {
	var payload, updatedAt string
	if err := query.QueryRowContext(ctx, "SELECT value_json,updated_at FROM settings WHERE key='software_update_policy'").Scan(&payload, &updatedAt); err != nil {
		return AutomationPolicy{}, fmt.Errorf("read software update policy: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(payload)))
	decoder.DisallowUnknownFields()
	var policy AutomationPolicy
	if err := decoder.Decode(&policy); err != nil {
		return AutomationPolicy{}, fmt.Errorf("decode software update policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return AutomationPolicy{}, errors.New("software update policy contains trailing JSON")
	}
	policy.UpdatedAt = updatedAt
	if err := policy.Validate(); err != nil {
		return AutomationPolicy{}, err
	}
	return policy, nil
}

func automationPolicyAudit(policy AutomationPolicy) map[string]any {
	return map[string]any{
		"channel": policy.Channel, "automatic_check_enabled": policy.AutomaticCheckEnabled,
		"automatic_download_enabled": policy.AutomaticDownloadEnabled, "automatic_apply_enabled": policy.AutomaticApplyEnabled,
		"check_interval_hours": policy.CheckIntervalHours, "jitter_minutes": policy.JitterMinutes,
		"maintenance_window_enabled":   policy.MaintenanceWindowEnabled,
		"maintenance_start_minute_utc": policy.MaintenanceStartMinuteUTC,
		"maintenance_duration_minutes": policy.MaintenanceDurationMinutes,
		"maximum_apply_delay_hours":    policy.MaximumApplyDelayHours,
		"retention_maximum_points":     policy.RetentionMaximumPoints, "retention_maximum_bytes": policy.RetentionMaximumBytes,
		"retention_maximum_age_days":   policy.RetentionMaximumAgeDays,
		"retention_minimum_old_points": policy.RetentionMinimumOldPoints,
	}
}
