// Package watchdog owns Gateway VPN's bounded self-health policy, durable
// recovery budgets and the fixed-component supervisor contract.
package watchdog

import (
	"errors"
	"fmt"
	"time"
)

const (
	PolicySchemaVersion = 2

	RecoveryModeMonitorOnly = "MONITOR_ONLY"
	RecoveryModeReconcile   = "RECONCILE"
	RecoveryModeRestart     = "RESTART"

	MinimumCheckIntervalSeconds = 5
	MaximumCheckIntervalSeconds = 300
	MinimumFailureThreshold     = 1
	MaximumFailureThreshold     = 10
	MinimumSuccessThreshold     = 1
	MaximumSuccessThreshold     = 10
	MinimumRestartCooldown      = 5
	MaximumRestartCooldown      = 3600
	MinimumRestartBudget        = 1
	MaximumRestartBudget        = 20
	MinimumRestartWindow        = 60
	MaximumRestartWindow        = 86400
	MinimumRebootCritical       = 300
	MaximumRebootCritical       = 86400
	MinimumRebootBudget         = 1
	MaximumRebootBudget         = 3
	MinimumRebootGrace          = 10
	MaximumRebootGrace          = 600
	MinimumWorkerStaleSeconds   = 30
	MaximumWorkerStaleSeconds   = 900
	MinimumWGHandshakeStale     = 60
	MaximumWGHandshakeStale     = 3600
	MinimumBackupMaxAgeHours    = 24
	MaximumBackupMaxAgeHours    = 168
	MinimumDatabaseWALBytes     = int64(64 << 20)
	MaximumDatabaseWALBytes     = int64(4 << 30)
	MinimumDiskFreeBytesFloor   = int64(128 << 20)
	MaximumDiskFreeBytesFloor   = int64(16 << 30)
	MinimumMemoryBytesFloor     = int64(64 << 20)
	MaximumMemoryBytesFloor     = int64(8 << 30)
	MinimumResourcePercent      = 1
	MaximumResourcePercent      = 25
)

type Policy struct {
	SchemaVersion                  int               `json:"schema_version"`
	Enabled                        bool              `json:"enabled"`
	CheckIntervalSeconds           int               `json:"check_interval_seconds"`
	FailureThreshold               int               `json:"failure_threshold"`
	SuccessThreshold               int               `json:"success_threshold"`
	ReconcileEnabled               bool              `json:"reconcile_enabled"`
	ComponentRestartEnabled        bool              `json:"component_restart_enabled"`
	RestartCooldownSeconds         int               `json:"restart_cooldown_seconds"`
	MaxRestartsPerComponent        int               `json:"max_restarts_per_component"`
	RestartWindowSeconds           int               `json:"restart_window_seconds"`
	HostRebootEnabled              bool              `json:"host_reboot_enabled"`
	RebootAfterCriticalSeconds     int               `json:"reboot_after_critical_seconds"`
	MaxRebootsPer24h               int               `json:"max_reboots_per_24h"`
	RebootGraceSeconds             int               `json:"reboot_grace_seconds"`
	WorkerStaleSeconds             int               `json:"worker_stale_seconds"`
	WireGuardHandshakeStaleSeconds int               `json:"wireguard_handshake_stale_seconds"`
	BackupMaxAgeHours              int               `json:"backup_max_age_hours"`
	DatabaseWALMaxBytes            int64             `json:"database_wal_max_bytes"`
	MinimumDiskFreeBytes           int64             `json:"minimum_disk_free_bytes"`
	MinimumDiskFreePercent         int               `json:"minimum_disk_free_percent"`
	MinimumMemoryAvailableBytes    int64             `json:"minimum_memory_available_bytes"`
	MinimumMemoryAvailablePercent  int               `json:"minimum_memory_available_percent"`
	ComponentRecoveryModes         map[string]string `json:"component_recovery_modes"`
	UpdatedAt                      string            `json:"updated_at"`
}

type UpdateInput struct {
	Enabled                        bool
	CheckIntervalSeconds           int
	FailureThreshold               int
	SuccessThreshold               int
	ReconcileEnabled               bool
	ComponentRestartEnabled        bool
	RestartCooldownSeconds         int
	MaxRestartsPerComponent        int
	RestartWindowSeconds           int
	HostRebootEnabled              bool
	RebootAfterCriticalSeconds     int
	MaxRebootsPer24h               int
	RebootGraceSeconds             int
	WorkerStaleSeconds             int
	WireGuardHandshakeStaleSeconds int
	BackupMaxAgeHours              int
	DatabaseWALMaxBytes            int64
	MinimumDiskFreeBytes           int64
	MinimumDiskFreePercent         int
	MinimumMemoryAvailableBytes    int64
	MinimumMemoryAvailablePercent  int
	ComponentRecoveryModes         map[string]string
}

func DefaultPolicy() Policy {
	return Policy{
		SchemaVersion: PolicySchemaVersion, Enabled: true, CheckIntervalSeconds: 15,
		FailureThreshold: 3, SuccessThreshold: 2, ReconcileEnabled: true,
		ComponentRestartEnabled: true, RestartCooldownSeconds: 30,
		MaxRestartsPerComponent: 5, RestartWindowSeconds: 900,
		HostRebootEnabled: false, RebootAfterCriticalSeconds: 900,
		MaxRebootsPer24h: 1, RebootGraceSeconds: 60,
		WorkerStaleSeconds: 120, WireGuardHandshakeStaleSeconds: 180,
		BackupMaxAgeHours: 36, DatabaseWALMaxBytes: 256 << 20,
		MinimumDiskFreeBytes: 512 << 20, MinimumDiskFreePercent: 5,
		MinimumMemoryAvailableBytes: 128 << 20, MinimumMemoryAvailablePercent: 5,
		ComponentRecoveryModes: defaultRecoveryModes(),
	}
}

func (policy Policy) Validate() error {
	if policy.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("watchdog policy schema version must be %d", PolicySchemaVersion)
	}
	if policy.CheckIntervalSeconds < MinimumCheckIntervalSeconds || policy.CheckIntervalSeconds > MaximumCheckIntervalSeconds {
		return fmt.Errorf("watchdog check interval must be %d..%d seconds", MinimumCheckIntervalSeconds, MaximumCheckIntervalSeconds)
	}
	if policy.FailureThreshold < MinimumFailureThreshold || policy.FailureThreshold > MaximumFailureThreshold {
		return fmt.Errorf("watchdog failure threshold must be %d..%d", MinimumFailureThreshold, MaximumFailureThreshold)
	}
	if policy.SuccessThreshold < MinimumSuccessThreshold || policy.SuccessThreshold > MaximumSuccessThreshold {
		return fmt.Errorf("watchdog success threshold must be %d..%d", MinimumSuccessThreshold, MaximumSuccessThreshold)
	}
	if policy.RestartCooldownSeconds < MinimumRestartCooldown || policy.RestartCooldownSeconds > MaximumRestartCooldown {
		return fmt.Errorf("watchdog restart cooldown must be %d..%d seconds", MinimumRestartCooldown, MaximumRestartCooldown)
	}
	if policy.MaxRestartsPerComponent < MinimumRestartBudget || policy.MaxRestartsPerComponent > MaximumRestartBudget {
		return fmt.Errorf("watchdog restart budget must be %d..%d", MinimumRestartBudget, MaximumRestartBudget)
	}
	if policy.RestartWindowSeconds < MinimumRestartWindow || policy.RestartWindowSeconds > MaximumRestartWindow || policy.RestartWindowSeconds < policy.RestartCooldownSeconds {
		return errors.New("watchdog restart window is outside the supported range or shorter than cooldown")
	}
	if policy.RebootAfterCriticalSeconds < MinimumRebootCritical || policy.RebootAfterCriticalSeconds > MaximumRebootCritical {
		return fmt.Errorf("watchdog critical reboot delay must be %d..%d seconds", MinimumRebootCritical, MaximumRebootCritical)
	}
	if policy.MaxRebootsPer24h < MinimumRebootBudget || policy.MaxRebootsPer24h > MaximumRebootBudget {
		return fmt.Errorf("watchdog reboot budget must be %d..%d per 24 hours", MinimumRebootBudget, MaximumRebootBudget)
	}
	if policy.RebootGraceSeconds < MinimumRebootGrace || policy.RebootGraceSeconds > MaximumRebootGrace {
		return fmt.Errorf("watchdog reboot grace must be %d..%d seconds", MinimumRebootGrace, MaximumRebootGrace)
	}
	if policy.WorkerStaleSeconds < MinimumWorkerStaleSeconds || policy.WorkerStaleSeconds > MaximumWorkerStaleSeconds {
		return fmt.Errorf("watchdog worker stale threshold must be %d..%d seconds", MinimumWorkerStaleSeconds, MaximumWorkerStaleSeconds)
	}
	if policy.WireGuardHandshakeStaleSeconds < MinimumWGHandshakeStale || policy.WireGuardHandshakeStaleSeconds > MaximumWGHandshakeStale {
		return fmt.Errorf("watchdog WireGuard handshake stale threshold must be %d..%d seconds", MinimumWGHandshakeStale, MaximumWGHandshakeStale)
	}
	if policy.BackupMaxAgeHours < MinimumBackupMaxAgeHours || policy.BackupMaxAgeHours > MaximumBackupMaxAgeHours {
		return fmt.Errorf("watchdog backup maximum age must be %d..%d hours", MinimumBackupMaxAgeHours, MaximumBackupMaxAgeHours)
	}
	if policy.DatabaseWALMaxBytes < MinimumDatabaseWALBytes || policy.DatabaseWALMaxBytes > MaximumDatabaseWALBytes {
		return errors.New("watchdog database WAL threshold is outside the supported range")
	}
	if policy.MinimumDiskFreeBytes < MinimumDiskFreeBytesFloor || policy.MinimumDiskFreeBytes > MaximumDiskFreeBytesFloor || policy.MinimumMemoryAvailableBytes < MinimumMemoryBytesFloor || policy.MinimumMemoryAvailableBytes > MaximumMemoryBytesFloor {
		return errors.New("watchdog disk or memory byte floor is outside the supported range")
	}
	if policy.MinimumDiskFreePercent < MinimumResourcePercent || policy.MinimumDiskFreePercent > MaximumResourcePercent || policy.MinimumMemoryAvailablePercent < MinimumResourcePercent || policy.MinimumMemoryAvailablePercent > MaximumResourcePercent {
		return errors.New("watchdog disk or memory percent floor is outside the supported range")
	}
	if err := validateRecoveryModes(policy.ComponentRecoveryModes); err != nil {
		return err
	}
	if policy.UpdatedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, policy.UpdatedAt); err != nil {
			return errors.New("watchdog policy update timestamp is invalid")
		}
	}
	return nil
}

func NormalizeUpdate(input UpdateInput, now time.Time) (Policy, error) {
	modes := input.ComponentRecoveryModes
	if len(modes) == 0 {
		modes = defaultRecoveryModes()
	}
	policy := Policy{
		SchemaVersion: PolicySchemaVersion, Enabled: input.Enabled,
		CheckIntervalSeconds: input.CheckIntervalSeconds,
		FailureThreshold:     input.FailureThreshold, SuccessThreshold: input.SuccessThreshold,
		ReconcileEnabled: input.ReconcileEnabled, ComponentRestartEnabled: input.ComponentRestartEnabled,
		RestartCooldownSeconds:     input.RestartCooldownSeconds,
		MaxRestartsPerComponent:    input.MaxRestartsPerComponent,
		RestartWindowSeconds:       input.RestartWindowSeconds,
		HostRebootEnabled:          input.HostRebootEnabled,
		RebootAfterCriticalSeconds: input.RebootAfterCriticalSeconds,
		MaxRebootsPer24h:           input.MaxRebootsPer24h, RebootGraceSeconds: input.RebootGraceSeconds,
		WorkerStaleSeconds:             input.WorkerStaleSeconds,
		WireGuardHandshakeStaleSeconds: input.WireGuardHandshakeStaleSeconds,
		BackupMaxAgeHours:              input.BackupMaxAgeHours, DatabaseWALMaxBytes: input.DatabaseWALMaxBytes,
		MinimumDiskFreeBytes: input.MinimumDiskFreeBytes, MinimumDiskFreePercent: input.MinimumDiskFreePercent,
		MinimumMemoryAvailableBytes:   input.MinimumMemoryAvailableBytes,
		MinimumMemoryAvailablePercent: input.MinimumMemoryAvailablePercent,
		ComponentRecoveryModes:        cloneRecoveryModes(modes),
		UpdatedAt:                     now.UTC().Format(time.RFC3339Nano),
	}
	if err := policy.Validate(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func (policy Policy) CheckInterval() time.Duration {
	return time.Duration(policy.CheckIntervalSeconds) * time.Second
}

func (policy Policy) RestartWindow() time.Duration {
	return time.Duration(policy.RestartWindowSeconds) * time.Second
}

func (policy Policy) RecoveryMode(componentID string) string {
	if mode := policy.ComponentRecoveryModes[componentID]; mode != "" {
		return mode
	}
	return RecoveryModeMonitorOnly
}

func defaultRecoveryModes() map[string]string {
	result := make(map[string]string, len(fixedComponentSpecs))
	for _, spec := range fixedComponentSpecs {
		if spec.Restartable {
			result[spec.ID] = RecoveryModeRestart
		} else if spec.Reconcileable {
			result[spec.ID] = RecoveryModeReconcile
		} else {
			result[spec.ID] = RecoveryModeMonitorOnly
		}
	}
	return result
}

func cloneRecoveryModes(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func validateRecoveryModes(modes map[string]string) error {
	if len(modes) != len(fixedComponentSpecs) {
		return errors.New("watchdog recovery modes must cover every fixed component")
	}
	for _, spec := range fixedComponentSpecs {
		mode, exists := modes[spec.ID]
		if !exists {
			return fmt.Errorf("watchdog recovery mode for %s is missing", spec.ID)
		}
		switch mode {
		case RecoveryModeMonitorOnly:
		case RecoveryModeReconcile:
			if !spec.Reconcileable {
				return fmt.Errorf("component %s does not support reconcile", spec.ID)
			}
		case RecoveryModeRestart:
			if !spec.Restartable {
				return fmt.Errorf("component %s does not support restart", spec.ID)
			}
		default:
			return fmt.Errorf("component %s has invalid recovery mode", spec.ID)
		}
	}
	for id := range modes {
		if !validComponentID(id) {
			return errors.New("watchdog recovery modes contain an unknown component")
		}
	}
	return nil
}
