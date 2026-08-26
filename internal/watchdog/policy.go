// Package watchdog owns Gateway VPN's bounded self-health policy, durable
// recovery budgets and the fixed-component supervisor contract.
package watchdog

import (
	"errors"
	"fmt"
	"time"
)

const (
	PolicySchemaVersion = 1

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
)

type Policy struct {
	SchemaVersion              int    `json:"schema_version"`
	Enabled                    bool   `json:"enabled"`
	CheckIntervalSeconds       int    `json:"check_interval_seconds"`
	FailureThreshold           int    `json:"failure_threshold"`
	SuccessThreshold           int    `json:"success_threshold"`
	ReconcileEnabled           bool   `json:"reconcile_enabled"`
	ComponentRestartEnabled    bool   `json:"component_restart_enabled"`
	RestartCooldownSeconds     int    `json:"restart_cooldown_seconds"`
	MaxRestartsPerComponent    int    `json:"max_restarts_per_component"`
	RestartWindowSeconds       int    `json:"restart_window_seconds"`
	HostRebootEnabled          bool   `json:"host_reboot_enabled"`
	RebootAfterCriticalSeconds int    `json:"reboot_after_critical_seconds"`
	MaxRebootsPer24h           int    `json:"max_reboots_per_24h"`
	RebootGraceSeconds         int    `json:"reboot_grace_seconds"`
	UpdatedAt                  string `json:"updated_at"`
}

type UpdateInput struct {
	Enabled                    bool
	CheckIntervalSeconds       int
	FailureThreshold           int
	SuccessThreshold           int
	ReconcileEnabled           bool
	ComponentRestartEnabled    bool
	RestartCooldownSeconds     int
	MaxRestartsPerComponent    int
	RestartWindowSeconds       int
	HostRebootEnabled          bool
	RebootAfterCriticalSeconds int
	MaxRebootsPer24h           int
	RebootGraceSeconds         int
}

func DefaultPolicy() Policy {
	return Policy{
		SchemaVersion: 1, Enabled: true, CheckIntervalSeconds: 15,
		FailureThreshold: 3, SuccessThreshold: 2, ReconcileEnabled: true,
		ComponentRestartEnabled: true, RestartCooldownSeconds: 30,
		MaxRestartsPerComponent: 5, RestartWindowSeconds: 900,
		HostRebootEnabled: false, RebootAfterCriticalSeconds: 900,
		MaxRebootsPer24h: 1, RebootGraceSeconds: 60,
	}
}

func (policy Policy) Validate() error {
	if policy.SchemaVersion != PolicySchemaVersion {
		return errors.New("watchdog policy schema version must be 1")
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
	if policy.UpdatedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, policy.UpdatedAt); err != nil {
			return errors.New("watchdog policy update timestamp is invalid")
		}
	}
	return nil
}

func NormalizeUpdate(input UpdateInput, now time.Time) (Policy, error) {
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
		UpdatedAt: now.UTC().Format(time.RFC3339Nano),
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
