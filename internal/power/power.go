// Package power owns the deliberately small and audited host power contract.
// It never accepts an executable, systemd unit, filesystem path, or shell text
// from the management API.
package power

import (
	"errors"
	"fmt"
)

type Action string

const (
	ActionReboot        Action = "REBOOT"
	ActionShutdown      Action = "SHUTDOWN"
	ActionRTCPowerCycle Action = "RTC_POWER_CYCLE"

	MinimumRTCDelaySeconds = 30
	MaximumRTCDelaySeconds = 3600
)

var (
	ErrInvalidCommand      = errors.New("invalid power command")
	ErrUnavailable         = errors.New("power action is unavailable")
	ErrMaintenanceActive   = errors.New("critical maintenance is active")
	ErrOperationInProgress = errors.New("another power operation is in progress")
)

type Command struct {
	Action       Action `json:"action"`
	DelaySeconds int    `json:"delay_seconds"`
}

func (command Command) Validate() error {
	switch command.Action {
	case ActionReboot, ActionShutdown:
		if command.DelaySeconds != 0 {
			return fmt.Errorf("%w: delay is only valid for RTC power-cycle", ErrInvalidCommand)
		}
	case ActionRTCPowerCycle:
		if command.DelaySeconds < MinimumRTCDelaySeconds || command.DelaySeconds > MaximumRTCDelaySeconds {
			return fmt.Errorf("%w: RTC delay must be between %d and %d seconds", ErrInvalidCommand, MinimumRTCDelaySeconds, MaximumRTCDelaySeconds)
		}
	default:
		return fmt.Errorf("%w: unknown action", ErrInvalidCommand)
	}
	return nil
}

type Capability struct {
	Available  bool   `json:"available"`
	Detected   bool   `json:"detected"`
	Verified   bool   `json:"verified"`
	State      string `json:"state"`
	ReasonCode string `json:"reason_code,omitempty"`
}

type Capabilities struct {
	Reboot                 Capability `json:"reboot"`
	Shutdown               Capability `json:"shutdown"`
	RTCPowerCycle          Capability `json:"rtc_power_cycle"`
	MinimumRTCDelaySeconds int        `json:"minimum_rtc_delay_seconds"`
	MaximumRTCDelaySeconds int        `json:"maximum_rtc_delay_seconds"`
	DefaultRTCDelaySeconds int        `json:"default_rtc_delay_seconds"`
}

// MaintenanceStatus is a fixed, path-free projection used to suppress
// unattended work while a privileged lifecycle mutation is active. ReasonCode
// is an allowlisted machine code; no unit output or filesystem path crosses
// the root boundary.
type MaintenanceStatus struct {
	Active     bool   `json:"active"`
	ReasonCode string `json:"reason_code,omitempty"`
}

func ExpectedConfirmation(action Action) string {
	switch action {
	case ActionReboot:
		return "ПЕРЕЗАГРУЗИТЬ"
	case ActionShutdown:
		return "ВЫКЛЮЧИТЬ"
	case ActionRTCPowerCycle:
		return "ВЫКЛЮЧИТЬ И ВКЛЮЧИТЬ"
	default:
		return ""
	}
}
