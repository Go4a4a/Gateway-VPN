// Package modemrecovery owns durable, bounded recovery of physical HiLink
// uplinks. Internet censorship, failed VPN nodes and subscription failures are
// deliberately outside this package.
package modemrecovery

import (
	"context"
	"errors"
)

const (
	FailureNone                  = ""
	FailureDeviceAbsent          = "DEVICE_ABSENT"
	FailureCarrierDown           = "CARRIER_DOWN"
	FailureDHCPLeaseMissing      = "DHCP_LEASE_MISSING"
	FailureManagementUnreachable = "HILINK_MANAGEMENT_UNREACHABLE"

	ActionDHCPRenew            = "DHCP_RENEW"
	ActionHiLinkAPIReconnect   = "HILINK_API_RECONNECT"
	ActionMobileSessionRestart = "MOBILE_SESSION_RESTART"
	ActionUSBDriverRebind      = "USB_DRIVER_REBIND"
	ActionUSBDeviceReset       = "USB_DEVICE_RESET"
	ActionUSBPortPowerCycle    = "USB_PORT_POWER_CYCLE"

	RequestedBySystem = "SYSTEM"
	RequestedByUser   = "USER"

	AttemptRunning       = "RUNNING"
	AttemptSucceeded     = "SUCCEEDED"
	AttemptFailed        = "FAILED"
	AttemptDeviceRemoved = "DEVICE_REMOVED"
	AttemptSuppressed    = "SUPPRESSED"
)

var (
	ErrNoPhysicalFailure = errors.New("no physical modem failure is observed")
	ErrActionUnsupported = errors.New("modem recovery action is not supported on this hardware profile")
	ErrDeviceRemoved     = errors.New("modem was removed before recovery action")
	ErrStaleGeneration   = errors.New("modem recovery policy generation is stale")
	ErrBudgetExhausted   = errors.New("modem recovery budget is exhausted")
)

type Policy struct {
	UplinkID                         string `json:"uplink_id"`
	Enabled                          bool   `json:"enabled"`
	DHCPRetryAfterSeconds            int    `json:"dhcp_retry_after_seconds"`
	APIRetryAfterSeconds             int    `json:"api_retry_after_seconds"`
	MobileSessionRestartAfterSeconds int    `json:"mobile_session_restart_after_seconds"`
	USBRebindAfterSeconds            int    `json:"usb_rebind_after_seconds"`
	USBResetAfterSeconds             int    `json:"usb_reset_after_seconds"`
	USBResetCooldownSeconds          int    `json:"usb_reset_cooldown_seconds"`
	MaxUSBResetsPerWindow            int    `json:"max_usb_resets_per_window"`
	USBResetWindowSeconds            int    `json:"usb_reset_window_seconds"`
	AllowHubPortPowerCycle           bool   `json:"allow_hub_port_power_cycle"`
	Generation                       int64  `json:"policy_generation"`
	UpdatedAt                        string `json:"updated_at"`
}

type PolicyUpdate struct {
	Enabled                          bool `json:"enabled"`
	DHCPRetryAfterSeconds            int  `json:"dhcp_retry_after_seconds"`
	APIRetryAfterSeconds             int  `json:"api_retry_after_seconds"`
	MobileSessionRestartAfterSeconds int  `json:"mobile_session_restart_after_seconds"`
	USBRebindAfterSeconds            int  `json:"usb_rebind_after_seconds"`
	USBResetAfterSeconds             int  `json:"usb_reset_after_seconds"`
	USBResetCooldownSeconds          int  `json:"usb_reset_cooldown_seconds"`
	MaxUSBResetsPerWindow            int  `json:"max_usb_resets_per_window"`
	USBResetWindowSeconds            int  `json:"usb_reset_window_seconds"`
	AllowHubPortPowerCycle           bool `json:"allow_hub_port_power_cycle"`
}

type Runtime struct {
	UplinkID              string `json:"uplink_id"`
	PolicyGeneration      int64  `json:"policy_generation"`
	State                 string `json:"state"`
	FailureReason         string `json:"failure_reason,omitempty"`
	FailureStartedAt      string `json:"failure_started_at,omitempty"`
	CooldownUntil         string `json:"cooldown_until,omitempty"`
	BudgetWindowStartedAt string `json:"budget_window_started_at,omitempty"`
	USBResetsInWindow     int    `json:"usb_resets_in_window"`
	ActiveAttemptID       string `json:"active_attempt_id,omitempty"`
	LastOutcomeCode       string `json:"last_outcome_code,omitempty"`
	UpdatedAt             string `json:"updated_at"`
}

type Attempt struct {
	ID               string `json:"id"`
	UplinkID         string `json:"uplink_id"`
	PolicyGeneration int64  `json:"policy_generation"`
	Action           string `json:"action"`
	RequestedBy      string `json:"requested_by"`
	Status           string `json:"status"`
	ReasonCode       string `json:"reason_code,omitempty"`
	FailureReason    string `json:"failure_reason,omitempty"`
	StartedAt        string `json:"started_at"`
	FinishedAt       string `json:"finished_at,omitempty"`
}

type Snapshot struct {
	Policy   Policy    `json:"policy"`
	Runtime  Runtime   `json:"runtime"`
	Attempts []Attempt `json:"attempts"`
}

type Command struct {
	UplinkID         string `json:"uplink_id"`
	PolicyGeneration int64  `json:"policy_generation"`
	Action           string `json:"action"`
}

func ValidateCommand(command Command) error {
	if !validID(command.UplinkID) || command.PolicyGeneration <= 0 || command.PolicyGeneration > int64(^uint32(0)) || !validAction(command.Action) {
		return errors.New("invalid bounded modem recovery command")
	}
	return nil
}

type Result struct {
	UplinkID    string `json:"uplink_id"`
	State       string `json:"state"`
	Action      string `json:"action,omitempty"`
	AttemptID   string `json:"attempt_id,omitempty"`
	Status      string `json:"status,omitempty"`
	ReasonCode  string `json:"reason_code,omitempty"`
	NextCheckAt string `json:"next_check_at,omitempty"`
}

type ActionExecutor interface {
	Execute(context.Context, Command) error
}
