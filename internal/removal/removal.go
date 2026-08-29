// Package removal owns the deliberately small host-uninstall contract.
// Neither the Web API nor the privileged broker accepts a command, unit,
// executable, or filesystem path from an HTTP request.
package removal

import (
	"errors"
	"regexp"
)

type Mode string

const (
	ModePreserveData Mode = "PRESERVE_DATA"
	ModePurgeData    Mode = "PURGE_DATA"

	ExactConfirmation = "УДАЛИТЬ GATEWAY VPN"
)

var (
	ErrInvalidRequest      = errors.New("invalid uninstall request")
	ErrUnavailable         = errors.New("uninstall is unavailable")
	ErrMaintenanceActive   = errors.New("critical maintenance is active")
	ErrOperationInProgress = errors.New("another uninstall operation is in progress")
	operationIDPattern     = regexp.MustCompile(`^uninstall-[a-f0-9]{32}$`)
)

type Request struct {
	OperationID string `json:"operation_id"`
	Mode        Mode   `json:"mode"`
}

func (request Request) Validate() error {
	if !operationIDPattern.MatchString(request.OperationID) {
		return ErrInvalidRequest
	}
	if request.Mode != ModePreserveData && request.Mode != ModePurgeData {
		return ErrInvalidRequest
	}
	return nil
}

type Impact struct {
	Available                  bool     `json:"available"`
	Active                     bool     `json:"active"`
	InstalledStateRecorded     bool     `json:"installed_state_recorded"`
	ApplicationDataPresent     bool     `json:"application_data_present"`
	SessionWillDisconnect      bool     `json:"session_will_disconnect"`
	OSPackagesRetained         bool     `json:"os_packages_retained"`
	PreserveDataDescription    string   `json:"preserve_data_description"`
	PurgeDataDescription       string   `json:"purge_data_description"`
	CommonEffects              []string `json:"common_effects"`
	NotRestoredAutomatically   []string `json:"not_restored_automatically"`
	RequiredConfirmationPhrase string   `json:"required_confirmation_phrase"`
}
