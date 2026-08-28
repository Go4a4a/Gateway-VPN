package modemrecovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/store"
)

// LinuxBackend is the privileged half of recovery. It accepts no interface,
// sysfs path, executable or USB identifier from the control plane. The
// current interface and active attempt are re-read from SQLite immediately
// before one fixed command is executed.
type LinuxBackend struct {
	Database   *sql.DB
	Executor   platformexec.Executor
	Networkctl string
}

func (backend LinuxBackend) Execute(ctx context.Context, command Command) error {
	if backend.Database == nil || backend.Executor == nil || ValidateCommand(command) != nil {
		return errors.New("complete bounded modem recovery backend is required")
	}
	var uplinkType, addressMode, interfaceName, carrierState string
	var enabled int
	var policyGeneration int64
	var activeAttemptID, attemptAction, attemptStatus string
	err := backend.Database.QueryRowContext(ctx, `
SELECT u.type, u.enabled, u.address_mode, COALESCE(ni.current_ifname, ''),
       COALESCE(ni.carrier_state, 'UNKNOWN'), p.policy_generation,
       COALESCE(r.active_attempt_id, ''), COALESCE(a.action, ''),
       COALESCE(a.status, '')
FROM uplinks AS u
JOIN hilink_modems AS h ON h.uplink_id=u.id
JOIN modem_recovery_policy AS p ON p.uplink_id=u.id
JOIN modem_recovery_runtime AS r ON r.uplink_id=u.id
LEFT JOIN network_interfaces AS ni ON ni.id=u.network_interface_id
LEFT JOIN modem_recovery_attempts AS a ON a.id=r.active_attempt_id
WHERE u.id=?`, command.UplinkID).Scan(
		&uplinkType, &enabled, &addressMode, &interfaceName, &carrierState,
		&policyGeneration, &activeAttemptID, &attemptAction, &attemptStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read authoritative modem recovery tuple: %w", err)
	}
	if uplinkType != "HILINK" || enabled != 1 {
		return ErrDeviceRemoved
	}
	if policyGeneration != command.PolicyGeneration || activeAttemptID == "" || attemptAction != command.Action || attemptStatus != AttemptRunning {
		return ErrStaleGeneration
	}
	if interfaceName == "" || !validInterfaceName(interfaceName) || carrierState == "ABSENT" {
		return ErrDeviceRemoved
	}
	switch command.Action {
	case ActionDHCPRenew:
		if addressMode != "DHCP" {
			return ErrActionUnsupported
		}
		networkctl := backend.Networkctl
		if networkctl == "" {
			networkctl = "/usr/bin/networkctl"
		}
		if networkctl != "/usr/bin/networkctl" {
			return errors.New("fixed /usr/bin/networkctl is required")
		}
		_, err := backend.Executor.Run(ctx, platformexec.Request{
			Executable:     networkctl,
			Arguments:      []string{"renew", interfaceName},
			MaxOutputBytes: 64 << 10,
		})
		if err != nil {
			return errors.New("networkd DHCP renew failed")
		}
		return nil
	default:
		// Firmware-specific mobile reconnect and USB identity-safe rebind/reset
		// remain disabled until their exact Huawei E3372h hardware gates pass.
		return ErrActionUnsupported
	}
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}
