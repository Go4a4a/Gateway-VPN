package power

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/watchdog"
)

const (
	DefaultSystemctlPath       = "/usr/bin/systemctl"
	DefaultRTCWakePath         = "/usr/sbin/rtcwake"
	DefaultRTCAlarmPath        = "/sys/class/rtc/rtc0/wakealarm"
	DefaultRTCVerificationPath = "/var/lib/gateway-vpn-privileged/rtc-wake-from-s5.verified"
	DefaultInstallMarkerPath   = "/var/lib/gateway-vpn-privileged/install-transactions/active"
	DefaultInstallRunMarker    = "/run/gateway-vpn-install-authorized"
	DefaultUninstallMarkerPath = "/var/lib/gateway-vpn-uninstall/active"
	RTCPowerCycleUnitPrefix    = "gateway-vpn-power-cycle@"
	rtcVerificationContent     = "RTC_WAKE_FROM_S5_VERIFIED_V1\n"
)

type LinuxBackend struct {
	Database         *sql.DB
	Executor         platformexec.Executor
	Systemctl        string
	RTCWake          string
	RTCAlarm         string
	RTCVerification  string
	InstallMarker    string
	InstallRunMarker string
	UninstallMarker  string
	Stat             func(string) (os.FileInfo, error)
	ReadFile         func(string) ([]byte, error)

	mutex      sync.Mutex
	dispatched bool
}

func DefaultLinuxBackend(database *sql.DB, executor platformexec.Executor) *LinuxBackend {
	return &LinuxBackend{
		Database: database, Executor: executor, Systemctl: DefaultSystemctlPath,
		RTCWake: DefaultRTCWakePath, RTCAlarm: DefaultRTCAlarmPath,
		RTCVerification: DefaultRTCVerificationPath,
		InstallMarker:   DefaultInstallMarkerPath, InstallRunMarker: DefaultInstallRunMarker,
		UninstallMarker: DefaultUninstallMarkerPath,
	}
}

func (backend *LinuxBackend) Capabilities(ctx context.Context) (Capabilities, error) {
	if err := backend.validate(); err != nil {
		return Capabilities{}, err
	}
	systemctl := backend.safeExecutable(backend.Systemctl)
	baseState, baseReason := "AVAILABLE", ""
	if !systemctl {
		baseState, baseReason = "UNAVAILABLE", "SYSTEMCTL_UNAVAILABLE"
	}
	base := Capability{Available: systemctl, Detected: systemctl, Verified: systemctl, State: baseState, ReasonCode: baseReason}
	rtcDetected := backend.safeExecutable(backend.RTCWake) && backend.pathExists(backend.RTCAlarm) && backend.rtcUnitLoaded(ctx)
	rtcVerified := rtcDetected && backend.rtcVerified()
	rtcState, rtcReason := "VERIFIED", ""
	if !rtcDetected {
		rtcState, rtcReason = "UNAVAILABLE", "RTC_OR_HELPER_UNAVAILABLE"
	} else if !rtcVerified {
		rtcState, rtcReason = "DETECTED_NOT_VERIFIED", "RTC_WAKE_FROM_S5_NOT_VERIFIED"
	}
	return Capabilities{
		Reboot: base, Shutdown: base,
		RTCPowerCycle:          Capability{Available: rtcVerified, Detected: rtcDetected, Verified: rtcVerified, State: rtcState, ReasonCode: rtcReason},
		MinimumRTCDelaySeconds: MinimumRTCDelaySeconds, MaximumRTCDelaySeconds: MaximumRTCDelaySeconds, DefaultRTCDelaySeconds: MinimumRTCDelaySeconds,
	}, nil
}

func (backend *LinuxBackend) Execute(ctx context.Context, command Command) error {
	if err := command.Validate(); err != nil {
		return err
	}
	if err := backend.validate(); err != nil {
		return err
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if backend.dispatched {
		return ErrOperationInProgress
	}
	capabilities, err := backend.Capabilities(ctx)
	if err != nil {
		return err
	}
	available := capabilities.Reboot.Available
	if command.Action == ActionShutdown {
		available = capabilities.Shutdown.Available
	} else if command.Action == ActionRTCPowerCycle {
		available = capabilities.RTCPowerCycle.Available
	}
	if !available {
		return ErrUnavailable
	}
	if active, code := backend.maintenance(ctx); active {
		return fmt.Errorf("%w: %s", ErrMaintenanceActive, code)
	}
	arguments := []string{"--no-block", "reboot"}
	switch command.Action {
	case ActionShutdown:
		arguments = []string{"--no-block", "poweroff"}
	case ActionRTCPowerCycle:
		arguments = []string{"--no-block", "start", RTCPowerCycleUnitPrefix + strconv.Itoa(command.DelaySeconds) + ".service"}
	}
	operation, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := backend.Executor.Run(operation, platformexec.Request{Executable: backend.Systemctl, Arguments: arguments, MaxOutputBytes: 32 << 10}); err != nil {
		return errors.New("fixed systemd power action failed")
	}
	backend.dispatched = true
	return nil
}

func (backend *LinuxBackend) maintenance(ctx context.Context) (bool, string) {
	if backend.pathExists(backend.InstallMarker) || backend.pathExists(backend.InstallRunMarker) || backend.pathExists(backend.UninstallMarker) {
		return true, "INSTALL_ACTIVE"
	}
	var count int
	if err := backend.Database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM network_apply_transactions
WHERE state IN ('PREPARING','ARMED','APPLIED','CONFIRMING')`).Scan(&count); err != nil {
		return true, "NETWORK_APPLY_STATE_UNKNOWN"
	}
	if count != 0 {
		return true, "NETWORK_APPLY_ACTIVE"
	}
	for _, item := range watchdog.MaintenanceUnits() {
		result, err := backend.Executor.Run(ctx, platformexec.Request{
			Executable:     backend.Systemctl,
			Arguments:      []string{"show", "--property=ActiveState", "--value", item.Unit},
			MaxOutputBytes: 16 << 10,
		})
		if err != nil {
			// A manual power action must not race an update/restore merely
			// because systemd state could not be read. The public API maps this
			// to one generic maintenance conflict without exposing root details.
			return true, "MAINTENANCE_STATE_UNKNOWN"
		}
		// Type=oneshot recovery units with RemainAfterExit=yes deliberately stay
		// "active" after successful boot recovery.  Only transitional states mean
		// that a destructive lifecycle operation is still executing.
		switch strings.TrimSpace(result.Stdout) {
		case "activating", "deactivating", "reloading":
			return true, item.Code
		}
	}
	return false, ""
}

func (backend *LinuxBackend) rtcUnitLoaded(ctx context.Context) bool {
	result, err := backend.Executor.Run(ctx, platformexec.Request{
		Executable:     backend.Systemctl,
		Arguments:      []string{"show", "--property=LoadState", "--value", RTCPowerCycleUnitPrefix + "30.service"},
		MaxOutputBytes: 16 << 10,
	})
	return err == nil && strings.TrimSpace(result.Stdout) == "loaded"
}

func (backend *LinuxBackend) rtcVerified() bool {
	info, err := backend.stat(backend.RTCVerification)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	content, err := backend.readFile(backend.RTCVerification)
	return err == nil && string(content) == rtcVerificationContent
}

func (backend *LinuxBackend) safeExecutable(path string) bool {
	info, err := backend.stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func (backend *LinuxBackend) pathExists(path string) bool {
	_, err := backend.stat(path)
	return err == nil
}

func (backend *LinuxBackend) stat(path string) (os.FileInfo, error) {
	if backend.Stat != nil {
		return backend.Stat(path)
	}
	return os.Stat(path)
}

func (backend *LinuxBackend) readFile(path string) ([]byte, error) {
	if backend.ReadFile != nil {
		return backend.ReadFile(path)
	}
	return os.ReadFile(path)
}

func (backend *LinuxBackend) validate() error {
	if backend == nil || backend.Database == nil || backend.Executor == nil ||
		backend.Systemctl != DefaultSystemctlPath || backend.RTCWake != DefaultRTCWakePath ||
		backend.RTCAlarm != DefaultRTCAlarmPath || backend.RTCVerification != DefaultRTCVerificationPath ||
		backend.InstallMarker != DefaultInstallMarkerPath || backend.InstallRunMarker != DefaultInstallRunMarker ||
		backend.UninstallMarker != DefaultUninstallMarkerPath {
		return errors.New("complete fixed Linux power backend configuration is required")
	}
	return nil
}
