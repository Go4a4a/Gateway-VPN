package removal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gateway-vpn/internal/platformexec"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/watchdog"
)

const (
	DefaultRoot                 = "/var/lib/gateway-vpn-uninstall"
	DefaultSystemctlPath        = "/usr/bin/systemctl"
	DefaultUnit                 = "gateway-vpn-uninstall.service"
	DefaultHelperPath           = "/usr/libexec/gateway-vpn-uninstall-job"
	DefaultInstallMarkerPath    = "/var/lib/gateway-vpn-privileged/install-transactions/active"
	DefaultHostUpgradeMarker    = "/var/lib/gateway-vpn-host-upgrade/active"
	DefaultInstallRunMarkerPath = "/run/gateway-vpn-install-authorized"
	DefaultUpdateStagingMarker  = "/var/lib/gateway-vpn/update-staging/pending-update.json"
	DefaultUpdateJournalRoot    = "/var/lib/gateway-vpn-privileged/update-transactions"
	DefaultUpdateRollbackMarker = "/var/lib/gateway-vpn-privileged/update-rollback/pending.json"
	DefaultRestoreMarker        = "/var/lib/gateway-vpn/recovery/pending-restore.json"
)

type LinuxBackend struct {
	Database          *sql.DB
	Executor          platformexec.Executor
	Root              string
	Systemctl         string
	Unit              string
	Helper            string
	InstallMarker     string
	HostUpgrade       string
	InstallRunMarker  string
	UpdateStaging     string
	UpdateJournalRoot string
	UpdateRollback    string
	RestoreMarker     string

	mutex      sync.Mutex
	dispatched bool
}

func DefaultLinuxBackend(database *sql.DB, executor platformexec.Executor) *LinuxBackend {
	return &LinuxBackend{
		Database: database, Executor: executor, Root: DefaultRoot,
		Systemctl: DefaultSystemctlPath, Unit: DefaultUnit,
		Helper:        DefaultHelperPath,
		InstallMarker: DefaultInstallMarkerPath, HostUpgrade: DefaultHostUpgradeMarker,
		InstallRunMarker: DefaultInstallRunMarkerPath,
		UpdateStaging:    DefaultUpdateStagingMarker, UpdateJournalRoot: DefaultUpdateJournalRoot,
		UpdateRollback: DefaultUpdateRollbackMarker, RestoreMarker: DefaultRestoreMarker,
	}
}

func (backend *LinuxBackend) Impact(ctx context.Context) (Impact, error) {
	if err := backend.validate(); err != nil {
		return Impact{}, err
	}
	helperReady := false
	if helper, err := os.Lstat(backend.Helper); err == nil && helper.Mode().IsRegular() && helper.Mode().Perm() == 0o700 && isRootOwned(helper) {
		helperReady = true
	}
	unitReady := false
	if result, err := backend.Executor.Run(ctx, platformexec.Request{Executable: backend.Systemctl, Arguments: []string{"show", "--property=LoadState", "--value", backend.Unit}, MaxOutputBytes: 16 << 10}); err == nil && strings.TrimSpace(result.Stdout) == "loaded" {
		unitReady = true
	}
	return Impact{
		Available:                  helperReady && unitReady,
		Active:                     pathExists(filepath.Join(backend.Root, "active")),
		InstalledStateRecorded:     completedInstallMarkerExists(),
		ApplicationDataPresent:     pathExists("/var/lib/gateway-vpn"),
		SessionWillDisconnect:      true,
		OSPackagesRetained:         true,
		PreserveDataDescription:    "Программа, systemd units и конфигурация удаляются; /var/lib/gateway-vpn сохраняется для повторной установки.",
		PurgeDataDescription:       "Дополнительно удаляются база, секреты, ключи, резервные копии и экспорты журналов; перед этим сохраните нужный экспорт.",
		CommonEffects:              []string{"Пользовательский путь сначала блокируется", "Сервисы Gateway VPN останавливаются", "Записанные LAN, forwarding, IPv6, SSH/socket, boot и GRUB изменения восстанавливаются", "Текущие WebUI, SSH и SFTP соединения могут оборваться"},
		NotRestoredAutomatically:   []string{"Пакеты Ubuntu", "Обновления безопасности ОС", "Изменения пользователя и других программ", "Не принадлежащие Gateway VPN firewall и network settings"},
		RequiredConfirmationPhrase: ExactConfirmation,
	}, nil
}

func (backend *LinuxBackend) Dispatch(ctx context.Context, request Request) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := backend.validate(); err != nil {
		return err
	}
	backend.mutex.Lock()
	defer backend.mutex.Unlock()
	if backend.dispatched || pathExists(filepath.Join(backend.Root, "active")) {
		return ErrOperationInProgress
	}
	if active, _ := backend.maintenance(ctx); active {
		return ErrMaintenanceActive
	}
	operation, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	loaded, err := backend.Executor.Run(operation, platformexec.Request{
		Executable: backend.Systemctl, Arguments: []string{"show", "--property=LoadState", "--value", backend.Unit}, MaxOutputBytes: 16 << 10,
	})
	if err != nil || strings.TrimSpace(loaded.Stdout) != "loaded" {
		return ErrUnavailable
	}
	helper, err := os.Lstat(backend.Helper)
	if err != nil || !helper.Mode().IsRegular() || helper.Mode().Perm() != 0o700 || !isRootOwned(helper) {
		return ErrUnavailable
	}
	if err := writeMarker(backend.Root, request); err != nil {
		return errors.New("create durable uninstall request failed")
	}
	if _, err := backend.Executor.Run(operation, platformexec.Request{
		Executable: backend.Systemctl, Arguments: []string{"--no-block", "start", backend.Unit}, MaxOutputBytes: 32 << 10,
	}); err != nil {
		_ = os.Remove(filepath.Join(backend.Root, "active"))
		_ = syncDirectory(backend.Root)
		return errors.New("start fixed uninstall guardian failed")
	}
	backend.dispatched = true
	return nil
}

func (backend *LinuxBackend) maintenance(ctx context.Context) (bool, string) {
	if pathExists(backend.InstallMarker) || pathExists(backend.HostUpgrade) || pathExists(backend.InstallRunMarker) ||
		pathExists(backend.UpdateStaging) || pathExists(backend.UpdateRollback) ||
		pathExists(backend.RestoreMarker) {
		return true, "LIFECYCLE_TRANSACTION_ACTIVE"
	}
	journal, exists, err := (updatepkg.JournalStore{Root: backend.UpdateJournalRoot}).LoadActive()
	if err != nil || exists && journal.InProgress() {
		return true, "UPDATE_TRANSACTION_ACTIVE_OR_UNKNOWN"
	}
	var count int
	if err := backend.Database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM network_apply_transactions
WHERE state IN ('PREPARING','ARMED','APPLIED','CONFIRMING')`).Scan(&count); err != nil || count != 0 {
		return true, "NETWORK_APPLY_ACTIVE_OR_UNKNOWN"
	}
	for _, item := range watchdog.MaintenanceUnits() {
		result, err := backend.Executor.Run(ctx, platformexec.Request{
			Executable:     backend.Systemctl,
			Arguments:      []string{"show", "--property=ActiveState", "--value", item.Unit},
			MaxOutputBytes: 16 << 10,
		})
		if err != nil {
			return true, "MAINTENANCE_STATE_UNKNOWN"
		}
		switch strings.TrimSpace(result.Stdout) {
		case "activating", "deactivating", "reloading":
			return true, item.Code
		}
	}
	return false, ""
}

func (backend *LinuxBackend) validate() error {
	if backend == nil || backend.Database == nil || backend.Executor == nil || backend.Root != DefaultRoot ||
		backend.Systemctl != DefaultSystemctlPath || backend.Unit != DefaultUnit ||
		backend.Helper != DefaultHelperPath ||
		backend.InstallMarker != DefaultInstallMarkerPath || backend.HostUpgrade != DefaultHostUpgradeMarker ||
		backend.InstallRunMarker != DefaultInstallRunMarkerPath || backend.UpdateStaging != DefaultUpdateStagingMarker ||
		backend.UpdateJournalRoot != DefaultUpdateJournalRoot || backend.UpdateRollback != DefaultUpdateRollbackMarker ||
		backend.RestoreMarker != DefaultRestoreMarker {
		return errors.New("complete fixed Linux uninstall backend configuration is required")
	}
	return nil
}

func writeMarker(root string, request Request) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !hasSecureMode(info, 0o700) || !isRootOwned(info) {
		return errors.New("uninstall root is unsafe")
	}
	temporary := filepath.Join(root, ".active.tmp")
	active := filepath.Join(root, "active")
	if _, err := os.Lstat(active); err == nil {
		return ErrOperationInProgress
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if temporaryInfo, err := os.Lstat(temporary); err == nil {
		if !temporaryInfo.Mode().IsRegular() || !hasSecureMode(temporaryInfo, 0o600) || !isRootOwned(temporaryInfo) {
			return errors.New("stale uninstall marker temporary is unsafe")
		}
		if err := os.Remove(temporary); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	content := fmt.Sprintf("format=1\noperation_id=%s\nmode=%s\n", request.OperationID, request.Mode)
	_, writeErr := file.WriteString(content)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(temporary)
		return writeErr
	}
	// Link is the no-replace publication primitive available on every target
	// filesystem supported by the installer. It cannot overwrite an existing
	// durable request, unlike os.Rename on Unix.
	if err := os.Link(temporary, active); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	return syncDirectory(root)
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func completedInstallMarkerExists() bool {
	matches, err := filepath.Glob("/var/lib/gateway-vpn-privileged/install-transactions/completed-*")
	return err == nil && len(matches) != 0
}
