package power

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/platformexec"
)

type powerExecutor struct {
	requests []platformexec.Request
	active   map[string]string
	fail     bool
	failShow bool
}

func (executor *powerExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	if executor.failShow && len(request.Arguments) != 0 && request.Arguments[0] == "show" {
		return platformexec.Result{}, errors.New("private systemd state detail")
	}
	if executor.fail && (len(request.Arguments) == 0 || request.Arguments[0] != "show") {
		return platformexec.Result{}, errors.New("private executor detail")
	}
	if reflect.DeepEqual(request.Arguments, []string{"show", "--property=LoadState", "--value", "gateway-vpn-power-cycle@30.service"}) {
		return platformexec.Result{Stdout: "loaded\n"}, nil
	}
	if len(request.Arguments) == 4 && request.Arguments[0] == "show" {
		return platformexec.Result{Stdout: executor.active[request.Arguments[3]] + "\n"}, nil
	}
	return platformexec.Result{}, nil
}

type powerFileInfo struct {
	name string
	mode os.FileMode
}

func (info powerFileInfo) Name() string       { return info.name }
func (info powerFileInfo) Size() int64        { return 1 }
func (info powerFileInfo) Mode() os.FileMode  { return info.mode }
func (info powerFileInfo) ModTime() time.Time { return time.Time{} }
func (info powerFileInfo) IsDir() bool        { return false }
func (info powerFileInfo) Sys() any           { return nil }

func TestCommandValidationIsTypedAndBounded(t *testing.T) {
	for _, command := range []Command{{Action: ActionReboot}, {Action: ActionShutdown}, {Action: ActionRTCPowerCycle, DelaySeconds: 30}, {Action: ActionRTCPowerCycle, DelaySeconds: 3600}} {
		if err := command.Validate(); err != nil {
			t.Fatalf("valid command %+v rejected: %v", command, err)
		}
	}
	for _, command := range []Command{{Action: "SHELL"}, {Action: ActionReboot, DelaySeconds: 30}, {Action: ActionRTCPowerCycle, DelaySeconds: 29}, {Action: ActionRTCPowerCycle, DelaySeconds: 3601}} {
		if err := command.Validate(); !errors.Is(err, ErrInvalidCommand) {
			t.Fatalf("invalid command %+v = %v", command, err)
		}
	}
}

func TestLinuxBackendRequiresVerifiedRTCAndUsesFixedSystemdActions(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	executor := &powerExecutor{active: map[string]string{}}
	backend := DefaultLinuxBackend(database, executor)
	backend.Stat = func(path string) (os.FileInfo, error) {
		if path == DefaultRTCVerificationPath || path == DefaultInstallMarkerPath || path == DefaultInstallRunMarker || path == DefaultUninstallMarkerPath {
			return nil, os.ErrNotExist
		}
		mode := os.FileMode(0o644)
		if path == DefaultSystemctlPath || path == DefaultRTCWakePath {
			mode = 0o755
		}
		return powerFileInfo{name: filepath.Base(path), mode: mode}, nil
	}
	backend.ReadFile = func(string) ([]byte, error) { return []byte(rtcVerificationContent), nil }
	capabilities, err := backend.Capabilities(ctx)
	if err != nil || !capabilities.Reboot.Available || !capabilities.RTCPowerCycle.Detected || capabilities.RTCPowerCycle.Available || capabilities.RTCPowerCycle.State != "DETECTED_NOT_VERIFIED" {
		t.Fatalf("unverified capabilities = %+v, %v", capabilities, err)
	}
	if err := backend.Execute(ctx, Command{Action: ActionRTCPowerCycle, DelaySeconds: 30}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unverified RTC execute = %v", err)
	}
	backend.Stat = func(path string) (os.FileInfo, error) {
		if path == DefaultInstallMarkerPath || path == DefaultInstallRunMarker || path == DefaultUninstallMarkerPath {
			return nil, os.ErrNotExist
		}
		mode := os.FileMode(0o644)
		if path == DefaultSystemctlPath || path == DefaultRTCWakePath {
			mode = 0o755
		}
		if path == DefaultRTCVerificationPath {
			mode = 0o600
		}
		return powerFileInfo{name: filepath.Base(path), mode: mode}, nil
	}
	if err := backend.Execute(ctx, Command{Action: ActionRTCPowerCycle, DelaySeconds: 30}); err != nil {
		t.Fatal(err)
	}
	last := executor.requests[len(executor.requests)-1]
	if last.Executable != DefaultSystemctlPath || !reflect.DeepEqual(last.Arguments, []string{"--no-block", "start", "gateway-vpn-power-cycle@30.service"}) {
		t.Fatalf("RTC dispatch = %+v", last)
	}
	if err := backend.Execute(ctx, Command{Action: ActionReboot}); !errors.Is(err, ErrOperationInProgress) {
		t.Fatalf("second action = %v", err)
	}
}

func TestLinuxBackendBlocksNetworkApplyAndTransitioningMaintenanceUnit(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	executor := &powerExecutor{active: map[string]string{}}
	backend := DefaultLinuxBackend(database, executor)
	backend.Stat = func(path string) (os.FileInfo, error) {
		if strings.Contains(path, "install") || path == DefaultRTCVerificationPath {
			return nil, os.ErrNotExist
		}
		return powerFileInfo{name: filepath.Base(path), mode: 0o755}, nil
	}
	backend.ReadFile = os.ReadFile
	_, err = database.ExecContext(ctx, `
INSERT INTO network_apply_transactions(
 id,state,confirm_token_sha256,interface_name,old_lan_cidr,new_lan_cidr,old_url,new_url,new_destination_ip,
 rollback_deadline,transaction_dir,created_at,updated_at
) VALUES('apply-power','APPLIED','digest','lan0','192.168.1.1/24','192.168.2.1/24','old','new','192.168.2.1','later','dir','now','now')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Execute(ctx, Command{Action: ActionReboot}); !errors.Is(err, ErrMaintenanceActive) {
		t.Fatalf("network apply maintenance = %v", err)
	}
	if status, err := backend.MaintenanceStatus(ctx); err != nil || !status.Active || status.ReasonCode != "NETWORK_APPLY_ACTIVE" {
		t.Fatalf("network apply status = %+v,%v", status, err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE network_apply_transactions SET state='CONFIRMED'"); err != nil {
		t.Fatal(err)
	}
	// Completed RemainAfterExit recovery units remain active and must not leave
	// manual power control permanently blocked.
	executor.active["gateway-vpn-update-recovery.service"] = "active"
	if err := backend.Execute(ctx, Command{Action: ActionShutdown}); err != nil {
		t.Fatalf("completed recovery unit blocked power: %v", err)
	}
	if status, err := backend.MaintenanceStatus(ctx); err != nil || !status.Active || status.ReasonCode != "POWER_ACTION_PENDING" {
		t.Fatalf("dispatched power status = %+v,%v", status, err)
	}

	// Use a fresh backend because a successful dispatch intentionally prevents
	// a second power operation in the same broker process.
	executor.active["gateway-vpn-update-recovery.service"] = ""
	executor.active["gateway-vpn-update.service"] = "activating"
	backend = DefaultLinuxBackend(database, executor)
	backend.Stat = func(path string) (os.FileInfo, error) {
		if strings.Contains(path, "install") || path == DefaultRTCVerificationPath {
			return nil, os.ErrNotExist
		}
		return powerFileInfo{name: filepath.Base(path), mode: 0o755}, nil
	}
	backend.ReadFile = os.ReadFile
	if err := backend.Execute(ctx, Command{Action: ActionShutdown}); !errors.Is(err, ErrMaintenanceActive) {
		t.Fatalf("update maintenance = %v", err)
	}
}

func TestLinuxBackendDoesNotExposeExecutorFailureDetails(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	executor := &powerExecutor{active: map[string]string{}}
	backend := DefaultLinuxBackend(database, executor)
	backend.Stat = func(path string) (os.FileInfo, error) {
		if path == DefaultInstallMarkerPath || path == DefaultInstallRunMarker || path == DefaultUninstallMarkerPath || path == DefaultRTCVerificationPath {
			return nil, os.ErrNotExist
		}
		return powerFileInfo{name: filepath.Base(path), mode: 0o755}, nil
	}
	executor.fail = true
	err = backend.Execute(ctx, Command{Action: ActionReboot})
	if err == nil || strings.Contains(err.Error(), "private executor detail") || err.Error() != "fixed systemd power action failed" {
		t.Fatalf("redacted executor error = %v", err)
	}
}

func TestLinuxBackendFailsClosedWhenMaintenanceStateIsUnknown(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	executor := &powerExecutor{active: map[string]string{}, failShow: true}
	backend := DefaultLinuxBackend(database, executor)
	backend.Stat = func(path string) (os.FileInfo, error) {
		if path == DefaultInstallMarkerPath || path == DefaultInstallRunMarker || path == DefaultUninstallMarkerPath || path == DefaultRTCVerificationPath || path == DefaultRTCAlarmPath {
			return nil, os.ErrNotExist
		}
		return powerFileInfo{name: filepath.Base(path), mode: 0o755}, nil
	}
	err = backend.Execute(ctx, Command{Action: ActionShutdown})
	if !errors.Is(err, ErrMaintenanceActive) || !strings.Contains(err.Error(), "MAINTENANCE_STATE_UNKNOWN") {
		t.Fatalf("unknown maintenance state = %v", err)
	}
	for _, request := range executor.requests {
		if reflect.DeepEqual(request.Arguments, []string{"--no-block", "poweroff"}) {
			t.Fatal("power action dispatched while maintenance state was unknown")
		}
	}
}

func TestPowerRepositorySerializesAndAuditsOperations(t *testing.T) {
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository := Repository{Database: database}
	first, err := repository.Start(ctx, "admin", Command{Action: ActionReboot})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Start(ctx, "admin", Command{Action: ActionShutdown}); !errors.Is(err, ErrOperationInProgress) {
		t.Fatalf("parallel power start = %v", err)
	}
	finished, err := repository.Finish(ctx, first.ID, true, "")
	if err != nil || finished.Status != "SUCCEEDED" || finished.SummaryCode != "POWER_ACTION_DISPATCHED" {
		t.Fatalf("finished operation = %+v, %v", finished, err)
	}
	var requested, dispatched int
	_ = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='SYSTEM_POWER_REQUESTED'").Scan(&requested)
	_ = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='SYSTEM_POWER_DISPATCHED'").Scan(&dispatched)
	if requested != 1 || dispatched != 1 {
		t.Fatalf("power audit counts = %d/%d", requested, dispatched)
	}
}
