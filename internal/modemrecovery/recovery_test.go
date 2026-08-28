package modemrecovery

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
)

type fakeActionExecutor struct {
	commands []Command
	err      error
}

func (executor *fakeActionExecutor) Execute(_ context.Context, command Command) error {
	executor.commands = append(executor.commands, command)
	return executor.err
}

type fakePlatformExecutor struct {
	requests []platformexec.Request
	err      error
}

func (executor *fakePlatformExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	return platformexec.Result{}, executor.err
}

func recoveryFixture(t *testing.T) (*Repository, *modem.Repository, *time.Time) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{
		ID: "modem-a", Name: "Primary LTE", IdentityKind: "usb_serial_hash",
		IdentityHash: strings.Repeat("a", 64), MaskedSerial: "****1234",
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	repository := NewRepository(database)
	repository.Now = func() time.Time { return now }
	return repository, modems, &now
}

func TestControllerUsesOnlyPhysicalFailuresAndHonorsHysteresis(t *testing.T) {
	repository, modems, now := recoveryFixture(t)
	ctx := context.Background()
	if err := modems.ObservePhysicalLink(ctx, "modem-a", "enx123", true); err != nil {
		t.Fatal(err)
	}
	executor := &fakeActionExecutor{}
	controller := &Controller{Repository: repository, Executor: executor}

	if _, err := controller.Request(ctx, "modem-a", "GLOBAL_TARGETS_FAILED"); err == nil {
		t.Fatal("non-physical Internet failure was accepted by modem recovery")
	}
	if failures := controller.Observe(ctx, ObservationBatch{Failures: map[string]string{"modem-a": FailureDHCPLeaseMissing}}); len(failures) != 0 {
		t.Fatalf("first physical observation errors = %v", failures)
	}
	if len(executor.commands) != 0 {
		t.Fatalf("DHCP recovery ignored hysteresis: %+v", executor.commands)
	}
	snapshot, err := repository.Snapshot(ctx, "modem-a", 10)
	if err != nil || snapshot.Runtime.FailureReason != FailureDHCPLeaseMissing || snapshot.Runtime.FailureStartedAt == "" {
		t.Fatalf("failure runtime = %+v, %v", snapshot.Runtime, err)
	}

	*now = now.Add(30 * time.Second)
	if failures := controller.Observe(ctx, ObservationBatch{Failures: map[string]string{"modem-a": FailureDHCPLeaseMissing}}); len(failures) != 0 {
		t.Fatalf("due physical recovery errors = %v", failures)
	}
	if len(executor.commands) != 1 || executor.commands[0].Action != ActionDHCPRenew || executor.commands[0].UplinkID != "modem-a" {
		t.Fatalf("bounded command = %+v", executor.commands)
	}
	snapshot, err = repository.Snapshot(ctx, "modem-a", 10)
	if err != nil || len(snapshot.Attempts) != 1 || snapshot.Attempts[0].Status != AttemptSucceeded || snapshot.Runtime.ActiveAttemptID != "" {
		t.Fatalf("completed recovery snapshot = %+v, %v", snapshot, err)
	}
}

func TestManualRequestDoesNotResetHealthyOrAbsentModem(t *testing.T) {
	repository, _, _ := recoveryFixture(t)
	controller := &Controller{Repository: repository, Executor: &fakeActionExecutor{}}
	if result, err := controller.Request(context.Background(), "modem-a", FailureNone); !errors.Is(err, ErrNoPhysicalFailure) || result.State != "NO_PHYSICAL_FAILURE" {
		t.Fatalf("healthy manual recovery = %+v, %v", result, err)
	}
	result, err := controller.Request(context.Background(), "modem-a", FailureDeviceAbsent)
	if err != nil || result.State != "WAITING_FOR_DEVICE" || result.ReasonCode != "DEVICE_ABSENT_NO_SAFE_ACTION" {
		t.Fatalf("absent manual recovery = %+v, %v", result, err)
	}
	snapshot, _ := repository.Snapshot(context.Background(), "modem-a", 10)
	if len(snapshot.Attempts) != 0 {
		t.Fatalf("device absence manufactured an unsafe attempt: %+v", snapshot.Attempts)
	}
}

func TestInterruptedAttemptAndUSBResetBudgetSurviveRestart(t *testing.T) {
	repository, _, now := recoveryFixture(t)
	ctx := context.Background()
	if _, err := repository.PrepareFailure(ctx, "modem-a", FailureCarrierDown); err != nil {
		t.Fatal(err)
	}
	attempt, err := repository.BeginAttempt(ctx, "modem-a", ActionUSBDeviceReset, RequestedBySystem, FailureCarrierDown)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := repository.RecoverInterrupted(ctx)
	if err != nil || closed != 1 {
		t.Fatalf("RecoverInterrupted() = %d, %v", closed, err)
	}
	snapshot, _ := repository.Snapshot(ctx, "modem-a", 10)
	if len(snapshot.Attempts) != 1 || snapshot.Attempts[0].ID != attempt.ID || snapshot.Attempts[0].Status != AttemptFailed || snapshot.Attempts[0].ReasonCode != "PROCESS_RESTARTED" || snapshot.Runtime.USBResetsInWindow != 1 {
		t.Fatalf("interrupted durable state = %+v", snapshot)
	}

	*now = now.Add(time.Minute)
	if _, err := repository.PrepareFailure(ctx, "modem-a", FailureCarrierDown); err != nil {
		t.Fatal(err)
	}
	second, err := repository.BeginAttempt(ctx, "modem-a", ActionUSBDeviceReset, RequestedBySystem, FailureCarrierDown)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.FinishAttempt(ctx, second, AttemptSucceeded, "ACTION_COMPLETED", 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.UpdatePolicy(ctx, "modem-a", PolicyUpdate{
		Enabled: true, DHCPRetryAfterSeconds: 20, APIRetryAfterSeconds: 40,
		MobileSessionRestartAfterSeconds: 100, USBRebindAfterSeconds: 240,
		USBResetAfterSeconds: 480, USBResetCooldownSeconds: 900,
		MaxUSBResetsPerWindow: 2, USBResetWindowSeconds: 3600,
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = repository.Snapshot(ctx, "modem-a", 10)
	if snapshot.Runtime.USBResetsInWindow != 2 || snapshot.Runtime.CooldownUntil == "" {
		t.Fatalf("policy update reset durable USB safety state: %+v", snapshot.Runtime)
	}
	if _, err := repository.BeginAttempt(ctx, "modem-a", ActionUSBDeviceReset, RequestedBySystem, FailureCarrierDown); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("USB cooldown not durable, error = %v", err)
	}
}

func TestStalePolicyGenerationCannotFinishNewRuntime(t *testing.T) {
	repository, _, _ := recoveryFixture(t)
	ctx := context.Background()
	if _, err := repository.PrepareFailure(ctx, "modem-a", FailureDHCPLeaseMissing); err != nil {
		t.Fatal(err)
	}
	attempt, err := repository.BeginAttempt(ctx, "modem-a", ActionDHCPRenew, RequestedBySystem, FailureDHCPLeaseMissing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Database.ExecContext(ctx, "UPDATE modem_recovery_runtime SET policy_generation=policy_generation+1 WHERE uplink_id='modem-a'"); err != nil {
		t.Fatal(err)
	}
	if err := repository.FinishAttempt(ctx, attempt, AttemptSucceeded, "ACTION_COMPLETED", 30*time.Second); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale completion error = %v", err)
	}
}

func TestLinuxBackendDerivesInterfaceAndRejectsStaleOrUnsafeActions(t *testing.T) {
	repository, modems, _ := recoveryFixture(t)
	ctx := context.Background()
	if err := modems.ObservePhysicalLink(ctx, "modem-a", "enx123", true); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.PrepareFailure(ctx, "modem-a", FailureDHCPLeaseMissing); err != nil {
		t.Fatal(err)
	}
	attempt, err := repository.BeginAttempt(ctx, "modem-a", ActionDHCPRenew, RequestedBySystem, FailureDHCPLeaseMissing)
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakePlatformExecutor{}
	backend := LinuxBackend{Database: repository.Database, Executor: executor, Networkctl: "/usr/bin/networkctl"}
	command := Command{UplinkID: "modem-a", PolicyGeneration: attempt.PolicyGeneration, Action: ActionDHCPRenew}
	if err := backend.Execute(ctx, command); err != nil {
		t.Fatal(err)
	}
	if len(executor.requests) != 1 || executor.requests[0].Executable != "/usr/bin/networkctl" || strings.Join(executor.requests[0].Arguments, " ") != "renew enx123" {
		t.Fatalf("derived fixed DHCP request = %+v", executor.requests)
	}
	if err := backend.Execute(ctx, Command{UplinkID: "modem-a", PolicyGeneration: attempt.PolicyGeneration + 1, Action: ActionDHCPRenew}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale backend command error = %v", err)
	}
	if err := backend.Execute(ctx, Command{UplinkID: "modem-a", PolicyGeneration: attempt.PolicyGeneration, Action: ActionUSBDeviceReset}); !errors.Is(err, ErrStaleGeneration) {
		// The active durable attempt action differs, so stale tuple validation
		// must happen before the hardware capability decision.
		t.Fatalf("mismatched backend action error = %v", err)
	}
}
