package update

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/watchdog"
)

type systemRuntimeExecutor struct {
	requests         []platformexec.Request
	failReset        bool
	failManagedReset bool
	failSync         bool
}

func (executor *systemRuntimeExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	if reflect.DeepEqual(request.Arguments, []string{"reset-failed", firewallUnit, guardUnit}) {
		if executor.failReset {
			return platformexec.Result{Stderr: "private systemd detail"}, os.ErrPermission
		}
		return platformexec.Result{}, nil
	}
	if reflect.DeepEqual(request.Arguments, []string{"reset-failed", networkRecoveryUnit, watchdogUnit, brokerUnit, brokerServiceUnit, controlUnit, mihomoUnit, dnsmasqUnit}) {
		if executor.failManagedReset {
			return platformexec.Result{Stderr: "private systemd detail"}, os.ErrPermission
		}
		return platformexec.Result{}, nil
	}
	if reflect.DeepEqual(request.Arguments, []string{"restart", firewallUnit, guardUnit}) {
		if executor.failSync {
			return platformexec.Result{Stderr: "private systemd detail"}, os.ErrPermission
		}
		return platformexec.Result{}, nil
	}
	if strings.HasSuffix(request.Executable, filepath.Join("bin", "gateway-vpn")) && reflect.DeepEqual(request.Arguments, []string{"--version"}) {
		return platformexec.Result{Stdout: "gateway-vpn 1.2.3 (test)\n"}, nil
	}
	if strings.HasSuffix(request.Executable, filepath.Join("bin", "gateway-vpnctl")) && len(request.Arguments) == 4 && request.Arguments[0] == "status" {
		return platformexec.Result{Stdout: "{}\n"}, nil
	}
	return platformexec.Result{}, nil
}

func TestUpdateRuntimeQuiesceAtomicallySelectsFailClosedFirewallAndGuard(t *testing.T) {
	executor := &systemRuntimeExecutor{}
	runtime := SystemRuntime{Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl"), ReleaseRoot: filepath.Join(t.TempDir(), "gateway-vpn")}
	if err := runtime.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(executor.requests) != 3 {
		t.Fatalf("quiesce requests = %+v", executor.requests)
	}
	if !reflect.DeepEqual(executor.requests[0].Arguments, []string{"stop", controlUnit, "gateway-vpn-network-broker.service", brokerUnit, mihomoUnit, dnsmasqUnit}) {
		t.Fatalf("quiesce stop = %v", executor.requests[0].Arguments)
	}
	if !reflect.DeepEqual(executor.requests[1].Arguments, []string{"reset-failed", firewallUnit, guardUnit}) ||
		!reflect.DeepEqual(executor.requests[2].Arguments, []string{"restart", firewallUnit, guardUnit}) {
		t.Fatalf("firewall schema transaction = %+v", executor.requests[1:])
	}
}

func TestUpdateRecoverySynchronizesSelectedFirewallBeforeAcceptingRelease(t *testing.T) {
	executor := &systemRuntimeExecutor{}
	releaseRoot := filepath.Join(t.TempDir(), "gateway-vpn")
	runtime := SystemRuntime{Executor: executor, Systemctl: filepath.Join(t.TempDir(), "systemctl"), ReleaseRoot: releaseRoot, RecoveryOnly: true}
	databasePath := filepath.Join(t.TempDir(), "state.db")
	if err := runtime.StartAndHealth(context.Background(), "1.2.3", databasePath, ManagedRuntimeState{}); err != nil {
		t.Fatal(err)
	}
	if len(executor.requests) != 5 ||
		!reflect.DeepEqual(executor.requests[0].Arguments, []string{"reset-failed", firewallUnit, guardUnit}) ||
		!reflect.DeepEqual(executor.requests[1].Arguments, []string{"restart", firewallUnit, guardUnit}) ||
		!reflect.DeepEqual(executor.requests[2].Arguments, []string{"reset-failed", networkRecoveryUnit, watchdogUnit, brokerUnit, brokerServiceUnit, controlUnit, mihomoUnit, dnsmasqUnit}) {
		t.Fatalf("recovery requests = %+v", executor.requests)
	}
	executor = &systemRuntimeExecutor{failSync: true}
	runtime.Executor = executor
	if err := runtime.StartAndHealth(context.Background(), "1.2.3", databasePath, ManagedRuntimeState{}); err == nil || len(executor.requests) != 2 {
		t.Fatalf("failed firewall synchronization was not fatal: requests=%+v error=%v", executor.requests, err)
	}
	executor = &systemRuntimeExecutor{failReset: true}
	runtime.Executor = executor
	if err := runtime.StartAndHealth(context.Background(), "1.2.3", databasePath, ManagedRuntimeState{}); err == nil || len(executor.requests) != 1 {
		t.Fatalf("failed start-limit reset was not fatal: requests=%+v error=%v", executor.requests, err)
	}
	executor = &systemRuntimeExecutor{failManagedReset: true}
	runtime.Executor = executor
	if err := runtime.StartAndHealth(context.Background(), "1.2.3", databasePath, ManagedRuntimeState{}); err == nil || len(executor.requests) != 3 {
		t.Fatalf("failed managed start-limit reset was not fatal: requests=%+v error=%v", executor.requests, err)
	}
}

func TestUpdateLifecycleUnitsDoNotRequireTheFirewallPairTheyRestart(t *testing.T) {
	for _, name := range []string{"gateway-vpn-update.service", "gateway-vpn-update-recovery.service", "gateway-vpn-update-resume.service"} {
		content, err := os.ReadFile(filepath.Join("..", "..", "packaging", "systemd", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		if !strings.Contains(text, "After=") || !strings.Contains(text, firewallUnit) || !strings.Contains(text, guardUnit) || !strings.Contains(text, "Wants=") {
			t.Errorf("%s does not order and weakly activate the firewall pair", name)
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "Requires=") && (strings.Contains(line, firewallUnit) || strings.Contains(line, guardUnit)) {
				t.Errorf("%s has a self-terminating dependency while restarting the firewall pair: %s", name, line)
			}
		}
	}
}

func TestUpdateRuntimeRequiresFreshWatchdogAndControlEvidence(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "gateway-vpn-watchdog")
	if err := os.Mkdir(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(directory, "status.json")
	heartbeatPath := filepath.Join(directory, "control.json")
	now := time.Date(2026, 8, 26, 22, 0, 0, 0, time.UTC)
	status := watchdog.Status{
		SchemaVersion: 1, SupervisorStartedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		ObservedAt: now.Format(time.RFC3339Nano), OverallState: watchdog.OverallHealthy,
	}
	if err := (watchdog.StatusFile{Path: statusPath}).Write(status); err != nil {
		t.Fatal(err)
	}
	heartbeat := watchdog.ControlHeartbeat{
		SchemaVersion: 2, PID: 42, ProcessStartedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		WrittenAt: now.Format(time.RFC3339Nano), DatabaseOK: true, WorkersOK: true, APIServing: true,
		ReconcileLastAt: now.Add(-time.Second).Format(time.RFC3339Nano),
		Workers: map[string]watchdog.WorkerProgress{
			watchdog.WorkerDataPlaneReconcile: {LastProgressAt: now.Add(-time.Second).Format(time.RFC3339Nano), MaximumSilenceSeconds: 30, Critical: true},
		},
	}
	if err := (watchdog.HeartbeatFile{Path: heartbeatPath}).Write(heartbeat); err != nil {
		t.Fatal(err)
	}
	if err := checkWatchdogRuntimeFiles(statusPath, heartbeatPath, now.Add(10*time.Second)); err != nil {
		t.Fatalf("fresh watchdog evidence rejected: %v", err)
	}
	if err := checkWatchdogRuntimeFiles(statusPath, heartbeatPath, now.Add(3*time.Minute)); err == nil {
		t.Fatal("stale watchdog evidence accepted after update")
	}
}
