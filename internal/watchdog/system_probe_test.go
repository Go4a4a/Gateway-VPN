package watchdog

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"gateway-vpn/internal/platformexec"
)

type recordingExecutor struct {
	requests []platformexec.Request
	result   platformexec.Result
	err      error
}

func (executor *recordingExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	return executor.result, executor.err
}

func TestSystemProbePrivilegedActionsUseOnlyFixedCommands(t *testing.T) {
	executor := &recordingExecutor{}
	probe := fixedTestSystemProbe(executor)
	ctx := context.Background()
	if err := probe.Reconcile(ctx, ComponentNetworkBroker); err != nil {
		t.Fatal(err)
	}
	if err := probe.FailClosed(ctx); err != nil {
		t.Fatal(err)
	}
	if err := probe.Restart(ctx, ComponentFirewallRuleset); err != nil {
		t.Fatal(err)
	}
	if err := probe.Reboot(ctx); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		executable string
		arguments  []string
	}{
		{"/usr/bin/systemctl", []string{"kill", "--kill-who=main", "--signal=SIGHUP", "gateway-vpn.service"}},
		{"/opt/gateway-vpn/current/bin/gateway-vpn", []string{"firewall-boot", "--config", "/etc/gateway-vpn/config.yaml", "--apply"}},
		{"/usr/bin/systemctl", []string{"restart", "gateway-vpn-firewall.service"}},
		{"/usr/bin/systemctl", []string{"restart", "gateway-vpn-firewall-guard.service"}},
		{"/usr/bin/systemctl", []string{"--no-block", "reboot"}},
	}
	if len(executor.requests) != len(want) {
		t.Fatalf("fixed privileged requests = %+v", executor.requests)
	}
	for index, expected := range want {
		request := executor.requests[index]
		if request.Executable != expected.executable || !reflect.DeepEqual(request.Arguments, expected.arguments) {
			t.Errorf("request %d = %s %v, want %s %v", index, request.Executable, request.Arguments, expected.executable, expected.arguments)
		}
	}
}

func TestSystemProbeRejectsUnknownComponentAndMutablePrivilegedPath(t *testing.T) {
	executor := &recordingExecutor{}
	probe := fixedTestSystemProbe(executor)
	if err := probe.Restart(context.Background(), "ssh"); err == nil {
		t.Fatal("unknown component restart accepted")
	}
	if err := probe.Restart(context.Background(), ComponentResources); err == nil {
		t.Fatal("non-restartable resource component accepted")
	}
	probe.Systemctl = "/tmp/systemctl"
	if err := probe.Reconcile(context.Background(), ComponentControl); err == nil {
		t.Fatal("mutable privileged executable accepted")
	}
	if len(executor.requests) != 0 {
		t.Fatalf("rejected actions reached executor: %+v", executor.requests)
	}
}

func TestSystemProbeRestartMatrixIsFixedAndComplete(t *testing.T) {
	want := map[string][]string{
		ComponentControl:          {"gateway-vpn.service"},
		ComponentSQLite:           {"gateway-vpn.service"},
		ComponentFirewallGuard:    {"gateway-vpn-firewall.service", "gateway-vpn-firewall-guard.service"},
		ComponentFirewallRuleset:  {"gateway-vpn-firewall.service", "gateway-vpn-firewall-guard.service"},
		ComponentNetworkBroker:    {"gateway-vpn-network-broker.service"},
		ComponentNetworkd:         {"systemd-networkd.service"},
		ComponentDNSMasq:          {"gateway-vpn-dnsmasq.service"},
		ComponentSSH:              {"ssh.service"},
		ComponentMihomo:           {"gateway-vpn-mihomo.service"},
		ComponentWireGuardMgmt:    {"gateway-vpn-network-broker.service", "gateway-vpn.service"},
		ComponentWireGuardIngress: {"gateway-vpn-network-broker.service", "gateway-vpn.service"},
		ComponentPolicyRouting:    {"gateway-vpn-network-broker.service", "gateway-vpn.service"},
		ComponentWorkerRuntime:    {"gateway-vpn.service"},
		ComponentConvergence:      {"gateway-vpn.service"},
		ComponentBackup:           {"gateway-vpn.service"},
	}
	for componentID, units := range want {
		t.Run(componentID, func(t *testing.T) {
			executor := &recordingExecutor{}
			probe := fixedTestSystemProbe(executor)
			if err := probe.Restart(context.Background(), componentID); err != nil {
				t.Fatal(err)
			}
			if len(executor.requests) != len(units) {
				t.Fatalf("restart requests = %+v", executor.requests)
			}
			for index, unit := range units {
				request := executor.requests[index]
				if request.Executable != "/usr/bin/systemctl" || !reflect.DeepEqual(request.Arguments, []string{"restart", unit}) {
					t.Errorf("restart request %d = %s %v", index, request.Executable, request.Arguments)
				}
			}
		})
	}
	if len(want) != len(restartUnits) {
		t.Fatalf("restart matrix has untested entries: actual=%v", restartUnits)
	}
}

func TestMaintenanceUnitAllowlistCoversDestructiveLifecycle(t *testing.T) {
	want := map[string]bool{
		"gateway-vpn-install-recovery.service":          false,
		"gateway-vpn-update.service":                    false,
		"gateway-vpn-update-recovery.service":           false,
		"gateway-vpn-update-finalize.service":           false,
		"gateway-vpn-update-resume.service":             false,
		"gateway-vpn-database-restore.service":          false,
		"gateway-vpn-database-restore-boot.service":     false,
		"gateway-vpn-database-restore-dispatch.service": false,
		"gateway-vpn-database-restore-resume.service":   false,
		"gateway-vpn-network-recovery.service":          false,
	}
	for _, item := range maintenanceUnits {
		if _, exists := want[item.unit]; !exists {
			t.Fatalf("unexpected maintenance unit %q", item.unit)
		}
		if want[item.unit] {
			t.Fatalf("duplicate maintenance unit %q", item.unit)
		}
		want[item.unit] = true
		if !fixedUnit(item.unit) || item.code == "" {
			t.Fatalf("maintenance unit is not fixed and coded: %+v", item)
		}
	}
	for unit, seen := range want {
		if !seen {
			t.Errorf("destructive lifecycle unit %s is missing from watchdog maintenance suppression", unit)
		}
	}
}

func TestHeartbeatFileRoundTripAndStaleness(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "gateway-vpn-watchdog")
	if err := os.Mkdir(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	file := HeartbeatFile{Path: filepath.Join(directory, "control.json")}
	now := time.Date(2026, 8, 26, 21, 0, 0, 0, time.UTC)
	heartbeat := ControlHeartbeat{
		SchemaVersion: 2, PID: 42, ProcessStartedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		WrittenAt: now.Format(time.RFC3339Nano), DatabaseOK: true, WorkersOK: true, APIServing: true,
		ReconcileLastAt: now.Add(-time.Second).Format(time.RFC3339Nano),
		Workers:         map[string]WorkerProgress{WorkerDataPlaneReconcile: {LastProgressAt: now.Add(-time.Second).Format(time.RFC3339Nano), MaximumSilenceSeconds: 30, Critical: true}},
	}
	if err := file.Write(heartbeat); err != nil {
		t.Fatal(err)
	}
	loaded, err := file.Read(now.Add(30*time.Second), time.Minute)
	if err != nil || loaded.PID != 42 {
		t.Fatalf("heartbeat round trip = %+v, %v", loaded, err)
	}
	if _, err := file.Read(now.Add(2*time.Minute), time.Minute); err == nil {
		t.Fatal("stale heartbeat accepted")
	}
}

func TestWatchdogStatusFreshnessRejectsStaleRuntimeFile(t *testing.T) {
	now := time.Date(2026, 8, 26, 21, 0, 0, 0, time.UTC)
	status := Status{
		SchemaVersion: 1, SupervisorStartedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		ObservedAt: now.Format(time.RFC3339Nano), OverallState: OverallHealthy,
	}
	maximumAge := MaximumStatusAge(DefaultPolicy())
	if err := status.ValidateFresh(now.Add(maximumAge), maximumAge); err != nil {
		t.Fatalf("boundary-fresh status rejected: %v", err)
	}
	if err := status.ValidateFresh(now.Add(maximumAge+time.Nanosecond), maximumAge); err == nil {
		t.Fatal("stale watchdog status accepted")
	}
}

func fixedTestSystemProbe(executor platformexec.Executor) *SystemProbe {
	return &SystemProbe{
		Executor: executor, Systemctl: "/usr/bin/systemctl", NFT: "/usr/sbin/nft", IP: "/usr/sbin/ip", WG: "/usr/bin/wg",
		SSHD: "/usr/sbin/sshd", SS: "/usr/bin/ss",
		GatewayBinary: "/opt/gateway-vpn/current/bin/gateway-vpn", ConfigPath: "/etc/gateway-vpn/config.yaml",
		DatabasePath: "/var/lib/gateway-vpn/state.db", HeartbeatPath: "/run/gateway-vpn-watchdog/control.json",
		MihomoConfigPath: "/var/lib/gateway-vpn/mihomo/active/config.yaml", MihomoTUN: "gateway-vpn-tun",
		WireGuardConfigPath: "/etc/gateway-vpn/wireguard.yaml", LANPrefix: "192.168.200.1/24", WireGuardPrefix: "10.80.0.0/24",
		BootstrapDNS: []string{"1.1.1.1"}, RoutingTableStart: 1101, FwmarkStart: 0x1101,
		InstallMarkerPath: "/var/lib/gateway-vpn-privileged/install-transactions/active",
	}
}
