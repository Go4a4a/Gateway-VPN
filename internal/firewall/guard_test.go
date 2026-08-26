package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gateway-vpn/internal/platformexec"
)

type guardExecutor struct {
	mu       sync.Mutex
	healthy  bool
	schema   bool
	lanUp    bool
	loadErr  error
	linkErr  error
	requests []platformexec.Request
}

func (executor *guardExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	executor.requests = append(executor.requests, request)
	arguments := strings.Join(request.Arguments, " ")
	switch request.Executable + " " + arguments {
	case "/usr/sbin/nft list table inet gateway_vpn":
		if !executor.healthy {
			return platformexec.Result{ExitCode: 1}, errors.New("table missing")
		}
		return platformexec.Result{Stdout: healthyGuardTable()}, nil
	case "/usr/sbin/nft --json list set inet gateway_vpn firewall_schema_generation":
		value := 9
		if executor.schema {
			value = SchemaGeneration
		}
		return platformexec.Result{Stdout: fmt.Sprintf(`{"nftables":[{"set":{"family":"inet","table":"gateway_vpn","name":"firewall_schema_generation","elem":[%d]}}]}`, value)}, nil
	case "/usr/sbin/nft --check --file -":
		return platformexec.Result{}, nil
	case "/usr/sbin/nft --file -":
		if executor.loadErr != nil {
			return platformexec.Result{}, executor.loadErr
		}
		executor.healthy, executor.schema = true, true
		return platformexec.Result{}, nil
	case "/usr/sbin/ip -json link show dev enp2s0":
		if executor.linkErr != nil {
			return platformexec.Result{}, executor.linkErr
		}
		flags := `["BROADCAST","MULTICAST"]`
		if executor.lanUp {
			flags = `["BROADCAST","MULTICAST","UP","LOWER_UP"]`
		}
		return platformexec.Result{Stdout: `[{"ifname":"enp2s0","flags":` + flags + `}]`}, nil
	case "/usr/sbin/ip link set dev enp2s0 down":
		executor.lanUp = false
		return platformexec.Result{}, nil
	case "/usr/sbin/ip link set dev enp2s0 up":
		executor.lanUp = true
		return platformexec.Result{}, nil
	default:
		return platformexec.Result{}, fmt.Errorf("unexpected guard request %s %s", request.Executable, arguments)
	}
}

func (executor *guardExecutor) setHealthy(healthy bool) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	executor.healthy = healthy
}

func TestFirewallGuardHealthyTableDoesNotTouchLAN(t *testing.T) {
	guard, executor := testGuard(t)
	executor.healthy, executor.schema, executor.lanUp = true, true, true
	result, err := guard.Ensure(context.Background())
	if err != nil || !result.Healthy || result.Recovered || !executor.lanUp {
		t.Fatalf("Ensure(healthy) = %+v, %v, lan=%v", result, err, executor.lanUp)
	}
	if len(executor.requests) != 2 {
		t.Fatalf("healthy guard request count = %d", len(executor.requests))
	}
}

func TestFirewallGuardQuarantinesRestoresAndReopensLAN(t *testing.T) {
	guard, executor := testGuard(t)
	executor.lanUp = true
	result, err := guard.Ensure(context.Background())
	if err != nil || !result.Healthy || !result.Recovered || !result.Quarantined || !result.LANRestored || !executor.lanUp {
		t.Fatalf("Ensure(missing) = %+v, %v, lan=%v", result, err, executor.lanUp)
	}
	if _, err := os.Stat(guard.MarkerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("quarantine marker remains: %v", err)
	}
	joined := guardRequests(executor.requests)
	for _, required := range []string{"ip -json link show dev enp2s0", "ip link set dev enp2s0 down", "nft --check --file -", "nft --file -", "ip link set dev enp2s0 up"} {
		if !strings.Contains(joined, required) {
			t.Errorf("guard requests missing %q:\n%s", required, joined)
		}
	}
	for _, request := range executor.requests {
		if strings.Contains(string(request.Stdin), "flush ruleset") {
			t.Fatal("guard attempted a global nftables flush")
		}
	}
}

func TestFirewallGuardKeepsLANDownUntilFailedRecoverySucceeds(t *testing.T) {
	guard, executor := testGuard(t)
	executor.lanUp = true
	executor.loadErr = errors.New("nft load failed")
	result, err := guard.Ensure(context.Background())
	if err == nil || result.Healthy || executor.lanUp {
		t.Fatalf("Ensure(load failure) = %+v, %v, lan=%v", result, err, executor.lanUp)
	}
	if _, err := os.Stat(guard.MarkerPath); err != nil {
		t.Fatalf("durable quarantine marker missing: %v", err)
	}

	// Simulate a service restart: a fresh Guard instance recovers ownership
	// from the root-only runtime marker and is allowed to reopen the LAN only
	// after the table and schema generation verify.
	executor.loadErr = nil
	restarted := *guard
	result, err = restarted.Ensure(context.Background())
	if err != nil || !result.Healthy || !result.LANRestored || !executor.lanUp {
		t.Fatalf("Ensure(after restart) = %+v, %v, lan=%v", result, err, executor.lanUp)
	}
}

func TestFirewallGuardPreservesPreexistingAdministrativeDownState(t *testing.T) {
	guard, executor := testGuard(t)
	executor.lanUp = false
	result, err := guard.Ensure(context.Background())
	if err != nil || !result.Healthy || !result.Recovered || result.LANRestored || executor.lanUp {
		t.Fatalf("Ensure(admin down) = %+v, %v, lan=%v", result, err, executor.lanUp)
	}
	if _, err := os.Stat(guard.MarkerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("guard claimed preexisting down state: %v", err)
	}
}

func TestFirewallGuardRejectsWrongSchemaGeneration(t *testing.T) {
	guard, executor := testGuard(t)
	executor.healthy, executor.schema, executor.lanUp = true, false, true
	result, err := guard.Ensure(context.Background())
	if err != nil || !result.Recovered || !executor.schema || !executor.lanUp {
		t.Fatalf("Ensure(wrong schema) = %+v, %v", result, err)
	}
}

type guardMonitor struct {
	events  chan struct{}
	errors  chan error
	started chan struct{}
}

func (monitor guardMonitor) Watch(context.Context) (<-chan struct{}, <-chan error, error) {
	close(monitor.started)
	return monitor.events, monitor.errors, nil
}

func TestFirewallGuardRunnerReactsToMonitorEvent(t *testing.T) {
	guard, executor := testGuard(t)
	executor.healthy, executor.schema, executor.lanUp = true, true, true
	monitor := guardMonitor{events: make(chan struct{}, 1), errors: make(chan error, 1), started: make(chan struct{})}
	recovered := make(chan GuardResult, 1)
	runner := &GuardRunner{Guard: guard, Monitor: monitor, PollInterval: time.Hour, MonitorBackoff: time.Second, OnResult: func(result GuardResult) {
		if result.Recovered {
			recovered <- result
		}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	<-monitor.started
	executor.setHealthy(false)
	monitor.events <- struct{}{}
	select {
	case result := <-recovered:
		if !result.LANRestored {
			t.Fatalf("monitor recovery result = %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("guard did not react to nft monitor event")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("GuardRunner.Run() error = %v", err)
	}
}

func TestFirewallGuardRunnerPollingRecoversWhenMonitorIsSilent(t *testing.T) {
	guard, executor := testGuard(t)
	executor.healthy, executor.schema, executor.lanUp = true, true, true
	monitor := guardMonitor{events: make(chan struct{}), errors: make(chan error), started: make(chan struct{})}
	recovered := make(chan GuardResult, 1)
	runner := &GuardRunner{Guard: guard, Monitor: monitor, PollInterval: 20 * time.Millisecond, MonitorBackoff: 20 * time.Millisecond, OnResult: func(result GuardResult) {
		if result.Recovered {
			recovered <- result
		}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	<-monitor.started
	executor.setHealthy(false)
	select {
	case <-recovered:
	case <-time.After(3 * time.Second):
		t.Fatal("periodic guard check did not recover silent nft loss")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("GuardRunner.Run() error = %v", err)
	}
}

func testGuard(t *testing.T) (*Guard, *guardExecutor) {
	t.Helper()
	ruleset, err := RenderBootBlocked(BootConfig{LANInterface: "enp2s0", TUNInterface: "gateway-vpn-tun", WireGuardInterface: "wg-mgmt", APIPort: 8443, WireGuardListenPort: 51821})
	if err != nil {
		t.Fatal(err)
	}
	executor := &guardExecutor{}
	return &Guard{Executor: executor, NFT: "/usr/sbin/nft", IP: "/usr/sbin/ip", LANInterface: "enp2s0", Ruleset: ruleset, MarkerPath: filepath.Join(t.TempDir(), "quarantine")}, executor
}

func healthyGuardTable() string {
	return `table inet gateway_vpn {
set firewall_schema_generation
set active_tun_interfaces
set active_path_generation
set hilink_interfaces
set wireguard_endpoint_v4
set mihomo_endpoint_tcp_v4
counter user_upload
counter user_download
counter service_upload
counter service_download
chain input { type filter hook input priority filter; policy drop; }
chain forward { type filter hook forward priority filter; policy drop; oifname @active_tun_interfaces counter comment "gateway-vpn PATH_BLOCKED" }
chain output { type filter hook output priority filter; policy drop; oifname . meta mark . ip daddr @wireguard_endpoint_v4 udp dport 51821 accept }
}`
}

func guardRequests(requests []platformexec.Request) string {
	values := make([]string, 0, len(requests))
	for _, request := range requests {
		values = append(values, filepath.Base(request.Executable)+" "+strings.Join(request.Arguments, " "))
	}
	return strings.Join(values, "\n")
}
