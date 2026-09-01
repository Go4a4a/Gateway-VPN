package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/uplink"
)

const (
	desiredRulesJSON  = `[{"priority":1101,"src":"all","fwmark":"0x1101","table":"1101","protocol":"186"}]`
	desiredRoutesJSON = `[
  {"dst":"192.168.8.0/24","dev":"enx0001","scope":"link","table":"1101"},
  {"dst":"default","gateway":"192.168.8.1","dev":"enx0001","table":"1101"},
  {"dst":"203.0.113.10/32","gateway":"192.168.8.1","dev":"enx0001","table":"1101"}
]`
)

type routingGate struct {
	blocks int
	err    error
}

func (gate *routingGate) BlockPath(context.Context) error {
	gate.blocks++
	return gate.err
}

type routingExecutor struct {
	requests     []platformexec.Request
	cycle        int
	beforeRules  string
	beforeRoutes string
	afterRules   string
	afterRoutes  string
	routeGetErr  error
	sourceMark   string
}

func (executor *routingExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	arguments := strings.Join(request.Arguments, " ")
	switch arguments {
	case "-n net.ipv4.conf.all.src_valid_mark":
		value := executor.sourceMark
		if value == "" {
			value = "1"
		}
		return platformexec.Result{Stdout: value + "\n"}, nil
	case "-N -json -4 rule show":
		executor.cycle++
		if executor.cycle == 1 {
			return platformexec.Result{Stdout: executor.beforeRules}, nil
		}
		return platformexec.Result{Stdout: executor.afterRules}, nil
	case "-json -4 route show table all protocol 186":
		if executor.cycle == 1 {
			return platformexec.Result{Stdout: executor.beforeRoutes}, nil
		}
		return platformexec.Result{Stdout: executor.afterRoutes}, nil
	case "-json -4 route get 1.1.1.1 mark 0x1101":
		if executor.routeGetErr != nil {
			return platformexec.Result{ExitCode: 2}, executor.routeGetErr
		}
		return platformexec.Result{Stdout: `[{"dst":"1.1.1.1","gateway":"192.168.8.1","dev":"enx0001","table":1101}]`}, nil
	default:
		return platformexec.Result{}, nil
	}
}

func TestRoutingBackendReplacesStaleBaseStateAndPreservesEndpointRoutes(t *testing.T) {
	repository, closeDatabase := readyRoutingModem(t)
	defer closeDatabase()
	gate := &routingGate{}
	executor := &routingExecutor{
		beforeRules: `[{"priority":1102,"fwmark":"0x1102","fwmask":"0xffffffff","table":"1102","protocol":"186"}]`,
		beforeRoutes: `[
  {"dst":"192.168.9.0/24","dev":"enxgone","scope":"link","table":"1102"},
  {"dst":"default","gateway":"192.168.9.1","dev":"enxgone","table":"1102"},
  {"dst":"203.0.113.10/32","gateway":"192.168.9.1","dev":"enxgone","table":"1102"}
]`,
		afterRules: desiredRulesJSON, afterRoutes: desiredRoutesJSON,
	}
	backend := testRoutingBackend(repository, executor, gate)
	if err := backend.SyncRouting(context.Background()); err != nil {
		t.Fatalf("SyncRouting() error = %v", err)
	}
	if gate.blocks != 1 {
		t.Fatalf("path gate blocks = %d, want 1", gate.blocks)
	}
	joined := make([]string, 0, len(executor.requests))
	for _, request := range executor.requests {
		joined = append(joined, strings.Join(request.Arguments, " "))
	}
	all := strings.Join(joined, "\n")
	for _, required := range []string{
		"rule del priority 1102 protocol 186",
		"route del 192.168.9.0/24 table 1102 protocol 186",
		"route del 0.0.0.0/0 table 1102 protocol 186",
		"route replace 0.0.0.0/0 via 192.168.8.1 dev enx0001 table 1101 protocol 186",
		"route get 1.1.1.1 mark 0x1101",
	} {
		if !strings.Contains(all, required) {
			t.Errorf("requests missing %q:\n%s", required, all)
		}
	}
	for _, forbidden := range []string{"route del 203.0.113.10/32", "flush", "table main", "table 254"} {
		if strings.Contains(all, forbidden) {
			t.Fatalf("routing sync contains forbidden operation %q:\n%s", forbidden, all)
		}
	}
}

func TestRoutingBackendNoopStillVerifiesMarkedLookupWithoutClosingGate(t *testing.T) {
	repository, closeDatabase := readyRoutingModem(t)
	defer closeDatabase()
	gate := &routingGate{}
	executor := &routingExecutor{beforeRules: desiredRulesJSON, beforeRoutes: desiredRoutesJSON}
	backend := testRoutingBackend(repository, executor, gate)
	if err := backend.SyncRouting(context.Background()); err != nil {
		t.Fatalf("SyncRouting(no-op) error = %v", err)
	}
	if gate.blocks != 0 {
		t.Fatalf("no-op path gate blocks = %d", gate.blocks)
	}
	if len(executor.requests) != 4 {
		t.Fatalf("no-op request count = %d, want observe+verify only", len(executor.requests))
	}
}

func TestRoutingBackendUnavailableSourceMarkClosesGateBeforeObservation(t *testing.T) {
	repository, closeDatabase := readyRoutingModem(t)
	defer closeDatabase()
	gate := &routingGate{}
	executor := &routingExecutor{sourceMark: "0"}
	backend := testRoutingBackend(repository, executor, gate)
	if err := backend.SyncRouting(context.Background()); err == nil || !strings.Contains(err.Error(), "source-mark") {
		t.Fatalf("SyncRouting(source mark disabled) error = %v", err)
	}
	if gate.blocks != 1 {
		t.Fatalf("source-mark failure path gate blocks = %d, want 1", gate.blocks)
	}
	if len(executor.requests) != 1 || executor.requests[0].Executable != "/usr/sbin/sysctl" {
		t.Fatalf("source-mark failure reached routing observation: %+v", executor.requests)
	}
}

func TestRoutingBackendRequiresFixedSysctlExecutable(t *testing.T) {
	repository, closeDatabase := readyRoutingModem(t)
	defer closeDatabase()
	backend := testRoutingBackend(repository, &routingExecutor{}, nil)
	backend.Sysctl = ""
	if _, err := backend.CheckRouting(context.Background()); err == nil || !strings.Contains(err.Error(), "fixed Ubuntu sysctl") {
		t.Fatalf("CheckRouting(missing sysctl) error = %v", err)
	}
}

func TestRoutingBackendReadOnlyCheckCannotMutate(t *testing.T) {
	repository, closeDatabase := readyRoutingModem(t)
	defer closeDatabase()
	executor := &routingExecutor{beforeRules: desiredRulesJSON, beforeRoutes: desiredRoutesJSON}
	backend := testRoutingBackend(repository, executor, nil)
	result, err := backend.CheckRouting(context.Background())
	if err != nil || result.ReadyUplinks != 1 || result.Rules != 1 || result.Routes != 2 {
		t.Fatalf("CheckRouting() = %+v, %v", result, err)
	}
	for _, request := range executor.requests {
		arguments := strings.Join(request.Arguments, " ")
		if strings.Contains(arguments, " replace ") || strings.Contains(arguments, " del ") || strings.Contains(arguments, " add ") {
			t.Fatalf("read-only routing check attempted mutation: %s %s", request.Executable, arguments)
		}
	}
}

func TestRoutingBackendLookupFailureClosesGate(t *testing.T) {
	repository, closeDatabase := readyRoutingModem(t)
	defer closeDatabase()
	gate := &routingGate{}
	executor := &routingExecutor{beforeRules: desiredRulesJSON, beforeRoutes: desiredRoutesJSON, routeGetErr: errors.New("no marked route")}
	backend := testRoutingBackend(repository, executor, gate)
	if err := backend.SyncRouting(context.Background()); err == nil {
		t.Fatal("SyncRouting(route lookup failure) error = nil")
	}
	if gate.blocks != 1 {
		t.Fatalf("lookup failure path gate blocks = %d, want 1", gate.blocks)
	}
}

func readyRoutingModem(t *testing.T) (*uplink.Repository, func()) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	repository := modem.NewRepository(database, 1101, 0x1101)
	_, err = repository.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "Operator A", IdentityKind: "hilink_serial_hash", IdentityHash: strings.Repeat("a", 64)})
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := repository.ApplyLease(ctx, "modem-a", modem.LeaseInput{InterfaceName: "enx0001", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"192.168.8.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return uplink.NewRepository(database, 1101, 0x1101), func() { _ = database.Close() }
}

func testRoutingBackend(repository *uplink.Repository, executor platformexec.Executor, gate PathBlocker) RoutingBackend {
	return RoutingBackend{
		Uplinks: repository, Executor: executor, IP: "/usr/sbin/ip", Sysctl: "/usr/sbin/sysctl",
		LANPrefix: "192.168.200.1/24", WireGuardPrefix: "10.80.0.0/24",
		BootstrapDNS: []string{"1.1.1.1"}, RoutingTableStart: 1101, FwmarkStart: 0x1101, Gate: gate,
	}
}
