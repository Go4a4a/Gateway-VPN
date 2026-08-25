package routing

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gateway-vpn/internal/networkplan"
	"gateway-vpn/internal/platformexec"
)

func TestRenderNeverTargetsMainTableOrGlobalFlush(t *testing.T) {
	plan, err := networkplan.Build(networkplan.Input{
		LANPrefix:       "192.168.200.0/24",
		WireGuardPrefix: "10.80.0.0/24",
		Modems: []networkplan.ModemInput{
			{ID: "modem-a", Priority: 10, InterfaceName: "enx0001", ManagementPrefix: "192.168.8.0/24", Gateway: "192.168.8.1", RoutingTableID: 1101, Fwmark: 0x1101},
		},
	})
	if err != nil {
		t.Fatalf("networkplan.Build() error = %v", err)
	}
	operations, err := Render(plan, "/usr/sbin/ip")
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if len(operations) != 4 {
		t.Fatalf("operation count = %d, want 4", len(operations))
	}
	for _, operation := range operations {
		joined := strings.Join(operation.Request.Arguments, " ")
		if strings.Contains(joined, " flush") || strings.Contains(joined, " table main") || strings.Contains(joined, " table 254") {
			t.Fatalf("unsafe operation: %s", joined)
		}
	}
	rule := strings.Join(operations[3].Request.Arguments, " ")
	for _, expected := range []string{"fwmark 0x1101/0xffffffff", "lookup 1101", "protocol 186"} {
		if !strings.Contains(rule, expected) {
			t.Errorf("rule %q missing %q", rule, expected)
		}
	}
}

func TestApplyIsDryRunByDefaultAndHandlesOwnedDeleteMiss(t *testing.T) {
	executor := &fakeExecutor{results: []fakeResult{
		{result: platformexec.Result{ExitCode: 2}, err: errors.New("not found")},
		{},
	}}
	operations := []Operation{
		{Description: "delete", Request: platformexec.Request{Executable: "/usr/sbin/ip"}, AllowedExitCodes: []int{2}},
		{Description: "add", Request: platformexec.Request{Executable: "/usr/sbin/ip"}},
	}
	if err := Apply(context.Background(), executor, operations, ApplyOptions{}); err != nil {
		t.Fatalf("dry Apply() error = %v", err)
	}
	if len(executor.requests) != 0 {
		t.Fatalf("dry Apply() executed %d commands", len(executor.requests))
	}
	if err := Apply(context.Background(), executor, operations, ApplyOptions{Mutate: true}); err != nil {
		t.Fatalf("mutating Apply() error = %v", err)
	}
	if len(executor.requests) != 2 {
		t.Fatalf("mutating Apply() executed %d commands, want 2", len(executor.requests))
	}
}

func TestRenderRemovalIsModemScoped(t *testing.T) {
	plan, err := networkplan.Build(networkplan.Input{LANPrefix: "192.168.200.0/24", WireGuardPrefix: "10.80.0.0/24", Modems: []networkplan.ModemInput{{ID: "m1", InterfaceName: "enxm1", ManagementPrefix: "192.168.8.0/24", Gateway: "192.168.8.1", RoutingTableID: 1101, Fwmark: 0x1101}, {ID: "m2", InterfaceName: "enxm2", ManagementPrefix: "192.168.9.0/24", Gateway: "192.168.9.1", RoutingTableID: 1102, Fwmark: 0x1102}}})
	if err != nil {
		t.Fatal(err)
	}
	operations, err := RenderRemoval(plan, "m1", "/usr/sbin/ip")
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 3 {
		t.Fatalf("removal operation count = %d", len(operations))
	}
	for _, operation := range operations {
		joined := strings.Join(operation.Request.Arguments, " ")
		if strings.Contains(joined, "1102") || strings.Contains(joined, "enxm2") || strings.Contains(joined, "flush") {
			t.Fatalf("removal escaped modem scope: %s", joined)
		}
	}
}

type fakeResult struct {
	result platformexec.Result
	err    error
}

type fakeExecutor struct {
	requests []platformexec.Request
	results  []fakeResult
}

func (executor *fakeExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	if len(executor.results) == 0 {
		return platformexec.Result{}, nil
	}
	result := executor.results[0]
	executor.results = executor.results[1:]
	return result.result, result.err
}
