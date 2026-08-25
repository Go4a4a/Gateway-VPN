package mihomoruntime

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"gateway-vpn/internal/platformexec"
)

type adapterExecutor struct {
	requests []platformexec.Request
	results  []platformexec.Result
	errors   []error
}

func (executor *adapterExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	index := len(executor.requests) - 1
	var result platformexec.Result
	var err error
	if index < len(executor.results) {
		result = executor.results[index]
	}
	if index < len(executor.errors) {
		err = executor.errors[index]
	}
	return result, err
}

func TestSystemdAdminUsesOnlyFixedUnitsAndFailClosedOrder(t *testing.T) {
	executor := &adapterExecutor{}
	admin := SystemdAdmin{Executor: executor, Systemctl: "/usr/bin/systemctl"}
	if err := admin.RestartMihomo(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := admin.FailClosedMihomo(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"restart", MihomoUnit},
		{"reload", FirewallUnit},
		{"stop", MihomoUnit},
	}
	var got [][]string
	for _, request := range executor.requests {
		if request.Executable != "/usr/bin/systemctl" {
			t.Fatalf("unexpected executable %s", request.Executable)
		}
		got = append(got, request.Arguments)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("systemd operations = %v, want %v", got, want)
	}
}

func TestSystemdAdminAttemptsStopEvenWhenFirewallReloadFails(t *testing.T) {
	executor := &adapterExecutor{errors: []error{errors.New("reload failed")}}
	admin := SystemdAdmin{Executor: executor, Systemctl: "/usr/bin/systemctl"}
	if err := admin.FailClosedMihomo(context.Background()); err == nil {
		t.Fatal("FailClosedMihomo(reload failure) error = nil")
	}
	if len(executor.requests) != 2 || !reflect.DeepEqual(executor.requests[1].Arguments, []string{"stop", MihomoUnit}) {
		t.Fatalf("fail-closed requests = %+v", executor.requests)
	}
}

func TestIPLinkInspectorRequiresNamedUpLink(t *testing.T) {
	executor := &adapterExecutor{results: []platformexec.Result{{Stdout: `[{"ifname":"gateway-vpn-tun","flags":["UP","POINTOPOINT"]}]`}}}
	inspector := IPLinkInspector{Executor: executor, IP: "/usr/sbin/ip"}
	if err := inspector.RequireReady(context.Background(), "gateway-vpn-tun"); err != nil {
		t.Fatalf("RequireReady() error = %v", err)
	}
	executor = &adapterExecutor{results: []platformexec.Result{{Stdout: `[{"ifname":"gateway-vpn-tun","flags":["POINTOPOINT"]}]`}}}
	inspector.Executor = executor
	if err := inspector.RequireReady(context.Background(), "gateway-vpn-tun"); err == nil {
		t.Fatal("RequireReady(link down) error = nil")
	}
}
