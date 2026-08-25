package hilink

import (
	"context"
	"testing"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkplan"
	"gateway-vpn/internal/platformexec"
)

type recordingExecutor struct{ requests []platformexec.Request }

func (executor *recordingExecutor) Run(_ context.Context, request platformexec.Request) (platformexec.Result, error) {
	executor.requests = append(executor.requests, request)
	return platformexec.Result{}, nil
}

func TestIPRoutesRemainsDryUntilExplicitMutation(t *testing.T) {
	executor := &recordingExecutor{}
	controller := &IPRoutes{Executor: executor, IPExecutable: "/usr/sbin/ip", LANPrefix: "192.168.200.0/24", WireGuardPrefix: "10.80.0.0/24"}
	plan, err := networkplan.Build(networkplan.Input{LANPrefix: controller.LANPrefix, WireGuardPrefix: controller.WireGuardPrefix, Modems: []networkplan.ModemInput{{ID: "m1", InterfaceName: "enxm1", ManagementPrefix: "192.168.8.0/24", Gateway: "192.168.8.1", RoutingTableID: 1101, Fwmark: 0x1101}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.ApplyPlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := controller.RemoveModem(context.Background(), modem.Modem{ID: "m1", InterfaceName: "enxm1", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", RoutingTableID: 1101, Fwmark: 0x1101}); err != nil {
		t.Fatal(err)
	}
	if len(executor.requests) != 0 {
		t.Fatalf("dry controller executed %d commands", len(executor.requests))
	}
}
