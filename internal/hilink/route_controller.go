package hilink

import (
	"context"
	"errors"
	"sync"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkplan"
	"gateway-vpn/internal/platformexec"
	"gateway-vpn/internal/routing"
)

type IPRoutes struct {
	Executor        platformexec.Executor
	IPExecutable    string
	LANPrefix       string
	WireGuardPrefix string
	Mutate          bool

	mutex       sync.Mutex
	currentPlan networkplan.Plan
}

func (controller *IPRoutes) ApplyPlan(ctx context.Context, plan networkplan.Plan) error {
	if controller.Executor == nil || controller.IPExecutable == "" {
		return errors.New("ip route controller executor and executable are required")
	}
	operations, err := routing.Render(plan, controller.IPExecutable)
	if err != nil {
		return err
	}
	if err := routing.Apply(ctx, controller.Executor, operations, routing.ApplyOptions{Mutate: controller.Mutate}); err != nil {
		return err
	}
	controller.mutex.Lock()
	controller.currentPlan = plan
	controller.mutex.Unlock()
	return nil
}

func (controller *IPRoutes) RemoveModem(ctx context.Context, record modem.Modem) error {
	if record.InterfaceName == "" || record.ManagementCIDR == "" || record.Gateway == "" {
		return nil
	}
	controller.mutex.Lock()
	plan := controller.currentPlan
	controller.mutex.Unlock()
	found := false
	for _, route := range plan.Routes {
		if route.ModemID == record.ID {
			found = true
			break
		}
	}
	if !found {
		var err error
		plan, err = networkplan.Build(networkplan.Input{LANPrefix: controller.LANPrefix, WireGuardPrefix: controller.WireGuardPrefix, Modems: []networkplan.ModemInput{{ID: record.ID, Priority: record.Priority, InterfaceName: record.InterfaceName, ManagementPrefix: record.ManagementCIDR, Gateway: record.Gateway, RoutingTableID: record.RoutingTableID, Fwmark: record.Fwmark}}})
		if err != nil {
			return err
		}
	}
	operations, err := routing.RenderRemoval(plan, record.ID, controller.IPExecutable)
	if err != nil {
		return err
	}
	return routing.Apply(ctx, controller.Executor, operations, routing.ApplyOptions{Mutate: controller.Mutate})
}
