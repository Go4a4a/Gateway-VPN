package hilink

import (
	"context"
	"errors"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/networkplan"
)

type RoutingSynchronizer interface {
	SyncRouting(context.Context) error
}

// AuthoritativeRoutes deliberately ignores caller-supplied route arguments.
// The root broker rebuilds the plan from SQLite after each modem state change.
type AuthoritativeRoutes struct {
	Broker RoutingSynchronizer
}

func (routes AuthoritativeRoutes) ApplyPlan(ctx context.Context, plan networkplan.Plan) error {
	if routes.Broker == nil || plan.Owner != networkplan.Owner {
		return errors.New("authoritative routing broker and owned plan are required")
	}
	return routes.Broker.SyncRouting(ctx)
}

func (routes AuthoritativeRoutes) RemoveModem(ctx context.Context, record modem.Modem) error {
	if routes.Broker == nil || record.ID == "" {
		return errors.New("authoritative routing broker and modem identity are required")
	}
	return routes.Broker.SyncRouting(ctx)
}
