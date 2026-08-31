// Package managementruntime persists a bounded, secret-free projection of
// root-observed Management Fabric WireGuard handshakes.
package managementruntime

import (
	"context"
	"errors"
	"time"

	"gateway-vpn/internal/managementfabric"
	"gateway-vpn/internal/networkapply"
)

const defaultInterval = 15 * time.Second

var ErrObservationUnavailable = errors.New("management fabric runtime observation is unavailable")

type Source interface {
	ManagementFabricStatus(context.Context) (networkapply.ManagementFabricStatus, error)
}

type Result struct {
	ObservationState string
	ObservedLinks    int
	ExpiredLinks     int64
}

type Runner struct {
	Source     Source
	Repository *managementfabric.Repository
	Interval   time.Duration
	Now        func() time.Time
	OnCycle    func(Result)
	OnError    func(error)
}

func (runner *Runner) Run(ctx context.Context) error {
	if err := runner.validate(); err != nil {
		return err
	}
	interval := runner.Interval
	if interval == 0 {
		interval = defaultInterval
	}
	if interval < 5*time.Second || interval > 5*time.Minute {
		return errors.New("management runtime observer interval is outside the supported range")
	}
	runner.runCycle(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			runner.runCycle(ctx)
		}
	}
}

func (runner *Runner) Reconcile(ctx context.Context) (Result, error) {
	if err := runner.validate(); err != nil {
		return Result{}, err
	}
	now := runner.now()
	requestContext, cancel := context.WithTimeout(ctx, 8*time.Second)
	status, sourceErr := runner.Source.ManagementFabricStatus(requestContext)
	cancel()
	expired, expireErr := runner.Repository.ExpireLinkRuntimeObservations(ctx, now)
	result := Result{ObservationState: status.ObservationState, ExpiredLinks: expired}
	if expireErr != nil {
		return result, expireErr
	}
	if sourceErr != nil {
		return result, ErrObservationUnavailable
	}
	switch status.ObservationState {
	case "AVAILABLE":
		if err := runner.Repository.RecordLinkRuntimeObservations(ctx, status.ObservationGeneration, status.Links, now); err != nil {
			return result, err
		}
		result.ObservedLinks = len(status.Links)
		return result, nil
	case "DEFERRED":
		return result, nil
	case "UNAVAILABLE":
		return result, ErrObservationUnavailable
	default:
		return result, errors.New("management fabric runtime observation state is invalid")
	}
}

func (runner *Runner) runCycle(ctx context.Context) {
	result, err := runner.Reconcile(ctx)
	if runner.OnCycle != nil {
		runner.OnCycle(result)
	}
	if err != nil && !errors.Is(err, context.Canceled) && runner.OnError != nil {
		runner.OnError(err)
	}
}

func (runner *Runner) validate() error {
	if runner == nil || runner.Source == nil || runner.Repository == nil || runner.Repository.Database == nil {
		return errors.New("management runtime observer dependencies are incomplete")
	}
	return nil
}

func (runner *Runner) now() time.Time {
	if runner.Now != nil {
		return runner.Now().UTC()
	}
	return time.Now().UTC()
}
