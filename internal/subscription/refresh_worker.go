package subscription

import (
	"context"
	"errors"
	"time"
)

// RefreshWorker periodically asks every auto-refresh subscription to refresh
// without force. User-routing enablement is intentionally independent: a
// disabled route must still keep its LKG current when auto_refresh is enabled.
// Durable due times and leases in RefreshRepository are authoritative, so
// restart and concurrent manual refresh remain safe.
type RefreshWorker struct {
	Coordinator   *RefreshCoordinator
	Subscriptions *Repository
	Interval      time.Duration
	OnError       func(string, error)
	OnCycle       func()
}

func (worker *RefreshWorker) Run(ctx context.Context) error {
	if worker == nil || worker.Coordinator == nil || worker.Subscriptions == nil {
		return errors.New("subscription refresh worker dependencies are incomplete")
	}
	interval := worker.Interval
	if interval == 0 {
		interval = 30 * time.Second
	}
	if interval < time.Second || interval > 10*time.Minute {
		return errors.New("subscription refresh worker interval must be between one second and ten minutes")
	}
	worker.runCycle(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			worker.runCycle(ctx)
		}
	}
}

func (worker *RefreshWorker) runCycle(ctx context.Context) {
	worker.runOnce(ctx)
	if worker.OnCycle != nil {
		worker.OnCycle()
	}
}

func (worker *RefreshWorker) runOnce(ctx context.Context) {
	items, err := worker.Subscriptions.List(ctx)
	if err != nil {
		worker.report("", err)
		return
	}
	for _, item := range items {
		if !item.AutoRefresh || item.SourceType != "url" {
			continue
		}
		_, err := worker.Coordinator.RefreshOne(ctx, item.ID, false)
		if err == nil || errors.Is(err, ErrRefreshNotDue) || errors.Is(err, ErrRefreshInProgress) {
			continue
		}
		worker.report(item.ID, err)
		if ctx.Err() != nil {
			return
		}
	}
}

func (worker *RefreshWorker) report(subscriptionID string, err error) {
	if worker.OnError != nil {
		worker.OnError(subscriptionID, err)
	}
}
