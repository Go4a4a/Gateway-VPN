package hilink

import (
	"context"
	"errors"
	"time"
)

type Reconciler interface {
	Reconcile(context.Context) (CycleResult, error)
}

type LinkWatcher interface {
	Watch(context.Context, chan<- struct{}) error
}

type Runner struct {
	Manager           Reconciler
	Watcher           LinkWatcher
	ReconcileInterval time.Duration
	OnCycle           func(CycleResult)
	OnError           func(error)
}

func (runner *Runner) Run(ctx context.Context) error {
	if runner == nil || runner.Manager == nil || runner.Watcher == nil {
		return errors.New("HiLink runner manager and link watcher are required")
	}
	interval := runner.ReconcileInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	if interval < 500*time.Millisecond || interval > time.Minute {
		return errors.New("HiLink reconciliation interval must be 500ms..1m")
	}
	events := make(chan struct{}, 1)
	watcherErrors := make(chan error, 1)
	go func() { watcherErrors <- runner.Watcher.Watch(ctx, events) }()
	reconcile := func() {
		result, err := runner.Manager.Reconcile(ctx)
		if err != nil {
			if ctx.Err() == nil && runner.OnError != nil {
				runner.OnError(err)
			}
			return
		}
		if runner.OnCycle != nil {
			runner.OnCycle(result)
		}
	}
	reconcile()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-events:
			reconcile()
		case err := <-watcherErrors:
			if err != nil && ctx.Err() == nil && runner.OnError != nil {
				runner.OnError(err)
			}
			watcherErrors = nil
		case <-ticker.C:
			reconcile()
		}
	}
}
