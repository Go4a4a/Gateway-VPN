package modemrecovery

import (
	"context"
	"errors"
)

// Runner decouples USB hot-plug reconciliation from potentially slower root
// recovery actions. A full channel intentionally coalesces observations; the
// next periodic HiLink cycle supplies fresh authoritative state.
type Runner struct {
	Controller *Controller
	OnError    func(error)
	queue      chan ObservationBatch
}

func NewRunner(controller *Controller) *Runner {
	return &Runner{Controller: controller, queue: make(chan ObservationBatch, 1)}
}

func (runner *Runner) Submit(batch ObservationBatch) {
	if runner == nil {
		return
	}
	if runner.queue == nil {
		runner.queue = make(chan ObservationBatch, 1)
	}
	select {
	case runner.queue <- batch:
	default:
	}
}

func (runner *Runner) Run(ctx context.Context) error {
	if runner == nil || runner.Controller == nil {
		return errors.New("modem recovery controller is required")
	}
	if runner.queue == nil {
		runner.queue = make(chan ObservationBatch, 1)
	}
	if _, err := runner.Controller.RecoverInterrupted(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case batch := <-runner.queue:
			for _, err := range runner.Controller.Observe(ctx, batch) {
				if runner.OnError != nil {
					runner.OnError(err)
				}
			}
		}
	}
}
