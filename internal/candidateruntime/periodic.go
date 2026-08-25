package candidateruntime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gateway-vpn/internal/health"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/state"
)

type PeriodicConfig struct {
	PollInterval      time.Duration
	ActiveInterval    time.Duration
	StandbyInterval   time.Duration
	FailureThreshold  int
	SuccessThreshold  int
	JitterPercent     int
	DueLimit          int
	ConfirmationLimit int
}

type PeriodicCycleResult struct {
	Due              int
	Probed           int
	Deferred         int
	Published        int
	OutageSuppressed int
	Errors           map[string]string
}

type PeriodicRunner struct {
	Runtime   *Runtime
	Schedules health.PeriodicRepository
	Paths     *pathmatrix.Repository
	State     *state.Repository
	Reconcile func(context.Context) (any, error)
	Config    PeriodicConfig
	OnCycle   func(PeriodicCycleResult)
	OnError   func(error)
}

func DefaultPeriodicConfig() PeriodicConfig {
	return PeriodicConfig{
		PollInterval: time.Second, ActiveInterval: 10 * time.Second,
		StandbyInterval: 60 * time.Second, FailureThreshold: 3,
		SuccessThreshold: 2, JitterPercent: 20, DueLimit: 4,
		ConfirmationLimit: 4,
	}
}

func (runner *PeriodicRunner) Run(ctx context.Context) error {
	if err := runner.validate(); err != nil {
		return err
	}
	ticker := time.NewTicker(runner.Config.PollInterval)
	defer ticker.Stop()
	for {
		result, err := runner.RunOnce(ctx)
		if runner.OnCycle != nil {
			runner.OnCycle(result)
		}
		if err != nil && ctx.Err() == nil && runner.OnError != nil {
			runner.OnError(err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (runner *PeriodicRunner) RunOnce(ctx context.Context) (PeriodicCycleResult, error) {
	if err := runner.validate(); err != nil {
		return PeriodicCycleResult{}, err
	}
	snapshot, err := runner.State.Get(ctx)
	if err != nil {
		return PeriodicCycleResult{}, fmt.Errorf("read runtime for periodic health: %w", err)
	}
	activePathID := ""
	if snapshot.PathState == state.PathActive {
		activePathID = snapshot.ActivePathID
	}
	if err := runner.Schedules.Reconcile(ctx, activePathID); err != nil {
		return PeriodicCycleResult{}, err
	}
	due, err := runner.Schedules.Due(ctx, runner.Config.DueLimit)
	if err != nil {
		return PeriodicCycleResult{}, err
	}
	result := PeriodicCycleResult{Due: len(due), Errors: make(map[string]string)}
	var cycleErrors []error
	for _, item := range due {
		var operationErr error
		if item.ProbeClass == health.ProbeClassActive && item.PathID == snapshot.ActivePathID && snapshot.ActiveNodeID != "" {
			operationErr = runner.processActive(ctx, snapshot, item, &result)
		} else {
			operationErr = runner.processStandby(ctx, item, &result)
		}
		if operationErr != nil {
			result.Errors[item.PathID] = operationErr.Error()
			cycleErrors = append(cycleErrors, fmt.Errorf("periodic path %s: %w", item.PathID, operationErr))
			interval := runner.interval(item.ProbeClass)
			_, _ = runner.Schedules.Defer(ctx, item.PathID, "OPERATION_ERROR", interval, runner.Config.JitterPercent)
		}
	}
	return result, errors.Join(cycleErrors...)
}

func (runner *PeriodicRunner) processActive(ctx context.Context, snapshot state.Snapshot, due health.DuePath, cycle *PeriodicCycleResult) error {
	if snapshot.PolicyTransitionActive() {
		operation, err := runner.Runtime.periodicQualifyPath(ctx, due.PathID, scheduler.ClassFailover, true)
		if err != nil {
			return err
		}
		cycle.Probed++
		status := health.PeriodicFailed
		if operation.Result.State == health.CellQualified {
			status = health.PeriodicPassed
		}
		if _, err := runner.Schedules.Record(ctx, due.PathID, status, runner.Config.ActiveInterval, runner.Config.JitterPercent); err != nil {
			return err
		}
		if err := runner.Schedules.Acknowledge(ctx, due.PathID); err != nil {
			return err
		}
		cycle.Published++
		return runner.reconcile(ctx)
	}
	operation, err := runner.Runtime.periodicProbeNode(ctx, due.PathID, snapshot.ActiveNodeID, scheduler.ClassActive)
	if err != nil {
		return err
	}
	cycle.Probed++
	passed := operation.Result.State == health.CellQualified
	periodicResult := health.PeriodicFailed
	if passed {
		periodicResult = health.PeriodicPassed
	}
	status, err := runner.Schedules.Record(ctx, due.PathID, periodicResult, runner.Config.ActiveInterval, runner.Config.JitterPercent)
	if err != nil {
		return err
	}
	if passed && status.Successes >= runner.Config.SuccessThreshold {
		published, err := runner.Runtime.periodicQualifyNode(ctx, due.PathID, snapshot.ActiveNodeID, scheduler.ClassActive, true)
		if err != nil {
			return err
		}
		if published.DeferredReason != "" {
			cycle.Deferred++
			_, err = runner.Schedules.Defer(ctx, due.PathID, published.DeferredReason, runner.Config.ActiveInterval, runner.Config.JitterPercent)
			return err
		}
		if err := runner.Schedules.Acknowledge(ctx, due.PathID); err != nil {
			return err
		}
		cycle.Published++
		return runner.reconcile(ctx)
	}
	if !passed && status.Failures >= runner.Config.FailureThreshold {
		if err := runner.handleActiveFailure(ctx, operation, cycle); err != nil {
			return err
		}
		return runner.Schedules.Acknowledge(ctx, due.PathID)
	}
	return nil
}

func (runner *PeriodicRunner) processStandby(ctx context.Context, due health.DuePath, cycle *PeriodicCycleResult) error {
	operation, err := runner.Runtime.periodicProbePath(ctx, due.PathID, scheduler.ClassStandby, false)
	if err != nil {
		return err
	}
	cycle.Probed++
	if deferred := deferredReason(operation.Result); deferred != "" && operation.Result.State != health.CellQualified {
		cycle.Deferred++
		_, err := runner.Schedules.Defer(ctx, due.PathID, deferred, runner.Config.StandbyInterval, runner.Config.JitterPercent)
		return err
	}
	periodicResult := health.PeriodicFailed
	if operation.Result.State == health.CellQualified {
		periodicResult = health.PeriodicPassed
	}
	status, err := runner.Schedules.Record(ctx, due.PathID, periodicResult, runner.Config.StandbyInterval, runner.Config.JitterPercent)
	if err != nil {
		return err
	}
	thresholdReached := periodicResult == health.PeriodicPassed && status.Successes >= runner.Config.SuccessThreshold ||
		periodicResult == health.PeriodicFailed && status.Failures >= runner.Config.FailureThreshold
	if !thresholdReached {
		return nil
	}
	published, err := runner.Runtime.periodicQualifyPath(ctx, due.PathID, scheduler.ClassStandby, false)
	if err != nil {
		return err
	}
	if published.DeferredReason != "" {
		cycle.Deferred++
		_, err = runner.Schedules.Defer(ctx, due.PathID, published.DeferredReason, runner.Config.StandbyInterval, runner.Config.JitterPercent)
		return err
	}
	if err := runner.Schedules.Acknowledge(ctx, due.PathID); err != nil {
		return err
	}
	cycle.Published++
	return runner.reconcile(ctx)
}

func (runner *PeriodicRunner) handleActiveFailure(ctx context.Context, operation PathOperationResult, cycle *PeriodicCycleResult) error {
	if operation.Result.TransportState != health.ProbePassed {
		if _, err := runner.Runtime.periodicQualifyPath(ctx, operation.PathID, scheduler.ClassFailover, false); err != nil {
			return err
		}
		cycle.Published++
		return runner.reconcile(ctx)
	}
	failedTargets := failedRequiredTargets(operation)
	if len(failedTargets) == 0 {
		if _, err := runner.Runtime.periodicQualifyPath(ctx, operation.PathID, scheduler.ClassFailover, true); err != nil {
			return err
		}
		cycle.Published++
		return runner.reconcile(ctx)
	}
	confirmedProbes, confirmedDeferred, err := runner.confirmStandbyPaths(ctx, operation.PathID)
	cycle.Probed += confirmedProbes
	cycle.Deferred += confirmedDeferred
	if err != nil {
		return err
	}
	allSuspect := true
	for _, targetID := range failedTargets {
		assessment, err := runner.Runtime.evaluateTargetObservation(ctx, targetID, operation.Result.ModemID, operation.Result.SubscriptionID, false)
		if err != nil {
			return err
		}
		if assessment.State != health.TargetSuspect {
			allSuspect = false
		}
	}
	if allSuspect {
		if err := runner.Runtime.publishTargetDegraded(ctx, operation); err != nil {
			return err
		}
		cycle.Published++
		cycle.OutageSuppressed++
		return runner.reconcile(ctx)
	}
	if _, err := runner.Runtime.periodicQualifyPath(ctx, operation.PathID, scheduler.ClassFailover, true); err != nil {
		return err
	}
	cycle.Published++
	return runner.reconcile(ctx)
}

func (runner *PeriodicRunner) confirmStandbyPaths(ctx context.Context, activePathID string) (int, int, error) {
	items, err := runner.Paths.List(ctx)
	if err != nil {
		return 0, 0, err
	}
	confirmed, probed, deferred := 0, 0, 0
	for _, item := range items {
		if item.ID == activePathID || confirmed >= runner.Config.ConfirmationLimit {
			continue
		}
		switch item.State {
		case pathmatrix.StateModemOffline, pathmatrix.StateModemDisabled, pathmatrix.StateSubscriptionDisabled:
			continue
		}
		operation, err := runner.Runtime.periodicQualifyPath(ctx, item.ID, scheduler.ClassFailover, true)
		if errors.Is(err, ErrPathNotReady) {
			continue
		}
		if err != nil {
			return probed, deferred, err
		}
		probed++
		if operation.DeferredReason != "" {
			deferred++
			continue
		}
		confirmed++
	}
	return probed, deferred, nil
}

func failedRequiredTargets(operation PathOperationResult) []string {
	if len(operation.Result.Nodes) != 1 {
		return nil
	}
	var result []string
	for _, target := range operation.Result.Nodes[0].Targets {
		if target.Required && target.State != health.ProbePassed {
			result = append(result, target.TargetID)
		}
	}
	return result
}

func (runner *PeriodicRunner) reconcile(ctx context.Context) error {
	if runner.Reconcile == nil {
		return nil
	}
	_, err := runner.Reconcile(ctx)
	return err
}

func (runner *PeriodicRunner) interval(probeClass string) time.Duration {
	if probeClass == health.ProbeClassActive {
		return runner.Config.ActiveInterval
	}
	return runner.Config.StandbyInterval
}

func (runner *PeriodicRunner) validate() error {
	config := runner.Config
	if runner == nil || runner.Runtime == nil || runner.Paths == nil || runner.State == nil || runner.Schedules.Database == nil {
		return errors.New("complete periodic health dependencies are required")
	}
	if config.PollInterval <= 0 || config.ActiveInterval <= 0 || config.StandbyInterval <= 0 ||
		config.FailureThreshold <= 0 || config.SuccessThreshold <= 0 || config.JitterPercent < 0 || config.JitterPercent > 50 ||
		config.DueLimit <= 0 || config.DueLimit > 100 || config.ConfirmationLimit <= 0 || config.ConfirmationLimit > 20 {
		return errors.New("invalid periodic health configuration")
	}
	return nil
}
