package directprobe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gateway-vpn/internal/scheduler"
)

type RunnerConfig struct {
	PollInterval time.Duration
	RefreshLead  time.Duration
	DueLimit     int
	ProbeClass   string
}

type CycleResult struct {
	Due       int
	Probed    int
	Published int
	Deferred  int
	Errors    map[string]string
}

type Runner struct {
	Prober  *Prober
	Config  RunnerConfig
	OnCycle func(CycleResult)
	OnError func(error)
	now     func() time.Time

	mutex      sync.Mutex
	nextPathID string
}

func DefaultRunnerConfig() RunnerConfig {
	return RunnerConfig{PollInterval: time.Second, RefreshLead: 30 * time.Second, DueLimit: 2, ProbeClass: scheduler.ClassStandby}
}

func NewRunner(prober *Prober, configuration RunnerConfig) (*Runner, error) {
	runner := &Runner{Prober: prober, Config: configuration, now: time.Now}
	if err := runner.validate(); err != nil {
		return nil, err
	}
	return runner, nil
}

func (runner *Runner) Run(ctx context.Context) error {
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

func (runner *Runner) RunOnce(ctx context.Context) (CycleResult, error) {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	if err := runner.validate(); err != nil {
		return CycleResult{}, err
	}
	if err := runner.Prober.Paths.Reconcile(ctx); err != nil {
		return CycleResult{}, fmt.Errorf("reconcile direct paths before probe: %w", err)
	}
	paths, err := runner.Prober.Paths.List(ctx)
	if err != nil {
		return CycleResult{}, err
	}
	result := CycleResult{Errors: make(map[string]string)}
	var cycleErrors []error
	deadline := runner.now().UTC().Add(runner.Config.RefreshLead)
	dueIndexes := make([]int, 0, len(paths))
	for index, path := range paths {
		if path.State == "UPLINK_DISABLED" || path.State == "UPLINK_OFFLINE" || path.State == "SUBNET_CONFLICT" {
			continue
		}
		if path.ExpiresAt != "" {
			expiresAt, parseErr := time.Parse(time.RFC3339Nano, path.ExpiresAt)
			if parseErr == nil && expiresAt.After(deadline) {
				continue
			}
		}
		dueIndexes = append(dueIndexes, index)
	}
	result.Due = len(dueIndexes)
	if len(dueIndexes) == 0 {
		runner.nextPathID = ""
		return result, nil
	}
	start := 0
	for position, index := range dueIndexes {
		if paths[index].ID == runner.nextPathID {
			start = position
			break
		}
	}
	attempted := 0
	for attempted < runner.Config.DueLimit && attempted < len(dueIndexes) {
		path := paths[dueIndexes[(start+attempted)%len(dueIndexes)]]
		attempted++
		_, probeErr := runner.Prober.ProbePath(ctx, path.ID, runner.Config.ProbeClass)
		if errors.Is(probeErr, ErrDeferredBudget) {
			result.Deferred++
			continue
		}
		result.Probed++
		if probeErr != nil {
			result.Errors[path.ID] = stableCycleError(probeErr)
			cycleErrors = append(cycleErrors, fmt.Errorf("direct path %s: %w", path.ID, probeErr))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		result.Published++
	}
	runner.nextPathID = paths[dueIndexes[(start+attempted)%len(dueIndexes)]].ID
	return result, errors.Join(cycleErrors...)
}

// ProbeAllNow re-evaluates every eligible direct uplink even when its previous
// evidence is still fresh. It is intended for an explicit user action or a
// policy transition; the same mutex prevents it from racing the periodic
// runner and every probe still passes through the shared traffic budget.
func (runner *Runner) ProbeAllNow(ctx context.Context) (CycleResult, error) {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	if err := runner.validate(); err != nil {
		return CycleResult{}, err
	}
	if err := runner.Prober.Paths.Reconcile(ctx); err != nil {
		return CycleResult{}, fmt.Errorf("reconcile direct paths before manual probe: %w", err)
	}
	paths, err := runner.Prober.Paths.List(ctx)
	if err != nil {
		return CycleResult{}, err
	}
	result := CycleResult{Errors: make(map[string]string)}
	var cycleErrors []error
	for _, path := range paths {
		if path.State == "UPLINK_DISABLED" || path.State == "UPLINK_OFFLINE" || path.State == "SUBNET_CONFLICT" {
			continue
		}
		result.Due++
		_, probeErr := runner.Prober.ProbePath(ctx, path.ID, scheduler.ClassFailover)
		if errors.Is(probeErr, ErrDeferredBudget) {
			result.Deferred++
			continue
		}
		result.Probed++
		if probeErr != nil {
			result.Errors[path.ID] = stableCycleError(probeErr)
			cycleErrors = append(cycleErrors, fmt.Errorf("manual direct path %s: %w", path.ID, probeErr))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		result.Published++
	}
	return result, errors.Join(cycleErrors...)
}

func (runner *Runner) validate() error {
	if runner == nil || runner.Prober == nil || runner.now == nil || runner.Config.PollInterval <= 0 || runner.Config.RefreshLead < 0 || runner.Config.RefreshLead >= runner.Prober.EvidenceTTL || runner.Config.DueLimit <= 0 || runner.Config.DueLimit > 20 {
		return errors.New("direct probe runner configuration is invalid")
	}
	switch runner.Config.ProbeClass {
	case scheduler.ClassStandby, scheduler.ClassActive, scheduler.ClassFailover:
	default:
		return errors.New("direct probe runner class is invalid")
	}
	return runner.Prober.validate()
}

func stableCycleError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	default:
		return "DIRECT_PROBE_FAILED"
	}
}
