package firewall

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

type EventMonitor interface {
	Watch(context.Context) (<-chan struct{}, <-chan error, error)
}

type NFTMonitor struct {
	Executable string
}

func (monitor NFTMonitor) Watch(ctx context.Context) (<-chan struct{}, <-chan error, error) {
	if monitor.Executable != "/usr/sbin/nft" {
		return nil, nil, errors.New("fixed nft monitor executable is required")
	}
	command := exec.CommandContext(ctx, monitor.Executable, "monitor", "ruleset")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, errors.New("open nft monitor output failed")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return nil, nil, errors.New("start nft monitor failed")
	}
	events := make(chan struct{}, 1)
	errorsChannel := make(chan error, 1)
	go func() {
		defer close(events)
		defer close(errorsChannel)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			select {
			case events <- struct{}{}:
			default:
			}
		}
		scanErr := scanner.Err()
		waitErr := command.Wait()
		if ctx.Err() == nil {
			errorsChannel <- errors.Join(scanErr, waitErr)
		}
	}()
	return events, errorsChannel, nil
}

type GuardRunner struct {
	Guard          *Guard
	Monitor        EventMonitor
	PollInterval   time.Duration
	MonitorBackoff time.Duration
	OnResult       func(GuardResult)
	OnError        func(error)
}

func (runner *GuardRunner) Run(ctx context.Context) error {
	if runner == nil || runner.Guard == nil || runner.Monitor == nil || runner.pollInterval() < 10*time.Millisecond || runner.monitorBackoff() < 10*time.Millisecond {
		return errors.New("complete firewall guard runner is required")
	}
	ticker := time.NewTicker(runner.pollInterval())
	defer ticker.Stop()
	var events <-chan struct{}
	var monitorErrors <-chan error
	var retry <-chan time.Time
	startMonitor := func() {
		observed, failures, err := runner.Monitor.Watch(ctx)
		if err != nil {
			runner.reportError(err)
			retry = time.After(runner.monitorBackoff())
			return
		}
		events, monitorErrors, retry = observed, failures, nil
	}
	ensure := func() {
		result, err := runner.Guard.Ensure(ctx)
		if runner.OnResult != nil && (result.Recovered || result.Quarantined || !result.Healthy) {
			runner.OnResult(result)
		}
		if err != nil && ctx.Err() == nil {
			runner.reportError(err)
		}
	}
	ensure()
	startMonitor()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ensure()
		case _, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			ensure()
		case err, ok := <-monitorErrors:
			if ok && err != nil {
				runner.reportError(err)
			}
			monitorErrors = nil
			events = nil
			retry = time.After(runner.monitorBackoff())
		case <-retry:
			retry = nil
			startMonitor()
		}
	}
}

func (runner *GuardRunner) reportError(err error) {
	if runner.OnError != nil {
		runner.OnError(err)
	}
}

func (runner *GuardRunner) pollInterval() time.Duration {
	if runner.PollInterval > 0 {
		return runner.PollInterval
	}
	return 2 * time.Second
}

func (runner *GuardRunner) monitorBackoff() time.Duration {
	if runner.MonitorBackoff > 0 {
		return runner.MonitorBackoff
	}
	return 2 * time.Second
}
