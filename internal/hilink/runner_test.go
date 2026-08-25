package hilink

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type runnerManager struct {
	mutex sync.Mutex
	calls int
}

func (manager *runnerManager) Reconcile(context.Context) (CycleResult, error) {
	manager.mutex.Lock()
	manager.calls++
	manager.mutex.Unlock()
	return CycleResult{ReadyModems: []string{"modem-a"}}, nil
}

func (manager *runnerManager) count() int {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	return manager.calls
}

type runnerWatcher struct {
	err error
}

func (watcher runnerWatcher) Watch(ctx context.Context, events chan<- struct{}) error {
	events <- struct{}{}
	if watcher.err != nil {
		return watcher.err
	}
	<-ctx.Done()
	return nil
}

func TestRunnerReconcilesImmediatelyAndOnLinkEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager := &runnerManager{}
	cycles := make(chan struct{}, 2)
	runner := &Runner{
		Manager: manager, Watcher: runnerWatcher{}, ReconcileInterval: time.Minute,
		OnCycle: func(CycleResult) {
			select {
			case cycles <- struct{}{}:
			default:
			}
			if manager.count() >= 2 {
				cancel()
			}
		},
	}
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not reconcile link event")
	}
	if manager.count() < 2 {
		t.Fatalf("reconcile calls = %d, want immediate+event", manager.count())
	}
}

func TestRunnerReportsWatcherFailureAndKeepsPolling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsSeen := make(chan error, 1)
	runner := &Runner{Manager: &runnerManager{}, Watcher: runnerWatcher{err: errors.New("netlink failed")}, ReconcileInterval: 500 * time.Millisecond, OnError: func(err error) { errorsSeen <- err }}
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-errorsSeen:
		cancel()
	case <-time.After(2 * time.Second):
		t.Fatal("watcher failure was not reported")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
