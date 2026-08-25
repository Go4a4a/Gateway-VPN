package app

import (
	"context"
	"testing"
	"time"
)

type appLoggingSynchronizer struct {
	calls chan struct{}
}

func (synchronizer *appLoggingSynchronizer) SyncLogging(context.Context) error {
	select {
	case synchronizer.calls <- struct{}{}:
	default:
	}
	return nil
}

func TestLoggingSyncLoopConvergesImmediatelyAndStopsWithContext(t *testing.T) {
	synchronizer := &appLoggingSynchronizer{calls: make(chan struct{}, 1)}
	runtime := &Runtime{LoggingSync: synchronizer}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.runLoggingSyncLoop(ctx) }()
	select {
	case <-synchronizer.calls:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("logging sync loop did not converge immediately")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runLoggingSyncLoop() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("logging sync loop did not stop")
	}
}
