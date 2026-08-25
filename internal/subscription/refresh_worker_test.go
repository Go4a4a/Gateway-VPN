package subscription

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRefreshWorkerUsesDurableDueAndStopsWithContext(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	fetcher := &queuedFetcher{results: []FetchResult{{Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one")}}}
	coordinator := testRefreshCoordinator(t, database, fetcher, &recordingRuntime{})
	worker := &RefreshWorker{Coordinator: coordinator, Subscriptions: NewRepository(database), Interval: 10 * time.Millisecond}
	if err := worker.Run(ctx); err == nil {
		t.Fatal("Run(invalid interval) error = nil")
	}
	worker.runOnce(ctx)
	if len(fetcher.options) != 1 {
		t.Fatalf("scheduled fetch count = %d", len(fetcher.options))
	}
	worker.Interval = time.Second
	runContext, cancel := context.WithCancel(ctx)
	cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Run(runContext) }()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	state, err := NewRefreshRepository(database).Get(ctx, "sub-a")
	if err != nil || state.NextAttemptAt == "" || state.LeaseOwner != "" {
		t.Fatalf("durable refresh state = %+v, %v", state, err)
	}
}

func TestRefreshWorkerReportsRealFailureButIgnoresNotDue(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	fetcher := &queuedFetcher{results: []FetchResult{{}}, errors: []error{errors.New("network down")}}
	coordinator := testRefreshCoordinator(t, database, fetcher, &recordingRuntime{})
	var reported int
	worker := &RefreshWorker{Coordinator: coordinator, Subscriptions: NewRepository(database), OnError: func(string, error) { reported++ }}
	worker.runOnce(ctx)
	if reported != 1 {
		t.Fatalf("reported failures = %d", reported)
	}
	worker.runOnce(ctx)
	if reported != 1 {
		t.Fatalf("not-due refresh was reported, failures = %d", reported)
	}
}
