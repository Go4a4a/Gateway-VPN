package subscription

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"gateway-vpn/internal/operations"
)

type blockingRefreshFetcher struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (fetcher *blockingRefreshFetcher) Fetch(ctx context.Context, _ string, _ FetchOptions) (FetchResult, error) {
	if fetcher.calls.Add(1) == 1 {
		close(fetcher.started)
	}
	select {
	case <-fetcher.release:
		return FetchResult{Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one")}, nil
	case <-ctx.Done():
		return FetchResult{}, ctx.Err()
	}
}

func TestRefreshDispatcherReturnsDurableIDAndJoinsSingleFlight(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	fetcher := &blockingRefreshFetcher{started: make(chan struct{}), release: make(chan struct{})}
	coordinator := testRefreshCoordinator(t, database, fetcher, &recordingRuntime{})
	dispatcher, err := NewRefreshDispatcher(coordinator, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	runContext, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- dispatcher.Run(runContext) }()
	if err := dispatcher.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}

	first, err := dispatcher.Enqueue(ctx, "sub-a", "USER:admin")
	if err != nil || first.OperationID == "" || first.Joined {
		t.Fatalf("first Enqueue() = %+v, %v", first, err)
	}
	select {
	case <-fetcher.started:
	case <-time.After(time.Second):
		t.Fatal("refresh worker did not start")
	}
	second, err := dispatcher.Enqueue(ctx, "sub-a", "USER:admin")
	if err != nil || !second.Joined || second.OperationID != first.OperationID {
		t.Fatalf("joined Enqueue() = %+v, %v, want %s", second, err, first.OperationID)
	}
	if fetcher.calls.Load() != 1 {
		t.Fatalf("parallel source fetches = %d", fetcher.calls.Load())
	}
	close(fetcher.release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		operation, getErr := coordinator.Operations.Get(ctx, first.OperationID, true)
		if getErr == nil && operation.Status == operations.StatusSucceeded {
			if operation.RequestedBy != "USER:admin" || operation.SummaryCode != "REFRESH_COMPLETE" {
				t.Fatalf("completed operation = %+v", operation)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation did not complete: %+v, %v", operation, getErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("dispatcher Run() = %v", err)
	}
}

func TestRefreshDispatcherRecoversInterruptedPreparedOperation(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	coordinator := testRefreshCoordinator(t, database, &queuedFetcher{}, &recordingRuntime{})
	prepared, joined, err := coordinator.PrepareRefresh(ctx, "sub-a", true, false, "USER:admin")
	if err != nil || joined {
		t.Fatalf("PrepareRefresh() = %+v, %t, %v", prepared, joined, err)
	}
	dispatcher, err := NewRefreshDispatcher(coordinator, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	runContext, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- dispatcher.Run(runContext) }()
	if err := dispatcher.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Refresh.Get(ctx, "sub-a")
	if err != nil || state.LeaseOwner != "" {
		t.Fatalf("recovered refresh state = %+v, %v", state, err)
	}
	operation, err := coordinator.Operations.Get(ctx, prepared.OperationID, false)
	if err != nil || operation.Status != operations.StatusFailed || operation.SummaryCode != "PROCESS_RESTART" {
		t.Fatalf("recovered operation = %+v, %v", operation, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
