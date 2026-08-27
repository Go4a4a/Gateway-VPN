package subscription

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrRefreshDispatcherBusy = errors.New("subscription refresh dispatcher is busy")

type DispatchResult struct {
	OperationID    string
	SubscriptionID string
	Joined         bool
}

// RefreshDispatcher is a bounded bridge between HTTP requests and durable
// refresh transactions. It never retains request contexts after Enqueue.
type RefreshDispatcher struct {
	Coordinator *RefreshCoordinator
	Workers     int
	Capacity    int

	mu      sync.RWMutex
	started bool
	queue   chan PreparedRefresh
	slots   chan struct{}
	ready   chan error
}

func NewRefreshDispatcher(coordinator *RefreshCoordinator, workers, capacity int) (*RefreshDispatcher, error) {
	if coordinator == nil || workers < 1 || workers > 8 || capacity < workers || capacity > 256 {
		return nil, errors.New("refresh dispatcher requires coordinator, 1..8 workers, and bounded capacity")
	}
	return &RefreshDispatcher{Coordinator: coordinator, Workers: workers, Capacity: capacity, queue: make(chan PreparedRefresh, capacity), slots: make(chan struct{}, capacity), ready: make(chan error, 1)}, nil
}

// Run owns the worker lifecycle. It recovers only previous-process jobs before
// accepting new work and then blocks until ctx is cancelled.
func (dispatcher *RefreshDispatcher) Run(ctx context.Context) error {
	if dispatcher == nil || dispatcher.Coordinator == nil || dispatcher.queue == nil || dispatcher.slots == nil {
		return errors.New("refresh dispatcher is not configured")
	}
	dispatcher.mu.Lock()
	if dispatcher.started {
		dispatcher.mu.Unlock()
		return errors.New("refresh dispatcher is already running")
	}
	if _, err := dispatcher.Coordinator.Refresh.ReleaseInterrupted(ctx); err != nil {
		dispatcher.mu.Unlock()
		dispatcher.ready <- err
		return err
	}
	if _, err := dispatcher.Coordinator.Operations.FailInterrupted(ctx, []string{"SUBSCRIPTION_REFRESH", "SUBSCRIPTION_RECLASSIFY"}, "PROCESS_RESTART"); err != nil {
		dispatcher.mu.Unlock()
		dispatcher.ready <- err
		return err
	}
	dispatcher.started = true
	dispatcher.mu.Unlock()
	dispatcher.ready <- nil

	var workers sync.WaitGroup
	for index := 0; index < dispatcher.Workers; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			dispatcher.worker(ctx)
		}()
	}
	<-ctx.Done()
	dispatcher.mu.Lock()
	dispatcher.started = false
	dispatcher.mu.Unlock()
	workers.Wait()
	return nil
}

func (dispatcher *RefreshDispatcher) WaitReady(ctx context.Context) error {
	if dispatcher == nil || dispatcher.ready == nil {
		return errors.New("refresh dispatcher is not configured")
	}
	select {
	case err := <-dispatcher.ready:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (dispatcher *RefreshDispatcher) Enqueue(ctx context.Context, subscriptionID, requestedBy string) (DispatchResult, error) {
	if dispatcher == nil || dispatcher.Coordinator == nil {
		return DispatchResult{}, errors.New("refresh dispatcher is not configured")
	}
	dispatcher.mu.RLock()
	started := dispatcher.started
	dispatcher.mu.RUnlock()
	if !started {
		return DispatchResult{}, errors.New("refresh dispatcher is not running")
	}
	// Reserve bounded capacity before acquiring a durable lease.
	select {
	case dispatcher.slots <- struct{}{}:
	default:
		return DispatchResult{}, ErrRefreshDispatcherBusy
	}
	prepared, joined, err := dispatcher.Coordinator.PrepareRefresh(ctx, subscriptionID, true, false, requestedBy)
	if err != nil {
		<-dispatcher.slots
		return DispatchResult{}, err
	}
	if joined {
		<-dispatcher.slots
		return DispatchResult{OperationID: prepared.OperationID, SubscriptionID: subscriptionID, Joined: true}, nil
	}
	select {
	case dispatcher.queue <- prepared:
		return DispatchResult{OperationID: prepared.OperationID, SubscriptionID: subscriptionID}, nil
	case <-ctx.Done():
		<-dispatcher.slots
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = dispatcher.Coordinator.CancelPrepared(cleanup, prepared, "REQUEST_CANCELLED")
		return DispatchResult{}, ctx.Err()
	}
}

func (dispatcher *RefreshDispatcher) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			dispatcher.cancelQueued()
			return
		case prepared := <-dispatcher.queue:
			_, _ = dispatcher.Coordinator.ExecutePrepared(ctx, prepared)
			<-dispatcher.slots
		}
	}
}

func (dispatcher *RefreshDispatcher) cancelQueued() {
	for {
		select {
		case prepared := <-dispatcher.queue:
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = dispatcher.Coordinator.CancelPrepared(cleanup, prepared, "PROCESS_STOPPING")
			cancel()
			<-dispatcher.slots
		default:
			return
		}
	}
}
