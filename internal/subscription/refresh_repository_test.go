package subscription

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestRefreshRepositoryDurableLeaseScheduleAndSuccess(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	repository := NewRefreshRepository(database)
	clock := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	repository.now = func() time.Time { return clock }

	lease, err := repository.Acquire(ctx, "sub-a", "worker-1", 5*time.Minute, false)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if lease.Subscription.ID != "sub-a" || lease.ConsecutiveFailures != 0 {
		t.Fatalf("Acquire() = %+v", lease)
	}
	if _, err := repository.Acquire(ctx, "sub-a", "worker-2", 5*time.Minute, true); !errors.Is(err, ErrRefreshInProgress) {
		t.Fatalf("parallel Acquire() error = %v", err)
	}

	next := clock.Add(time.Hour)
	if err := repository.FinishSuccess(ctx, lease, `"cache-v1"`, "today", next); err != nil {
		t.Fatalf("FinishSuccess() error = %v", err)
	}
	state, err := repository.Get(ctx, "sub-a")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if state.ETag != `"cache-v1"` || state.LastModified != "today" || state.ConsecutiveFailures != 0 || state.LeaseOwner != "" || state.NextAttemptAt != next.Format(time.RFC3339Nano) {
		t.Fatalf("state after success = %+v", state)
	}
	if _, err := repository.Acquire(ctx, "sub-a", "worker-2", 5*time.Minute, false); !errors.Is(err, ErrRefreshNotDue) {
		t.Fatalf("early scheduled Acquire() error = %v", err)
	}
	if _, err := repository.Acquire(ctx, "sub-a", "worker-2", 5*time.Minute, true); err != nil {
		t.Fatalf("forced Acquire() error = %v", err)
	}
}

func TestRefreshRepositoryExpiredLeaseAndFailureBackoffState(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "sub-a", "url")
	repository := NewRefreshRepository(database)
	clock := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	repository.now = func() time.Time { return clock }

	first, err := repository.Acquire(ctx, "sub-a", "crashed-worker", time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Minute)
	second, err := repository.Acquire(ctx, "sub-a", "recovery-worker", time.Minute, true)
	if err != nil {
		t.Fatalf("Acquire(after expiry) error = %v", err)
	}
	if err := repository.FinishFailure(ctx, first, "FETCH_FAILED", clock.Add(time.Minute)); !errors.Is(err, ErrRefreshLeaseLost) {
		t.Fatalf("stale FinishFailure() error = %v", err)
	}
	if err := repository.FinishFailure(ctx, second, "FETCH_FAILED", clock.Add(5*time.Minute)); err != nil {
		t.Fatalf("FinishFailure() error = %v", err)
	}
	state, err := repository.Get(ctx, "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.ConsecutiveFailures != 1 || state.LastErrorCode != "FETCH_FAILED" || state.ETag != "" || state.LeaseOwner != "" {
		t.Fatalf("state after failure = %+v", state)
	}

	clock = clock.Add(6 * time.Minute)
	third, err := repository.Acquire(ctx, "sub-a", "worker-3", time.Minute, false)
	if err != nil {
		t.Fatalf("Acquire(after backoff) error = %v", err)
	}
	if third.ConsecutiveFailures != 1 {
		t.Fatalf("failure history = %d, want 1", third.ConsecutiveFailures)
	}
}

func TestRefreshRepositoryRejectsDisabledAndUploadSources(t *testing.T) {
	ctx, database := migratedDatabase(t)
	createRefreshableSubscription(t, ctx, database, "disabled", "url")
	createRefreshableSubscription(t, ctx, database, "upload", "upload")
	if _, err := database.ExecContext(ctx, "UPDATE subscriptions SET enabled=0 WHERE id='disabled'"); err != nil {
		t.Fatal(err)
	}
	repository := NewRefreshRepository(database)
	if _, err := repository.Acquire(ctx, "disabled", "worker", time.Minute, true); !errors.Is(err, ErrSubscriptionDisabled) {
		t.Fatalf("disabled Acquire() error = %v", err)
	}
	if _, err := repository.Acquire(ctx, "upload", "worker", time.Minute, true); !errors.Is(err, ErrSourceIsNotRefreshable) {
		t.Fatalf("upload Acquire() error = %v", err)
	}
}

func createRefreshableSubscription(t *testing.T, ctx context.Context, database *sql.DB, id, sourceType string) {
	t.Helper()
	_, err := NewRepository(database).Create(ctx, CreateInput{ID: id, Name: id, SourceType: sourceType, SourceSecretRef: "/secret/" + id, RefreshInterval: time.Hour})
	if err != nil {
		t.Fatalf("create subscription %s: %v", id, err)
	}
}
