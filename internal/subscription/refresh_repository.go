package subscription

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

var (
	ErrRefreshInProgress      = errors.New("subscription refresh is already in progress")
	ErrRefreshNotDue          = errors.New("subscription refresh is not due")
	ErrRefreshLeaseLost       = errors.New("subscription refresh lease was lost")
	ErrSubscriptionDisabled   = errors.New("subscription is disabled")
	ErrSourceIsNotRefreshable = errors.New("subscription source is not refreshable")
)

type RefreshRepository struct {
	database *sql.DB
	now      func() time.Time
}

type RefreshState struct {
	SubscriptionID      string
	ETag                string
	LastModified        string
	ConsecutiveFailures int
	NextAttemptAt       string
	LeaseOwner          string
	LeaseExpiresAt      string
	LastErrorCode       string
	UpdatedAt           string
}

type RefreshLease struct {
	Subscription        Subscription
	Owner               string
	ETag                string
	LastModified        string
	ConsecutiveFailures int
}

func NewRefreshRepository(database *sql.DB) *RefreshRepository {
	return &RefreshRepository{database: database, now: time.Now}
}

// Acquire serializes manual and scheduled refreshes durably. A crashed owner
// stops blocking work after leaseDuration, while an early scheduled run is
// rejected unless force is true.
func (repository *RefreshRepository) Acquire(ctx context.Context, subscriptionID, owner string, leaseDuration time.Duration, force bool) (RefreshLease, error) {
	if repository == nil || repository.database == nil {
		return RefreshLease{}, errors.New("subscription refresh repository is not configured")
	}
	if strings.TrimSpace(subscriptionID) == "" || !safeRefreshToken(owner) {
		return RefreshLease{}, errors.New("subscription id and safe refresh owner are required")
	}
	if leaseDuration < time.Second || leaseDuration > time.Hour {
		return RefreshLease{}, errors.New("subscription refresh lease must be between one second and one hour")
	}
	now := repository.now().UTC()
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return RefreshLease{}, fmt.Errorf("begin subscription refresh lease: %w", err)
	}
	defer transaction.Rollback()

	current, err := scanSubscription(transaction.QueryRowContext(ctx, subscriptionSelect+" WHERE id=?", subscriptionID))
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshLease{}, store.ErrNotFound
	}
	if err != nil {
		return RefreshLease{}, fmt.Errorf("read subscription for refresh: %w", err)
	}
	if !current.Enabled {
		return RefreshLease{}, ErrSubscriptionDisabled
	}
	if current.SourceType != "url" {
		return RefreshLease{}, ErrSourceIsNotRefreshable
	}
	nowText := now.Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO subscription_refresh_state(subscription_id, updated_at)
VALUES (?, ?)
ON CONFLICT(subscription_id) DO NOTHING`, subscriptionID, nowText); err != nil {
		return RefreshLease{}, fmt.Errorf("initialize subscription refresh state: %w", err)
	}
	state, err := scanRefreshState(transaction.QueryRowContext(ctx, refreshStateSelect+" WHERE subscription_id=?", subscriptionID))
	if err != nil {
		return RefreshLease{}, fmt.Errorf("read subscription refresh state: %w", err)
	}
	if state.LeaseOwner != "" {
		expires, parseErr := time.Parse(time.RFC3339Nano, state.LeaseExpiresAt)
		if parseErr != nil {
			return RefreshLease{}, errors.New("stored subscription refresh lease is invalid")
		}
		if expires.After(now) {
			return RefreshLease{}, ErrRefreshInProgress
		}
	}
	if !force && state.NextAttemptAt != "" {
		next, parseErr := time.Parse(time.RFC3339Nano, state.NextAttemptAt)
		if parseErr != nil {
			return RefreshLease{}, errors.New("stored subscription refresh schedule is invalid")
		}
		if next.After(now) {
			return RefreshLease{}, ErrRefreshNotDue
		}
	}
	leaseExpires := now.Add(leaseDuration).Format(time.RFC3339Nano)
	result, err := transaction.ExecContext(ctx, `
UPDATE subscription_refresh_state
SET lease_owner=?, lease_expires_at=?, updated_at=?
WHERE subscription_id=?`, owner, leaseExpires, nowText, subscriptionID)
	if err != nil {
		return RefreshLease{}, fmt.Errorf("acquire subscription refresh lease: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return RefreshLease{}, ErrRefreshLeaseLost
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE subscriptions SET last_refresh_at=?, updated_at=? WHERE id=?", nowText, nowText, subscriptionID); err != nil {
		return RefreshLease{}, fmt.Errorf("record subscription refresh attempt: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return RefreshLease{}, fmt.Errorf("commit subscription refresh lease: %w", err)
	}
	return RefreshLease{Subscription: current, Owner: owner, ETag: state.ETag, LastModified: state.LastModified, ConsecutiveFailures: state.ConsecutiveFailures}, nil
}

func (repository *RefreshRepository) FinishSuccess(ctx context.Context, lease RefreshLease, etag, lastModified string, nextAttempt time.Time) error {
	if !validLease(lease) || nextAttempt.IsZero() {
		return errors.New("valid subscription refresh lease and next attempt are required")
	}
	if len(etag) > 1024 || strings.ContainsAny(etag, "\r\n") || len(lastModified) > 128 || strings.ContainsAny(lastModified, "\r\n") {
		return errors.New("subscription cache validators are invalid")
	}
	return repository.finish(ctx, lease, etag, lastModified, 0, nextAttempt, "", true)
}

func (repository *RefreshRepository) FinishFailure(ctx context.Context, lease RefreshLease, errorCode string, nextAttempt time.Time) error {
	if !validLease(lease) || nextAttempt.IsZero() || !safeErrorCode(errorCode) {
		return errors.New("valid subscription refresh lease, error code, and next attempt are required")
	}
	return repository.finish(ctx, lease, lease.ETag, lease.LastModified, lease.ConsecutiveFailures+1, nextAttempt, errorCode, false)
}

func (repository *RefreshRepository) finish(ctx context.Context, lease RefreshLease, etag, lastModified string, failures int, nextAttempt time.Time, errorCode string, success bool) error {
	now := repository.now().UTC().Format(time.RFC3339Nano)
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription refresh completion: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `
UPDATE subscription_refresh_state
SET etag=?, last_modified=?, consecutive_failures=?, next_attempt_at=?,
    lease_owner=NULL, lease_expires_at=NULL, last_error_code=?, updated_at=?
WHERE subscription_id=? AND lease_owner=?`,
		etag, lastModified, failures, nextAttempt.UTC().Format(time.RFC3339Nano), nullableString(errorCode), now, lease.Subscription.ID, lease.Owner)
	if err != nil {
		return fmt.Errorf("complete subscription refresh lease: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrRefreshLeaseLost
	}
	if success {
		if _, err := transaction.ExecContext(ctx, "UPDATE subscriptions SET last_success_at=?, updated_at=? WHERE id=?", now, now, lease.Subscription.ID); err != nil {
			return fmt.Errorf("record successful subscription refresh: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit subscription refresh completion: %w", err)
	}
	return nil
}

func (repository *RefreshRepository) Get(ctx context.Context, subscriptionID string) (RefreshState, error) {
	state, err := scanRefreshState(repository.database.QueryRowContext(ctx, refreshStateSelect+" WHERE subscription_id=?", subscriptionID))
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshState{}, store.ErrNotFound
	}
	if err != nil {
		return RefreshState{}, fmt.Errorf("get subscription refresh state: %w", err)
	}
	return state, nil
}

const refreshStateSelect = `
SELECT subscription_id, etag, last_modified, consecutive_failures,
       next_attempt_at, lease_owner, lease_expires_at, last_error_code, updated_at
FROM subscription_refresh_state`

func scanRefreshState(row scanner) (RefreshState, error) {
	var state RefreshState
	var nextAttempt, leaseOwner, leaseExpires, errorCode sql.NullString
	err := row.Scan(&state.SubscriptionID, &state.ETag, &state.LastModified, &state.ConsecutiveFailures, &nextAttempt, &leaseOwner, &leaseExpires, &errorCode, &state.UpdatedAt)
	state.NextAttemptAt = nextAttempt.String
	state.LeaseOwner = leaseOwner.String
	state.LeaseExpiresAt = leaseExpires.String
	state.LastErrorCode = errorCode.String
	return state, err
}

func validLease(lease RefreshLease) bool {
	return lease.Subscription.ID != "" && safeRefreshToken(lease.Owner) && lease.ConsecutiveFailures >= 0
}

func safeRefreshToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._:-", char) {
			continue
		}
		return false
	}
	return true
}

func safeErrorCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' {
			continue
		}
		return false
	}
	return true
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
