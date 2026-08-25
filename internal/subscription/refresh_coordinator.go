package subscription

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"gateway-vpn/internal/store"
)

const (
	RefreshSourceReadFailed = "SOURCE_READ_FAILED"
	RefreshFetchFailed      = "FETCH_FAILED"
	RefreshImportFailed     = "IMPORT_FAILED"
	RefreshPayloadFailed    = "PAYLOAD_STORE_FAILED"
	RefreshRuntimeRejected  = "RUNTIME_REJECTED"
	RefreshActivateFailed   = "LKG_ACTIVATE_FAILED"
	RefreshRuntimeCommit    = "RUNTIME_COMMIT_FAILED"
	RefreshRollbackFailed   = "RUNTIME_ROLLBACK_FAILED"
)

type SubscriptionFetcher interface {
	Fetch(context.Context, string, FetchOptions) (FetchResult, error)
}

type ScopedSubscriptionFetcher interface {
	FetchForSubscription(context.Context, string, string, FetchOptions) (FetchResult, error)
}

// CandidateRuntime must keep the current LKG path usable while it generates,
// validates and temporarily applies Candidate. Promote succeeds only after at
// least one enabled modem × candidate-node path is BYPASS_QUALIFIED. The
// returned promotion keeps rollback usable through SQLite activation; Commit
// then publishes evidence against the now-active version.
type CandidateRuntime interface {
	Promote(context.Context, Candidate) (CandidatePromotion, error)
}

type CandidatePromotion interface {
	// Commit publishes qualification evidence only after the candidate is the
	// active SQLite version. Until Commit returns, Rollback must remain usable.
	Commit(context.Context) error
	Rollback(context.Context) error
}

type Candidate struct {
	Subscription Subscription
	Version      StagedVersion
	PayloadPath  string
}

type RefreshCoordinator struct {
	Subscriptions  *Repository
	Versions       *VersionRepository
	Matchers       *MatcherRepository
	Refresh        *RefreshRepository
	Fetcher        SubscriptionFetcher
	Sources        SourceURLReader
	Runtime        CandidateRuntime
	PayloadRoot    string
	LeaseDuration  time.Duration
	BackoffInitial time.Duration
	BackoffMaximum time.Duration
	JitterPercent  float64
	now            func() time.Time
	random         func() float64
	newID          func(string) (string, error)
}

type RefreshResult struct {
	SubscriptionID string
	VersionID      string
	NotModified    bool
	NextAttemptAt  time.Time
}

func NewRefreshCoordinator(subscriptions *Repository, versions *VersionRepository, matchers *MatcherRepository, refresh *RefreshRepository, fetcher SubscriptionFetcher, sources SourceURLReader, runtime CandidateRuntime, payloadRoot string) *RefreshCoordinator {
	return &RefreshCoordinator{
		Subscriptions:  subscriptions,
		Versions:       versions,
		Matchers:       matchers,
		Refresh:        refresh,
		Fetcher:        fetcher,
		Sources:        sources,
		Runtime:        runtime,
		PayloadRoot:    payloadRoot,
		LeaseDuration:  30 * time.Minute,
		BackoffInitial: time.Minute,
		BackoffMaximum: 6 * time.Hour,
		JitterPercent:  20,
		now:            time.Now,
		random: func() float64 {
			var value [8]byte
			if _, err := rand.Read(value[:]); err != nil {
				return 0.5
			}
			var number uint64
			for _, current := range value {
				number = number<<8 | uint64(current)
			}
			return float64(number>>11) / (1 << 53)
		},
		newID: randomRefreshID,
	}
}

// RefreshOne runs a complete refresh transaction. force bypasses only the due
// time; it never bypasses the durable single-refresh lease.
func (coordinator *RefreshCoordinator) RefreshOne(ctx context.Context, subscriptionID string, force bool) (RefreshResult, error) {
	return coordinator.refreshOne(ctx, subscriptionID, force, false)
}

func (coordinator *RefreshCoordinator) ReclassifyOne(ctx context.Context, subscriptionID string) (RefreshResult, error) {
	return coordinator.refreshOne(ctx, subscriptionID, true, true)
}

func (coordinator *RefreshCoordinator) refreshOne(ctx context.Context, subscriptionID string, force, reclassify bool) (RefreshResult, error) {
	if err := coordinator.validate(); err != nil {
		return RefreshResult{}, err
	}
	owner, err := coordinator.newID("refresh")
	if err != nil {
		return RefreshResult{}, errors.New("allocate subscription refresh owner failed")
	}
	lease, err := coordinator.Refresh.Acquire(ctx, subscriptionID, owner, coordinator.LeaseDuration, force)
	if err != nil {
		return RefreshResult{}, err
	}
	failureCode := RefreshFetchFailed
	finished := false
	defer func() {
		if !finished {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			_ = coordinator.finishFailure(cleanup, lease, failureCode)
		}
	}()

	var fetched FetchResult
	var active Version
	var activeErr error
	if reclassify {
		active, activeErr = coordinator.Versions.Active(ctx, subscriptionID)
		if activeErr != nil {
			failureCode = RefreshPayloadFailed
			return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
		}
		fetched.Payload, err = readNormalizedPayload(coordinator.PayloadRoot, subscriptionID, active.ID)
		fetched.ETag = lease.ETag
		fetched.LastModified = lease.LastModified
	} else {
		secretURL, sourceErr := coordinator.Sources.ReadURL(ctx, lease.Subscription.SourceSecretRef)
		if sourceErr != nil {
			failureCode = RefreshSourceReadFailed
			return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
		}
		options := FetchOptions{ETag: lease.ETag, LastModified: lease.LastModified}
		if scoped, ok := coordinator.Fetcher.(ScopedSubscriptionFetcher); ok {
			fetched, err = scoped.FetchForSubscription(ctx, subscriptionID, secretURL, options)
		} else {
			fetched, err = coordinator.Fetcher.Fetch(ctx, secretURL, options)
		}
	}
	if err != nil {
		if reclassify {
			failureCode = RefreshPayloadFailed
		} else {
			failureCode = RefreshFetchFailed
		}
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	next := coordinator.successNextAttempt(lease.Subscription)
	if fetched.NotModified {
		if reclassify {
			failureCode = RefreshFetchFailed
			return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
		}
		if err := coordinator.Refresh.FinishSuccess(ctx, lease, fetched.ETag, fetched.LastModified, next); err != nil {
			return RefreshResult{}, fmt.Errorf("finish unchanged subscription refresh: %w", err)
		}
		finished = true
		return RefreshResult{SubscriptionID: subscriptionID, NotModified: true, NextAttemptAt: next}, nil
	}
	digest := sha256.Sum256(fetched.Payload)
	if active.ID == "" {
		active, activeErr = coordinator.Versions.Active(ctx, subscriptionID)
	}
	if activeErr == nil && active.ContentSHA256 == hex.EncodeToString(digest[:]) && !reclassify {
		if err := coordinator.Refresh.FinishSuccess(ctx, lease, fetched.ETag, fetched.LastModified, next); err != nil {
			return RefreshResult{}, fmt.Errorf("finish identical subscription refresh: %w", err)
		}
		finished = true
		return RefreshResult{SubscriptionID: subscriptionID, VersionID: active.ID, NotModified: true, NextAttemptAt: next}, nil
	}
	if activeErr != nil && !errors.Is(activeErr, store.ErrNotFound) {
		failureCode = RefreshImportFailed
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}

	matchers, err := coordinator.Matchers.List(ctx)
	if err != nil {
		failureCode = RefreshImportFailed
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	overrides, err := coordinator.Versions.ActiveOverrides(ctx, subscriptionID)
	if err != nil {
		failureCode = RefreshImportFailed
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	versionID, err := coordinator.newID("version")
	if err != nil {
		failureCode = RefreshImportFailed
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	staged, err := coordinator.Versions.Stage(ctx, StageInput{VersionID: versionID, SubscriptionID: subscriptionID, Payload: fetched.Payload, Matchers: matchers, Overrides: overrides})
	if err != nil {
		failureCode = RefreshImportFailed
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	markFailed := func(cleanup context.Context, code string) {
		_ = coordinator.Versions.MarkFailed(cleanup, versionID, errors.New(code))
	}
	payloadPath, err := WriteNormalizedPayload(coordinator.PayloadRoot, subscriptionID, versionID, staged.Import)
	if err != nil {
		failureCode = RefreshPayloadFailed
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		markFailed(cleanup, failureCode)
		cancel()
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	promotion, err := coordinator.Runtime.Promote(ctx, Candidate{Subscription: lease.Subscription, Version: staged, PayloadPath: payloadPath})
	if err != nil || promotion == nil {
		failureCode = RefreshRuntimeRejected
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		markFailed(cleanup, failureCode)
		cancel()
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	if err := coordinator.Versions.Activate(ctx, versionID); err != nil {
		failureCode = RefreshActivateFailed
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		rollbackErr := promotion.Rollback(cleanup)
		abortErr := coordinator.Versions.AbortActivation(cleanup, versionID, errors.New(failureCode))
		if rollbackErr != nil || abortErr != nil {
			failureCode = RefreshRollbackFailed
		}
		cancel()
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	if err := promotion.Commit(ctx); err != nil {
		failureCode = RefreshRuntimeCommit
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		rollbackErr := promotion.Rollback(cleanup)
		abortErr := coordinator.Versions.AbortActivation(cleanup, versionID, errors.New(failureCode))
		if rollbackErr != nil || abortErr != nil {
			failureCode = RefreshRollbackFailed
		}
		cancel()
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	if err := coordinator.Refresh.FinishSuccess(ctx, lease, fetched.ETag, fetched.LastModified, next); err != nil {
		return RefreshResult{}, fmt.Errorf("finish successful subscription refresh: %w", err)
	}
	finished = true
	return RefreshResult{SubscriptionID: subscriptionID, VersionID: versionID, NextAttemptAt: next}, nil
}

func (coordinator *RefreshCoordinator) validate() error {
	if coordinator == nil || coordinator.Subscriptions == nil || coordinator.Versions == nil || coordinator.Matchers == nil || coordinator.Refresh == nil || coordinator.Fetcher == nil || coordinator.Sources == nil || coordinator.Runtime == nil || coordinator.PayloadRoot == "" || coordinator.now == nil || coordinator.random == nil || coordinator.newID == nil {
		return errors.New("subscription refresh coordinator dependencies are incomplete")
	}
	if coordinator.LeaseDuration < time.Second || coordinator.LeaseDuration > time.Hour || coordinator.BackoffInitial < time.Second || coordinator.BackoffMaximum < coordinator.BackoffInitial || coordinator.JitterPercent < 0 || coordinator.JitterPercent > 50 {
		return errors.New("subscription refresh coordinator timing policy is invalid")
	}
	return nil
}

func (coordinator *RefreshCoordinator) finishFailure(ctx context.Context, lease RefreshLease, code string) error {
	delay := coordinator.BackoffInitial
	for index := 0; index < lease.ConsecutiveFailures && delay < coordinator.BackoffMaximum; index++ {
		if delay > coordinator.BackoffMaximum/2 {
			delay = coordinator.BackoffMaximum
			break
		}
		delay *= 2
	}
	if delay > coordinator.BackoffMaximum {
		delay = coordinator.BackoffMaximum
	}
	next := coordinator.now().UTC().Add(coordinator.withJitter(delay))
	return coordinator.Refresh.FinishFailure(ctx, lease, code, next)
}

func (coordinator *RefreshCoordinator) successNextAttempt(current Subscription) time.Time {
	interval := time.Duration(current.RefreshIntervalSeconds) * time.Second
	return coordinator.now().UTC().Add(coordinator.withJitter(interval))
}

func (coordinator *RefreshCoordinator) withJitter(base time.Duration) time.Duration {
	value := math.Max(0, math.Min(1, coordinator.random()))
	factor := 1 + (value*2-1)*(coordinator.JitterPercent/100)
	result := time.Duration(float64(base) * factor)
	if result < time.Second {
		return time.Second
	}
	return result
}

func randomRefreshID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(value[:]), nil
}

func refreshFailure(subscriptionID, code string) error {
	return fmt.Errorf("subscription %s refresh failed (%s)", subscriptionID, code)
}
