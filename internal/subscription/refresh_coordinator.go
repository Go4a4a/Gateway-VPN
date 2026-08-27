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

	"gateway-vpn/internal/operations"
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
	RefreshOperationFailed  = "OPERATION_STATUS_FAILED"
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
	Operations     *operations.Repository
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

type PreparedRefresh struct {
	OperationID    string
	SubscriptionID string
	Lease          RefreshLease
	Reclassify     bool
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
	prepared, joined, err := coordinator.PrepareRefresh(ctx, subscriptionID, force, false, "SYSTEM")
	if err != nil {
		return RefreshResult{}, err
	}
	if joined {
		return RefreshResult{}, ErrRefreshInProgress
	}
	return coordinator.ExecutePrepared(ctx, prepared)
}

func (coordinator *RefreshCoordinator) ReclassifyOne(ctx context.Context, subscriptionID string) (RefreshResult, error) {
	prepared, joined, err := coordinator.PrepareRefresh(ctx, subscriptionID, true, true, "SYSTEM")
	if err != nil {
		return RefreshResult{}, err
	}
	if joined {
		return RefreshResult{}, ErrRefreshInProgress
	}
	return coordinator.ExecutePrepared(ctx, prepared)
}

// PrepareRefresh acquires the durable single-flight lease and creates a QUEUED
// operation before an asynchronous API response is sent. A parallel request
// joins the existing operation instead of starting a second source fetch.
func (coordinator *RefreshCoordinator) PrepareRefresh(ctx context.Context, subscriptionID string, force, reclassify bool, requestedBy string) (PreparedRefresh, bool, error) {
	if err := coordinator.validate(); err != nil {
		return PreparedRefresh{}, false, err
	}
	owner, err := coordinator.newID("refresh")
	if err != nil {
		return PreparedRefresh{}, false, errors.New("allocate subscription refresh owner failed")
	}
	lease, err := coordinator.Refresh.Acquire(ctx, subscriptionID, owner, coordinator.LeaseDuration, force)
	if errors.Is(err, ErrRefreshInProgress) {
		current, stateErr := coordinator.Refresh.Get(ctx, subscriptionID)
		if stateErr != nil || current.LeaseOwner == "" {
			return PreparedRefresh{}, false, ErrRefreshInProgress
		}
		return PreparedRefresh{OperationID: current.LeaseOwner, SubscriptionID: subscriptionID}, true, nil
	}
	if err != nil {
		return PreparedRefresh{}, false, err
	}
	operationKind := "SUBSCRIPTION_REFRESH"
	if reclassify {
		operationKind = "SUBSCRIPTION_RECLASSIFY"
	}
	if _, err := coordinator.Operations.Create(ctx, operations.CreateInput{ID: owner, Kind: operationKind, ScopeType: "SUBSCRIPTION", ScopeID: subscriptionID, RequestedBy: requestedBy}); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = coordinator.Refresh.Release(cleanup, lease)
		cancel()
		return PreparedRefresh{}, false, errors.New("create subscription refresh operation failed")
	}
	return PreparedRefresh{OperationID: owner, SubscriptionID: subscriptionID, Lease: lease, Reclassify: reclassify}, false, nil
}

// CancelPrepared releases a queued job that cannot run and leaves a durable,
// explicit terminal status for the operation panel.
func (coordinator *RefreshCoordinator) CancelPrepared(ctx context.Context, prepared PreparedRefresh, code string) error {
	if prepared.OperationID == "" || prepared.Lease.Owner != prepared.OperationID || code == "" {
		return errors.New("prepared refresh and cancellation code are required")
	}
	_, finishErr := coordinator.Operations.Finish(ctx, prepared.OperationID, operations.StatusCancelled, code, operations.StepInput{
		Severity: "WARNING", Stage: "CANCELLED", Code: code, Message: "Обновление подписки отменено до запуска.",
		Details: map[string]any{"subscription_id": prepared.SubscriptionID},
	})
	releaseErr := coordinator.Refresh.Release(ctx, prepared.Lease)
	return errors.Join(finishErr, releaseErr)
}

// ExecutePrepared performs the network and LKG transaction for an already
// durable QUEUED operation.
func (coordinator *RefreshCoordinator) ExecutePrepared(ctx context.Context, prepared PreparedRefresh) (RefreshResult, error) {
	if err := coordinator.validate(); err != nil {
		return RefreshResult{}, err
	}
	owner, subscriptionID, lease, reclassify := prepared.OperationID, prepared.SubscriptionID, prepared.Lease, prepared.Reclassify
	if owner == "" || subscriptionID == "" || lease.Owner != owner || lease.Subscription.ID != subscriptionID {
		return RefreshResult{}, errors.New("prepared subscription refresh is invalid")
	}
	failureCode := RefreshFetchFailed
	requestedRetry := time.Duration(0)
	finished := false
	operationCreated := true
	operationFinished := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if !finished {
			_ = coordinator.finishFailure(cleanup, lease, failureCode, requestedRetry)
		}
		if operationCreated && !operationFinished {
			_, _ = coordinator.Operations.Finish(cleanup, owner, operations.StatusFailed, failureCode, operations.StepInput{
				Severity: "ERROR", Stage: "FAILED", Code: failureCode,
				Message: "Обновление подписки завершилось неуспешно.",
				Details: map[string]any{"subscription_id": subscriptionID},
			})
		}
	}()
	firstStage, firstCode, firstMessage := "SOURCE", "SOURCE_READ_STARTED", "Начато чтение источника подписки."
	if reclassify {
		firstStage, firstCode, firstMessage = "VALIDATE", "RECLASSIFY_STARTED", "Начата повторная классификация сохранённой подписки."
	}
	if _, err := coordinator.Operations.Start(ctx, owner, operations.StepInput{
		Severity: "INFO", Stage: firstStage, Code: firstCode, Message: firstMessage,
		Details: map[string]any{"subscription_id": subscriptionID},
	}); err != nil {
		failureCode = RefreshOperationFailed
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}

	var fetched FetchResult
	var active Version
	var activeErr error
	var err error
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
		options := FetchOptions{ETag: lease.ETag, LastModified: lease.LastModified, OperationID: owner}
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
			if delay, ok := FetchRetryAfter(err); ok {
				requestedRetry = delay
			}
		}
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	if !reclassify {
		if err := coordinator.appendOperationStep(ctx, owner, "HTTP", "FETCH_SUCCEEDED", "Источник подписки получен и передан на проверку."); err != nil {
			failureCode = RefreshOperationFailed
			return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
		}
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
		if err := coordinator.finishOperation(ctx, owner, "NOT_MODIFIED", operations.StepInput{Severity: "INFO", Stage: "COMPLETE", Code: "NOT_MODIFIED", Message: "Источник подписки не изменился.", Details: map[string]any{"subscription_id": subscriptionID}}); err != nil {
			return RefreshResult{}, errors.New("finish unchanged subscription operation failed")
		}
		operationFinished = true
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
		if err := coordinator.finishOperation(ctx, owner, "CONTENT_IDENTICAL", operations.StepInput{Severity: "INFO", Stage: "COMPLETE", Code: "CONTENT_IDENTICAL", Message: "Полученное содержимое совпадает с активной версией.", Details: map[string]any{"subscription_id": subscriptionID, "version_id": active.ID}}); err != nil {
			return RefreshResult{}, errors.New("finish identical subscription operation failed")
		}
		operationFinished = true
		return RefreshResult{SubscriptionID: subscriptionID, VersionID: active.ID, NotModified: true, NextAttemptAt: next}, nil
	}
	if activeErr != nil && !errors.Is(activeErr, store.ErrNotFound) {
		failureCode = RefreshImportFailed
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}

	if err := coordinator.appendOperationStep(ctx, owner, "IMPORT", "IMPORT_STARTED", "Начат безопасный импорт подписки."); err != nil {
		failureCode = RefreshOperationFailed
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
	if err := coordinator.appendOperationStep(ctx, owner, "VALIDATE", "CANDIDATE_VALIDATED", "Импортированная версия прошла структурную проверку."); err != nil {
		failureCode = RefreshOperationFailed
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		markFailed(cleanup, failureCode)
		cancel()
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	payloadPath, err := WriteNormalizedPayload(coordinator.PayloadRoot, subscriptionID, versionID, staged.Import)
	if err != nil {
		failureCode = RefreshPayloadFailed
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		markFailed(cleanup, failureCode)
		cancel()
		return RefreshResult{}, refreshFailure(subscriptionID, failureCode)
	}
	if err := coordinator.appendOperationStep(ctx, owner, "QUALIFY", "QUALIFICATION_STARTED", "Начата проверка новой версии через доступные модемы."); err != nil {
		failureCode = RefreshOperationFailed
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
	if err := coordinator.appendOperationStep(ctx, owner, "ACTIVATE", "ACTIVATION_STARTED", "Проверенная версия готовится к атомарной активации."); err != nil {
		failureCode = RefreshOperationFailed
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		_ = promotion.Rollback(cleanup)
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
	if err := coordinator.finishOperation(ctx, owner, "REFRESH_COMPLETE", operations.StepInput{Severity: "INFO", Stage: "COMPLETE", Code: "REFRESH_COMPLETE", Message: "Новая версия подписки проверена и активирована.", Details: map[string]any{"subscription_id": subscriptionID, "version_id": versionID}}); err != nil {
		return RefreshResult{}, errors.New("finish successful subscription operation failed")
	}
	operationFinished = true
	return RefreshResult{SubscriptionID: subscriptionID, VersionID: versionID, NextAttemptAt: next}, nil
}

func (coordinator *RefreshCoordinator) validate() error {
	if coordinator == nil || coordinator.Subscriptions == nil || coordinator.Versions == nil || coordinator.Matchers == nil || coordinator.Refresh == nil || coordinator.Fetcher == nil || coordinator.Sources == nil || coordinator.Runtime == nil || coordinator.Operations == nil || coordinator.PayloadRoot == "" || coordinator.now == nil || coordinator.random == nil || coordinator.newID == nil {
		return errors.New("subscription refresh coordinator dependencies are incomplete")
	}
	if coordinator.LeaseDuration < time.Second || coordinator.LeaseDuration > time.Hour || coordinator.BackoffInitial < time.Second || coordinator.BackoffMaximum < coordinator.BackoffInitial || coordinator.JitterPercent < 0 || coordinator.JitterPercent > 50 {
		return errors.New("subscription refresh coordinator timing policy is invalid")
	}
	return nil
}

func (coordinator *RefreshCoordinator) appendOperationStep(ctx context.Context, operationID, stage, code, message string) error {
	progress, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err := coordinator.Operations.AppendStep(progress, operationID, operations.StepInput{
		Severity: "INFO", Stage: stage, Code: code, Message: message,
	})
	return err
}

func (coordinator *RefreshCoordinator) finishOperation(ctx context.Context, operationID, summaryCode string, step operations.StepInput) error {
	progress, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err := coordinator.Operations.Finish(progress, operationID, operations.StatusSucceeded, summaryCode, step)
	return err
}

func (coordinator *RefreshCoordinator) finishFailure(ctx context.Context, lease RefreshLease, code string, requestedRetry time.Duration) error {
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
	if requestedRetry > delay {
		delay = requestedRetry
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
