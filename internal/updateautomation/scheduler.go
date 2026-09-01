// Package updateautomation owns the durable, unattended Gateway release
// schedule. It deliberately composes the existing signed remote source,
// stager and fixed root apply trigger instead of introducing a second update
// path.
package updateautomation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/power"
	"gateway-vpn/internal/state"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/updateremote"
)

const (
	defaultPollInterval = 30 * time.Second
	leaseDuration       = 90 * time.Second
	leaseRenewInterval  = 30 * time.Second
	maintenanceRetry    = 5 * time.Minute
	applyRetry          = 15 * time.Minute
)

var ErrLeaseBusy = errors.New("software update scheduler is already running")

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type RemoteSource interface {
	Check(context.Context, string) (updateremote.Available, error)
	StageAutomaticChannel(context.Context, string) (updatepkg.Operation, error)
}

type Stager interface {
	Status() (updatepkg.Operation, bool, error)
}

type ApplyController interface {
	ApplyPendingUpdate(context.Context) error
	UpdateStatus(context.Context) (networkapply.UpdateTransactionStatus, error)
	MaintenanceStatus(context.Context) (power.MaintenanceStatus, error)
}

type PathBlocker interface {
	BlockPath(context.Context) error
}

type StateRecorder interface {
	Block(context.Context, string, string) (state.Snapshot, bool, error)
	AppendEvent(context.Context, state.EventInput) error
}

type Scheduler struct {
	Repository Repository
	Policy     *updatepkg.AutomationPolicyRepository
	Remote     RemoteSource
	Stager     Stager
	Apply      ApplyController
	Path       PathBlocker
	State      StateRecorder
	Readiness  ApplyReadiness
	Owner      string
	Interval   time.Duration
	Now        func() time.Time
	OnError    func(error)
	OnProgress func(Status)

	mutex              sync.Mutex
	leaseRenewInterval time.Duration
}

func New(database *sql.DB, policy *updatepkg.AutomationPolicyRepository, remote RemoteSource, stager Stager, apply ApplyController, path PathBlocker, states StateRecorder) (*Scheduler, error) {
	if database == nil || policy == nil || policy.Database != database || remote == nil || stager == nil || apply == nil || path == nil || states == nil {
		return nil, errors.New("software update scheduler dependencies are incomplete")
	}
	ownerBytes := make([]byte, 16)
	if _, err := rand.Read(ownerBytes); err != nil {
		return nil, errors.New("generate software update scheduler owner failed")
	}
	return &Scheduler{
		Repository: Repository{Database: database}, Policy: policy, Remote: remote, Stager: stager,
		Apply: apply, Path: path, State: states, Readiness: SQLiteApplyReadiness{Database: database}, Owner: hex.EncodeToString(ownerBytes),
	}, nil
}

func (scheduler *Scheduler) Run(ctx context.Context) error {
	if err := scheduler.validate(); err != nil {
		return err
	}
	interval := scheduler.Interval
	if interval == 0 {
		interval = defaultPollInterval
	}
	if interval < 5*time.Second || interval > 10*time.Minute {
		return errors.New("software update scheduler poll interval is outside the supported range")
	}
	scheduler.runCycle(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			scheduler.runCycle(ctx)
		}
	}
}

func (scheduler *Scheduler) Status(ctx context.Context) (Status, error) {
	if scheduler == nil {
		return Status{}, errors.New("software update scheduler is unavailable")
	}
	return scheduler.Repository.Get(ctx)
}

func (scheduler *Scheduler) runCycle(ctx context.Context) {
	err := scheduler.RunOnce(ctx)
	if err != nil && !errors.Is(err, ErrLeaseBusy) && !errors.Is(err, context.Canceled) && scheduler.OnError != nil {
		scheduler.OnError(err)
	}
	if scheduler.OnProgress != nil {
		if status, statusErr := scheduler.Repository.Get(ctx); statusErr == nil {
			scheduler.OnProgress(status)
		}
	}
}

func (scheduler *Scheduler) RunOnce(ctx context.Context) (resultErr error) {
	if err := scheduler.validate(); err != nil {
		return err
	}
	scheduler.mutex.Lock()
	defer scheduler.mutex.Unlock()
	now := scheduler.now()
	_, acquired, err := scheduler.Repository.Acquire(ctx, scheduler.Owner, now, leaseDuration)
	if err != nil {
		return err
	}
	if !acquired {
		return ErrLeaseBusy
	}
	operationContext, cancelOperation := context.WithCancel(ctx)
	leaseDone := make(chan struct{})
	leaseStopped := make(chan struct{})
	leaseError := make(chan error, 1)
	renewInterval := scheduler.leaseRenewInterval
	if renewInterval == 0 {
		renewInterval = leaseRenewInterval
	}
	go func() {
		defer close(leaseStopped)
		scheduler.renewLease(operationContext, cancelOperation, leaseDone, leaseError, renewInterval)
	}()
	defer func() {
		close(leaseDone)
		cancelOperation()
		// A completed RunOnce must not leave a lease-renewal goroutine behind.
		// Besides making the Scheduler safe to reuse, waiting here ensures a
		// renewal failure cannot arrive just after the non-blocking result read
		// and be silently replaced by context.Canceled.
		<-leaseStopped
		select {
		case renewErr := <-leaseError:
			if renewErr != nil && (resultErr == nil || errors.Is(resultErr, context.Canceled)) {
				resultErr = renewErr
			}
		default:
		}
		releaseContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = scheduler.Repository.Release(releaseContext, scheduler.Owner, scheduler.now())
	}()
	policy, err := scheduler.Policy.Get(operationContext)
	if err != nil {
		return err
	}
	status, err := scheduler.syncPolicy(operationContext, policy, now)
	if err != nil {
		return err
	}
	status, stop, err := scheduler.reconcile(operationContext, policy, status, now)
	if err != nil || stop {
		return err
	}
	if !policy.AutomaticCheckEnabled {
		_, err = scheduler.Repository.UpdateOwned(operationContext, scheduler.Owner, func(current *Status) error {
			if current.StagedUpdateID == "" {
				current.Phase = PhaseDisabled
				current.NextCheckAt = ""
				current.NextApplyAt = ""
			}
			current.UpdatedAt = now.Format(time.RFC3339Nano)
			return nil
		})
		return err
	}
	if status.StagedUpdateID != "" {
		if policy.AutomaticApplyEnabled && deadlineDue(status.ApplyDeadlineAt, now) {
			return scheduler.maybeApply(operationContext, policy, status, now)
		}
		if status.NextApplyAt != "" && !deadlineDue(status.NextApplyAt, now) {
			return scheduler.leaseResult(leaseError)
		}
		return scheduler.maybeApply(operationContext, policy, status, now)
	}
	if !deadlineDue(status.NextCheckAt, now) {
		return scheduler.leaseResult(leaseError)
	}
	return scheduler.checkAndMaybeStage(operationContext, policy, now)
}

func (scheduler *Scheduler) syncPolicy(ctx context.Context, policy updatepkg.AutomationPolicy, now time.Time) (Status, error) {
	current, err := scheduler.Repository.Get(ctx)
	if err != nil {
		return Status{}, err
	}
	if current.PolicyUpdatedAt == policy.UpdatedAt && current.Channel == policy.Channel {
		return current, nil
	}
	return scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(status *Status) error {
		status.PolicyUpdatedAt = policy.UpdatedAt
		status.Channel = policy.Channel
		status.JitterOffsetMinutes = deterministicJitter(policy)
		status.CandidateVersion = ""
		status.CandidateReference = ""
		status.CandidatePublishedAt = ""
		status.ConsecutiveFailures = 0
		status.LastErrorCode = ""
		status.LastResultCode = "POLICY_CHANGED"
		status.NextApplyAt = ""
		if status.StagedUpdateID != "" && status.StagedAt != "" {
			staged, err := time.Parse(time.RFC3339Nano, status.StagedAt)
			if err != nil {
				return errors.New("stored automatic staging time is invalid")
			}
			status.ApplyDeadlineAt = staged.Add(time.Duration(policy.MaximumApplyDelayHours) * time.Hour).Format(time.RFC3339Nano)
		}
		if status.StagedUpdateID == "" {
			status.ApplyIntentAt = ""
			status.ApplyObservedAt = ""
			if policy.AutomaticCheckEnabled {
				status.Phase = PhaseIdle
				status.NextCheckAt = nextRegularCheck(policy, status.JitterOffsetMinutes, now)
			} else {
				status.Phase = PhaseDisabled
				status.NextCheckAt = ""
			}
		}
		status.UpdatedAt = now.Format(time.RFC3339Nano)
		return nil
	})
}

func (scheduler *Scheduler) reconcile(ctx context.Context, policy updatepkg.AutomationPolicy, status Status, now time.Time) (Status, bool, error) {
	rootContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	rootStatus, rootErr := scheduler.Apply.UpdateStatus(rootContext)
	cancel()
	if rootErr != nil {
		result, err := scheduler.suppress(ctx, status, now, "UPDATE_STATUS_UNAVAILABLE", maintenanceRetry)
		return result, true, err
	}
	operation, pending, stageErr := scheduler.Stager.Status()
	if stageErr != nil {
		result, err := scheduler.fail(ctx, status, now, "STAGED_UPDATE_STATUS_INVALID", true)
		return result, true, err
	}
	if status.StagedUpdateID != "" && rootStatus.Exists && rootStatus.UpdateID == status.StagedUpdateID {
		switch rootStatus.State {
		case string(updatepkg.StateFinalized):
			result, err := scheduler.finish(ctx, status, policy, now, "AUTO_UPDATE_FINALIZED", "")
			scheduler.event(ctx, "AUTOMATIC_UPDATE_FINALIZED", map[string]any{"update_id": status.StagedUpdateID, "gateway_version": status.StagedVersion})
			return result, true, err
		case string(updatepkg.StateRolledBack):
			result, err := scheduler.finish(ctx, status, policy, now, "AUTO_UPDATE_ROLLED_BACK", "AUTO_UPDATE_ROLLED_BACK")
			scheduler.event(ctx, "AUTOMATIC_UPDATE_ROLLED_BACK", map[string]any{"update_id": status.StagedUpdateID, "gateway_version": status.StagedVersion})
			return result, true, err
		case string(updatepkg.StateRollbackFailed):
			result, err := scheduler.finish(ctx, status, policy, now, "AUTO_UPDATE_ROLLBACK_FAILED", "AUTO_UPDATE_ROLLBACK_FAILED")
			return result, true, err
		default:
			result, err := scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
				current.Phase = PhaseApplyDispatched
				current.ApplyObservedAt = now.Format(time.RFC3339Nano)
				current.LastResultCode = "ROOT_UPDATE_ACTIVE"
				current.LastErrorCode = ""
				current.UpdatedAt = now.Format(time.RFC3339Nano)
				return nil
			})
			return result, true, err
		}
	}
	if pending {
		if operation.SourceKind != updatepkg.SourceAutomaticGitHub {
			result, err := scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
				current.Phase = PhaseManualPending
				current.StagedUpdateID = ""
				current.StagedVersion = ""
				current.StagedAt = ""
				current.ApplyDeadlineAt = ""
				current.ApplyIntentAt = ""
				current.ApplyObservedAt = ""
				current.NextApplyAt = ""
				current.LastResultCode = "MANUAL_UPDATE_PENDING"
				current.LastErrorCode = ""
				current.UpdatedAt = now.Format(time.RFC3339Nano)
				return nil
			})
			return result, true, err
		}
		if status.StagedUpdateID == operation.UpdateID && (status.Phase == PhaseApplyIntent || status.Phase == PhaseApplyDispatched || status.Phase == PhaseOutcomeUnknown) {
			result, err := scheduler.outcomeUnknown(ctx, status, now, "AUTO_APPLY_OUTCOME_UNKNOWN")
			return result, true, err
		}
		if status.StagedUpdateID == operation.UpdateID && status.Phase == PhaseManualAttention {
			return status, true, nil
		}
		if operation.SourceChannel != policy.Channel || !policy.AutomaticDownloadEnabled {
			result, err := scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
				current.Phase = PhaseManualPending
				current.StagedUpdateID = operation.UpdateID
				current.StagedVersion = operation.GatewayVersion
				if err := setStagingEvidence(current, operation, policy); err != nil {
					return err
				}
				current.NextApplyAt = ""
				current.LastResultCode = "AUTO_STAGE_POLICY_MISMATCH"
				current.LastErrorCode = "AUTO_STAGE_POLICY_MISMATCH"
				current.UpdatedAt = now.Format(time.RFC3339Nano)
				return nil
			})
			return result, true, err
		}
		if status.StagedUpdateID != "" && status.StagedUpdateID != operation.UpdateID {
			result, err := scheduler.outcomeUnknown(ctx, status, now, "AUTO_STAGE_ID_MISMATCH")
			return result, true, err
		}
		result, err := scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
			current.Phase = PhaseStaged
			current.StagedUpdateID = operation.UpdateID
			current.StagedVersion = operation.GatewayVersion
			if err := setStagingEvidence(current, operation, policy); err != nil {
				return err
			}
			current.CandidateVersion = operation.GatewayVersion
			current.CandidateReference = operation.SourceReference
			current.ApplyIntentAt = ""
			current.ApplyObservedAt = ""
			current.LastResultCode = "AUTO_UPDATE_STAGED"
			current.LastErrorCode = ""
			current.UpdatedAt = now.Format(time.RFC3339Nano)
			return nil
		})
		return result, false, err
	}
	if status.Phase == PhaseApplyIntent || status.Phase == PhaseApplyDispatched {
		result, err := scheduler.outcomeUnknown(ctx, status, now, "AUTO_APPLY_OUTCOME_UNKNOWN")
		return result, true, err
	}
	if status.StagedUpdateID != "" {
		result, err := scheduler.fail(ctx, status, now, "AUTO_STAGE_MISSING", true)
		return result, true, err
	}
	return status, false, nil
}

func (scheduler *Scheduler) checkAndMaybeStage(ctx context.Context, policy updatepkg.AutomationPolicy, now time.Time) error {
	if stop, err := scheduler.maintenance(ctx, now); err != nil || stop {
		return err
	}
	status, err := scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseChecking
		current.LastAttemptAt = now.Format(time.RFC3339Nano)
		current.LastResultCode = "CHECK_STARTED"
		current.LastErrorCode = ""
		current.UpdatedAt = now.Format(time.RFC3339Nano)
		return nil
	})
	if err != nil {
		return err
	}
	checkContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	available, checkErr := scheduler.Remote.Check(checkContext, policy.Channel)
	cancel()
	completed := scheduler.now()
	if checkErr != nil {
		_, err = scheduler.fail(ctx, status, completed, "UPDATE_CHECK_FAILED", true)
		return err
	}
	if !available.Available {
		_, err = scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
			current.Phase = PhaseIdle
			current.CandidateVersion = ""
			current.CandidateReference = ""
			current.CandidatePublishedAt = ""
			current.LastCompletedAt = completed.Format(time.RFC3339Nano)
			current.LastResultCode = "UP_TO_DATE"
			current.LastErrorCode = ""
			current.ConsecutiveFailures = 0
			current.NextCheckAt = nextRegularCheck(policy, current.JitterOffsetMinutes, completed)
			current.UpdatedAt = completed.Format(time.RFC3339Nano)
			return nil
		})
		return err
	}
	if !validAvailableCandidate(available, policy.Channel) {
		_, err = scheduler.fail(ctx, status, completed, "UPDATE_CANDIDATE_INVALID", true)
		return err
	}
	status, err = scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseCandidate
		current.CandidateVersion = available.CandidateVersion
		current.CandidateReference = available.SourceReference
		current.CandidatePublishedAt = available.PublishedAt
		current.LastCompletedAt = completed.Format(time.RFC3339Nano)
		current.LastResultCode = "UPDATE_AVAILABLE"
		current.LastErrorCode = ""
		current.ConsecutiveFailures = 0
		current.NextCheckAt = nextRegularCheck(policy, current.JitterOffsetMinutes, completed)
		current.UpdatedAt = completed.Format(time.RFC3339Nano)
		return nil
	})
	if err != nil {
		return err
	}
	scheduler.event(ctx, "AUTOMATIC_UPDATE_CANDIDATE_DISCOVERED", map[string]any{"channel": policy.Channel, "gateway_version": available.CandidateVersion, "source_reference": available.SourceReference})
	if !policy.AutomaticDownloadEnabled {
		return nil
	}
	if stop, err := scheduler.maintenance(ctx, completed); err != nil || stop {
		return err
	}
	status, err = scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseDownloading
		current.LastAttemptAt = completed.Format(time.RFC3339Nano)
		current.LastResultCode = "DOWNLOAD_STARTED"
		current.UpdatedAt = completed.Format(time.RFC3339Nano)
		return nil
	})
	if err != nil {
		return err
	}
	downloadContext, cancelDownload := context.WithTimeout(ctx, 20*time.Minute)
	operation, stageErr := scheduler.Remote.StageAutomaticChannel(downloadContext, policy.Channel)
	cancelDownload()
	completed = scheduler.now()
	if errors.Is(stageErr, updatepkg.ErrUpdatePending) {
		_, err = scheduler.suppress(ctx, status, completed, "UPDATE_PENDING_RACE", maintenanceRetry)
		return err
	}
	if stageErr != nil {
		_, err = scheduler.fail(ctx, status, completed, "UPDATE_DOWNLOAD_FAILED", true)
		return err
	}
	if operation.SourceKind != updatepkg.SourceAutomaticGitHub || operation.SourceChannel != policy.Channel {
		_, err = scheduler.outcomeUnknown(ctx, status, completed, "AUTO_STAGE_OWNERSHIP_INVALID")
		return err
	}
	status, err = scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseStaged
		current.StagedUpdateID = operation.UpdateID
		current.StagedVersion = operation.GatewayVersion
		if err := setStagingEvidence(current, operation, policy); err != nil {
			return err
		}
		current.CandidateVersion = operation.GatewayVersion
		current.CandidateReference = operation.SourceReference
		current.LastCompletedAt = completed.Format(time.RFC3339Nano)
		current.LastResultCode = "AUTO_UPDATE_STAGED"
		current.LastErrorCode = ""
		current.ConsecutiveFailures = 0
		current.UpdatedAt = completed.Format(time.RFC3339Nano)
		return nil
	})
	if err != nil {
		return err
	}
	scheduler.event(ctx, "AUTOMATIC_SIGNED_UPDATE_STAGED", map[string]any{"update_id": operation.UpdateID, "gateway_version": operation.GatewayVersion, "channel": operation.SourceChannel, "source_reference": operation.SourceReference})
	return scheduler.maybeApply(ctx, policy, status, completed)
}

func (scheduler *Scheduler) maybeApply(ctx context.Context, policy updatepkg.AutomationPolicy, status Status, now time.Time) error {
	if !policy.AutomaticApplyEnabled {
		_, err := scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
			current.Phase = PhaseStaged
			current.NextApplyAt = ""
			current.UpdatedAt = now.Format(time.RFC3339Nano)
			return nil
		})
		return err
	}
	if deadlineDue(status.ApplyDeadlineAt, now) {
		_, err := scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
			current.Phase = PhaseManualAttention
			current.NextApplyAt = ""
			current.LastCompletedAt = now.Format(time.RFC3339Nano)
			current.LastResultCode = "MANUAL_ATTENTION_REQUIRED"
			current.LastErrorCode = "AUTO_APPLY_DEADLINE_EXPIRED"
			current.UpdatedAt = now.Format(time.RFC3339Nano)
			return nil
		})
		if err == nil {
			_ = scheduler.State.AppendEvent(ctx, state.EventInput{Severity: "WARNING", Type: "AUTOMATIC_UPDATE_APPLY_DEADLINE_EXPIRED", Details: map[string]any{
				"update_id": status.StagedUpdateID, "gateway_version": status.StagedVersion,
				"staged_at": status.StagedAt, "apply_deadline_at": status.ApplyDeadlineAt,
			}})
		}
		return err
	}
	if !insideMaintenanceWindow(policy, now) {
		next := nextMaintenanceStart(policy, now)
		_, err := scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
			current.Phase = PhaseWaitingWindow
			current.NextApplyAt = next.Format(time.RFC3339Nano)
			current.LastResultCode = "WAITING_MAINTENANCE_WINDOW"
			current.LastErrorCode = ""
			current.UpdatedAt = now.Format(time.RFC3339Nano)
			return nil
		})
		return err
	}
	latest, err := scheduler.Policy.Get(ctx)
	if err != nil {
		return err
	}
	if latest.UpdatedAt != policy.UpdatedAt || latest.Channel != policy.Channel || !latest.AutomaticApplyEnabled {
		return nil
	}
	if stop, err := scheduler.maintenance(ctx, now); err != nil || stop {
		return err
	}
	readinessContext, cancelReadiness := context.WithTimeout(ctx, 10*time.Second)
	reason, readinessErr := scheduler.Readiness.Check(readinessContext, now)
	cancelReadiness()
	if readinessErr != nil {
		_, persistErr := scheduler.applyDeferred(ctx, status, now, "AUTO_READINESS_UNAVAILABLE")
		return persistErr
	}
	if reason != "" {
		_, persistErr := scheduler.applyDeferred(ctx, status, now, reason)
		return persistErr
	}
	blockContext, cancelBlock := context.WithTimeout(ctx, 15*time.Second)
	err = scheduler.Path.BlockPath(blockContext)
	cancelBlock()
	if err != nil {
		_, persistErr := scheduler.applyDeferred(ctx, status, now, "AUTO_PATH_BLOCK_FAILED")
		return persistErr
	}
	if _, _, err := scheduler.State.Block(ctx, state.GatewayBlocked, "AUTOMATIC_SIGNED_UPDATE_APPLY_REQUESTED"); err != nil {
		_, persistErr := scheduler.applyDeferred(ctx, status, now, "AUTO_STATE_BLOCK_FAILED")
		return persistErr
	}
	status, err = scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseApplyIntent
		current.ApplyIntentAt = now.Format(time.RFC3339Nano)
		current.ApplyObservedAt = ""
		current.NextApplyAt = ""
		current.LastAttemptAt = now.Format(time.RFC3339Nano)
		current.LastResultCode = "APPLY_INTENT_DURABLE"
		current.LastErrorCode = ""
		current.UpdatedAt = now.Format(time.RFC3339Nano)
		return nil
	})
	if err != nil {
		return err
	}
	scheduler.event(ctx, "AUTOMATIC_SIGNED_UPDATE_APPLY_REQUESTED", map[string]any{"update_id": status.StagedUpdateID, "gateway_version": status.StagedVersion, "channel": policy.Channel})
	dispatchContext, cancelDispatch := context.WithTimeout(ctx, 15*time.Second)
	dispatchErr := scheduler.Apply.ApplyPendingUpdate(dispatchContext)
	cancelDispatch()
	dispatchedAt := scheduler.now()
	if dispatchErr != nil {
		_, err = scheduler.outcomeUnknown(ctx, status, dispatchedAt, "AUTO_APPLY_DISPATCH_UNKNOWN")
		return err
	}
	_, err = scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseApplyDispatched
		current.ApplyObservedAt = dispatchedAt.Format(time.RFC3339Nano)
		current.LastCompletedAt = dispatchedAt.Format(time.RFC3339Nano)
		current.LastResultCode = "APPLY_DISPATCHED"
		current.LastErrorCode = ""
		current.UpdatedAt = dispatchedAt.Format(time.RFC3339Nano)
		return nil
	})
	return err
}

func (scheduler *Scheduler) maintenance(ctx context.Context, now time.Time) (bool, error) {
	statusContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	status, err := scheduler.Apply.MaintenanceStatus(statusContext)
	cancel()
	if err != nil {
		_, persistErr := scheduler.suppress(ctx, Status{}, now, "MAINTENANCE_STATUS_UNAVAILABLE", maintenanceRetry)
		return true, persistErr
	}
	if status.Active {
		code := status.ReasonCode
		if !codePattern.MatchString(code) || code == "" {
			code = "MAINTENANCE_ACTIVE"
		}
		_, err := scheduler.suppress(ctx, Status{}, now, code, maintenanceRetry)
		return true, err
	}
	return false, nil
}

func (scheduler *Scheduler) suppress(ctx context.Context, _ Status, now time.Time, code string, retry time.Duration) (Status, error) {
	return scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseSuppressed
		current.LastResultCode = "AUTOMATION_SUPPRESSED"
		current.LastErrorCode = code
		if current.StagedUpdateID != "" {
			current.NextApplyAt = now.Add(retry).Format(time.RFC3339Nano)
		} else {
			current.NextCheckAt = now.Add(retry).Format(time.RFC3339Nano)
		}
		current.UpdatedAt = now.Format(time.RFC3339Nano)
		return nil
	})
}

func (scheduler *Scheduler) fail(ctx context.Context, _ Status, now time.Time, code string, retryCheck bool) (Status, error) {
	return scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseFailed
		current.LastCompletedAt = now.Format(time.RFC3339Nano)
		current.LastResultCode = "AUTOMATION_FAILED"
		current.LastErrorCode = code
		if current.ConsecutiveFailures < 100 {
			current.ConsecutiveFailures++
		}
		if retryCheck {
			current.NextCheckAt = now.Add(failureBackoff(current.ConsecutiveFailures)).Format(time.RFC3339Nano)
		}
		current.UpdatedAt = now.Format(time.RFC3339Nano)
		return nil
	})
}

func (scheduler *Scheduler) applyDeferred(ctx context.Context, status Status, now time.Time, code string) (Status, error) {
	return scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseStaged
		current.LastCompletedAt = now.Format(time.RFC3339Nano)
		current.LastResultCode = "AUTO_APPLY_DEFERRED"
		current.LastErrorCode = code
		current.NextApplyAt = now.Add(applyRetry).Format(time.RFC3339Nano)
		if current.ConsecutiveFailures < 100 {
			current.ConsecutiveFailures++
		}
		current.UpdatedAt = now.Format(time.RFC3339Nano)
		return nil
	})
}

func (scheduler *Scheduler) outcomeUnknown(ctx context.Context, _ Status, now time.Time, code string) (Status, error) {
	return scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		current.Phase = PhaseOutcomeUnknown
		current.LastCompletedAt = now.Format(time.RFC3339Nano)
		current.LastResultCode = "OUTCOME_UNKNOWN"
		current.LastErrorCode = code
		current.NextApplyAt = ""
		current.UpdatedAt = now.Format(time.RFC3339Nano)
		return nil
	})
}

func (scheduler *Scheduler) finish(ctx context.Context, _ Status, policy updatepkg.AutomationPolicy, now time.Time, resultCode, errorCode string) (Status, error) {
	return scheduler.Repository.UpdateOwned(ctx, scheduler.Owner, func(current *Status) error {
		if errorCode == "" {
			current.Phase = PhaseSucceeded
			current.ConsecutiveFailures = 0
		} else {
			current.Phase = PhaseFailed
			if current.ConsecutiveFailures < 100 {
				current.ConsecutiveFailures++
			}
		}
		current.LastCompletedAt = now.Format(time.RFC3339Nano)
		current.LastResultCode = resultCode
		current.LastErrorCode = errorCode
		current.CandidateVersion = ""
		current.CandidateReference = ""
		current.CandidatePublishedAt = ""
		current.StagedUpdateID = ""
		current.StagedVersion = ""
		current.StagedAt = ""
		current.ApplyDeadlineAt = ""
		current.ApplyIntentAt = ""
		current.ApplyObservedAt = ""
		current.NextApplyAt = ""
		current.NextCheckAt = nextRegularCheck(policy, current.JitterOffsetMinutes, now)
		current.UpdatedAt = now.Format(time.RFC3339Nano)
		return nil
	})
}

func (scheduler *Scheduler) renewLease(ctx context.Context, cancel context.CancelFunc, done <-chan struct{}, result chan<- error, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if err := scheduler.Repository.Renew(ctx, scheduler.Owner, scheduler.now(), leaseDuration); err != nil {
				select {
				case result <- err:
				default:
				}
				cancel()
				return
			}
		}
	}
}

func (scheduler *Scheduler) leaseResult(result <-chan error) error {
	select {
	case err := <-result:
		return err
	default:
		return nil
	}
}

func (scheduler *Scheduler) event(ctx context.Context, eventType string, details map[string]any) {
	if scheduler.State == nil {
		return
	}
	_ = scheduler.State.AppendEvent(ctx, state.EventInput{Severity: "INFO", Type: eventType, Details: details})
}

func (scheduler *Scheduler) validate() error {
	if scheduler == nil || scheduler.Repository.Database == nil || scheduler.Policy == nil || scheduler.Policy.Database != scheduler.Repository.Database || scheduler.Remote == nil || scheduler.Stager == nil || scheduler.Apply == nil || scheduler.Path == nil || scheduler.State == nil || scheduler.Readiness == nil || !validOwner(scheduler.Owner) {
		return errors.New("software update scheduler is not safely configured")
	}
	return nil
}

func (scheduler *Scheduler) now() time.Time {
	if scheduler.Now != nil {
		return scheduler.Now().UTC()
	}
	return time.Now().UTC()
}

func deterministicJitter(policy updatepkg.AutomationPolicy) int {
	if policy.JitterMinutes <= 0 {
		return 0
	}
	digest := sha256.Sum256([]byte(policy.UpdatedAt + "\x00" + policy.Channel))
	value := uint64(digest[0])<<56 | uint64(digest[1])<<48 | uint64(digest[2])<<40 | uint64(digest[3])<<32 |
		uint64(digest[4])<<24 | uint64(digest[5])<<16 | uint64(digest[6])<<8 | uint64(digest[7])
	return int(value % uint64(policy.JitterMinutes+1))
}

func nextRegularCheck(policy updatepkg.AutomationPolicy, jitterMinutes int, now time.Time) string {
	return now.UTC().Add(time.Duration(policy.CheckIntervalHours)*time.Hour + time.Duration(jitterMinutes)*time.Minute).Format(time.RFC3339Nano)
}

func deadlineDue(value string, now time.Time) bool {
	if value == "" {
		return true
	}
	deadline, err := time.Parse(time.RFC3339Nano, value)
	return err != nil || !deadline.After(now)
}

func failureBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	delay := 5 * time.Minute
	for count := 1; count < failures && delay < 6*time.Hour; count++ {
		delay *= 2
	}
	if delay > 6*time.Hour {
		return 6 * time.Hour
	}
	return delay
}

func validAvailableCandidate(available updateremote.Available, channel string) bool {
	if !available.Available || available.Channel != channel || updatepkg.ValidateGatewayVersion(available.CandidateVersion) != nil || available.ReleaseTag != "v"+available.CandidateVersion || available.ArtifactBytes <= 0 || available.ArtifactBytes > updatepkg.MaximumArchiveBytes || !digestPattern.MatchString(available.ArtifactSHA256) {
		return false
	}
	if _, err := time.Parse(time.RFC3339, available.PublishedAt); err != nil {
		return false
	}
	status := Status{Phase: PhaseCandidate, Channel: channel, CandidateVersion: available.CandidateVersion, CandidateReference: available.SourceReference, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	return status.validateCandidateOnly() == nil
}

func setStagingEvidence(status *Status, operation updatepkg.Operation, policy updatepkg.AutomationPolicy) error {
	if status == nil || operation.UpdateID == "" || operation.GatewayVersion == "" {
		return errors.New("automatic staging evidence is incomplete")
	}
	staged, err := time.Parse(time.RFC3339Nano, operation.CreatedAt)
	if err != nil || staged.IsZero() {
		return errors.New("automatic staging timestamp is invalid")
	}
	status.StagedAt = staged.UTC().Format(time.RFC3339Nano)
	status.ApplyDeadlineAt = staged.UTC().Add(time.Duration(policy.MaximumApplyDelayHours) * time.Hour).Format(time.RFC3339Nano)
	return nil
}

func insideMaintenanceWindow(policy updatepkg.AutomationPolicy, now time.Time) bool {
	if !policy.MaintenanceWindowEnabled {
		return false
	}
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	for _, day := range []time.Time{today.Add(-24 * time.Hour), today} {
		start := day.Add(time.Duration(policy.MaintenanceStartMinuteUTC) * time.Minute)
		if !now.Before(start) && now.Before(start.Add(time.Duration(policy.MaintenanceDurationMinutes)*time.Minute)) {
			return true
		}
	}
	return false
}

func nextMaintenanceStart(policy updatepkg.AutomationPolicy, now time.Time) time.Time {
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := today.Add(time.Duration(policy.MaintenanceStartMinuteUTC) * time.Minute)
	if start.After(now) {
		return start
	}
	return start.Add(24 * time.Hour)
}

func (status Status) String() string {
	return fmt.Sprintf("%s/%s", status.Phase, status.LastResultCode)
}
