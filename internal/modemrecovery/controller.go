package modemrecovery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Controller struct {
	Repository *Repository
	Executor   ActionExecutor
	mutex      sync.Mutex
}

type ObservationBatch struct {
	Healthy  []string
	Failures map[string]string
}

func (controller *Controller) RecoverInterrupted(ctx context.Context) (int64, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	if controller.Repository == nil {
		return 0, errors.New("modem recovery repository is required")
	}
	return controller.Repository.RecoverInterrupted(ctx)
}

func (controller *Controller) Observe(ctx context.Context, batch ObservationBatch) []error {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	if controller.Repository == nil || controller.Executor == nil {
		return []error{errors.New("complete modem recovery controller is required")}
	}
	var result []error
	seen := make(map[string]struct{}, len(batch.Healthy)+len(batch.Failures))
	for _, uplinkID := range batch.Healthy {
		if _, duplicate := seen[uplinkID]; duplicate {
			continue
		}
		seen[uplinkID] = struct{}{}
		if err := controller.Repository.ObserveHealthy(ctx, uplinkID); err != nil {
			result = append(result, fmt.Errorf("mark modem %s physically healthy: %w", uplinkID, err))
		}
	}
	for uplinkID, reason := range batch.Failures {
		if _, duplicate := seen[uplinkID]; duplicate {
			result = append(result, fmt.Errorf("modem %s is both healthy and failed in one observation", uplinkID))
			continue
		}
		seen[uplinkID] = struct{}{}
		if _, err := controller.handleLocked(ctx, uplinkID, reason, RequestedBySystem, false); err != nil && !errors.Is(err, ErrBudgetExhausted) {
			result = append(result, fmt.Errorf("recover modem %s: %w", uplinkID, err))
		}
	}
	return result
}

func (controller *Controller) Request(ctx context.Context, uplinkID, failureReason string) (Result, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	if failureReason == FailureNone {
		return Result{UplinkID: uplinkID, State: "NO_PHYSICAL_FAILURE", ReasonCode: "NO_PHYSICAL_FAILURE"}, ErrNoPhysicalFailure
	}
	return controller.handleLocked(ctx, uplinkID, failureReason, RequestedByUser, true)
}

func (controller *Controller) Snapshot(ctx context.Context, uplinkID string, limit int) (Snapshot, error) {
	if controller == nil || controller.Repository == nil {
		return Snapshot{}, errors.New("modem recovery repository is required")
	}
	return controller.Repository.Snapshot(ctx, uplinkID, limit)
}

func (controller *Controller) UpdatePolicy(ctx context.Context, uplinkID string, input PolicyUpdate) (Policy, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	if controller.Repository == nil {
		return Policy{}, errors.New("modem recovery repository is required")
	}
	return controller.Repository.UpdatePolicy(ctx, uplinkID, input)
}

func (controller *Controller) handleLocked(ctx context.Context, uplinkID, failureReason, requestedBy string, manual bool) (Result, error) {
	if controller.Repository == nil || controller.Executor == nil {
		return Result{}, errors.New("complete modem recovery controller is required")
	}
	snapshot, err := controller.Repository.PrepareFailure(ctx, uplinkID, failureReason)
	if err != nil {
		return Result{}, err
	}
	if snapshot.Runtime.ActiveAttemptID != "" {
		return Result{UplinkID: uplinkID, State: "ALREADY_RUNNING", AttemptID: snapshot.Runtime.ActiveAttemptID, ReasonCode: "ATTEMPT_ALREADY_RUNNING"}, nil
	}
	if !snapshot.Policy.Enabled {
		_ = controller.Repository.SetWaiting(ctx, uplinkID, "AUTOMATIC_RECOVERY_DISABLED", time.Time{})
		return Result{UplinkID: uplinkID, State: "SUPPRESSED", ReasonCode: "AUTOMATIC_RECOVERY_DISABLED"}, nil
	}
	now := controller.Repository.now()
	if until, ok := parseTime(snapshot.Runtime.CooldownUntil); ok && now.Before(until) && !manual {
		return Result{UplinkID: uplinkID, State: "COOLDOWN", ReasonCode: "RECOVERY_COOLDOWN", NextCheckAt: until.Format(time.RFC3339Nano)}, ErrBudgetExhausted
	}
	decision := chooseAction(snapshot, failureReason, now, manual)
	if decision.Action == "" {
		if err := controller.Repository.SetWaiting(ctx, uplinkID, decision.ReasonCode, decision.NextCheck); err != nil {
			return Result{}, err
		}
		result := Result{UplinkID: uplinkID, State: decision.State, ReasonCode: decision.ReasonCode}
		if !decision.NextCheck.IsZero() {
			result.NextCheckAt = decision.NextCheck.Format(time.RFC3339Nano)
		}
		return result, nil
	}
	attempt, err := controller.Repository.BeginAttempt(ctx, uplinkID, decision.Action, requestedBy, failureReason)
	if err != nil {
		if errors.Is(err, ErrBudgetExhausted) {
			_ = controller.Repository.SetWaiting(ctx, uplinkID, "RECOVERY_BUDGET_EXHAUSTED", time.Time{})
			return Result{UplinkID: uplinkID, State: "SUPPRESSED", Action: decision.Action, ReasonCode: "RECOVERY_BUDGET_EXHAUSTED"}, nil
		}
		return Result{}, err
	}
	command := Command{UplinkID: uplinkID, PolicyGeneration: attempt.PolicyGeneration, Action: attempt.Action}
	executeErr := controller.Executor.Execute(ctx, command)
	status, outcome := AttemptSucceeded, "ACTION_COMPLETED"
	cooldown := actionCooldown(snapshot.Policy, attempt.Action)
	switch {
	case executeErr == nil:
	case errors.Is(executeErr, ErrDeviceRemoved):
		status, outcome = AttemptDeviceRemoved, "DEVICE_REMOVED_DURING_RECOVERY"
	case errors.Is(executeErr, ErrActionUnsupported):
		status, outcome = AttemptSuppressed, "HARDWARE_ACTION_NOT_AVAILABLE"
	case errors.Is(executeErr, ErrStaleGeneration):
		status, outcome = AttemptFailed, "STALE_POLICY_GENERATION"
	default:
		status, outcome = AttemptFailed, "ACTION_FAILED"
	}
	if finishErr := controller.Repository.FinishAttempt(ctx, attempt, status, outcome, cooldown); finishErr != nil {
		return Result{}, finishErr
	}
	result := Result{UplinkID: uplinkID, State: "ATTEMPT_FINISHED", Action: attempt.Action, AttemptID: attempt.ID, Status: status, ReasonCode: outcome}
	if cooldown > 0 {
		result.NextCheckAt = now.Add(cooldown).Format(time.RFC3339Nano)
	}
	return result, nil
}

type actionDecision struct {
	Action     string
	State      string
	ReasonCode string
	NextCheck  time.Time
}

type recoveryStage struct {
	Action string
	After  time.Duration
}

func chooseAction(snapshot Snapshot, failureReason string, now time.Time, manual bool) actionDecision {
	started, ok := parseTime(snapshot.Runtime.FailureStartedAt)
	if !ok {
		started = now
	}
	elapsed := now.Sub(started)
	policy := snapshot.Policy
	stages := stagesForFailure(policy, failureReason)
	attempted := make(map[string]bool)
	for _, attempt := range snapshot.Attempts {
		attemptTime, parsed := parseTime(attempt.StartedAt)
		if parsed && !attemptTime.Before(started) {
			attempted[attempt.Action] = true
		}
	}
	var next time.Time
	for _, stage := range stages {
		if attempted[stage.Action] {
			continue
		}
		due := stage.After
		if manual && (stage.Action == ActionDHCPRenew || stage.Action == ActionHiLinkAPIReconnect) {
			due = 0
		}
		if elapsed >= due {
			return actionDecision{Action: stage.Action, State: "READY", ReasonCode: "ACTION_DUE"}
		}
		candidate := started.Add(due)
		if next.IsZero() || candidate.Before(next) {
			next = candidate
		}
	}
	if !next.IsZero() {
		return actionDecision{State: "OBSERVING", ReasonCode: "FAILURE_HYSTERESIS", NextCheck: next}
	}
	if failureReason == FailureDeviceAbsent && !policy.AllowHubPortPowerCycle {
		return actionDecision{State: "WAITING_FOR_DEVICE", ReasonCode: "DEVICE_ABSENT_NO_SAFE_ACTION"}
	}
	return actionDecision{State: "SUPPRESSED", ReasonCode: "RECOVERY_LADDER_EXHAUSTED"}
}

func stagesForFailure(policy Policy, failureReason string) []recoveryStage {
	seconds := func(value int) time.Duration { return time.Duration(value) * time.Second }
	switch failureReason {
	case FailureDHCPLeaseMissing:
		return []recoveryStage{
			{Action: ActionDHCPRenew, After: seconds(policy.DHCPRetryAfterSeconds)},
			{Action: ActionUSBDriverRebind, After: seconds(policy.USBRebindAfterSeconds)},
			{Action: ActionUSBDeviceReset, After: seconds(policy.USBResetAfterSeconds)},
		}
	case FailureManagementUnreachable:
		return []recoveryStage{
			{Action: ActionHiLinkAPIReconnect, After: seconds(policy.APIRetryAfterSeconds)},
			{Action: ActionMobileSessionRestart, After: seconds(policy.MobileSessionRestartAfterSeconds)},
			{Action: ActionUSBDriverRebind, After: seconds(policy.USBRebindAfterSeconds)},
			{Action: ActionUSBDeviceReset, After: seconds(policy.USBResetAfterSeconds)},
		}
	case FailureCarrierDown:
		return []recoveryStage{
			{Action: ActionUSBDriverRebind, After: seconds(policy.USBRebindAfterSeconds)},
			{Action: ActionUSBDeviceReset, After: seconds(policy.USBResetAfterSeconds)},
		}
	case FailureDeviceAbsent:
		if policy.AllowHubPortPowerCycle {
			return []recoveryStage{{Action: ActionUSBPortPowerCycle, After: seconds(policy.USBResetAfterSeconds)}}
		}
	}
	return nil
}

func actionCooldown(policy Policy, action string) time.Duration {
	switch action {
	case ActionUSBDeviceReset, ActionUSBPortPowerCycle:
		return time.Duration(policy.USBResetCooldownSeconds) * time.Second
	case ActionUSBDriverRebind:
		return time.Minute
	case ActionMobileSessionRestart:
		return time.Duration(policy.APIRetryAfterSeconds) * time.Second
	case ActionHiLinkAPIReconnect:
		return time.Duration(policy.APIRetryAfterSeconds) * time.Second
	default:
		return time.Duration(policy.DHCPRetryAfterSeconds) * time.Second
	}
}
