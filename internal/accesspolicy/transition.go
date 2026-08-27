package accesspolicy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type SelectionRuntime struct {
	PendingCandidateKey   string
	PendingCandidateSince string
	LastSwitchAt          string
	LastSwitchReason      string
	TemporaryDirectOnly   bool
	TemporaryDirectBootID string
	UpdatedAt             string
}

type TransitionInput struct {
	CurrentKey     string
	ProposedKey    string
	CurrentHealthy bool
	HardFailure    bool
	Policy         Policy
	Runtime        SelectionRuntime
	Now            time.Time
}

type TransitionDecision struct {
	Allow        bool
	TrackPending bool
	ClearPending bool
	Reason       string
}

func EvaluateTransition(input TransitionInput) (TransitionDecision, error) {
	if strings.TrimSpace(input.ProposedKey) == "" || input.Now.IsZero() {
		return TransitionDecision{}, errors.New("proposed access candidate and current time are required")
	}
	if input.ProposedKey == input.CurrentKey && input.HardFailure {
		return TransitionDecision{Allow: true, ClearPending: true, Reason: "HARD_FAILURE_REACTIVATE"}, nil
	}
	if input.ProposedKey == input.CurrentKey {
		return TransitionDecision{ClearPending: input.Runtime.PendingCandidateKey != "", Reason: "CURRENT_PATH_REMAINS_BEST"}, nil
	}
	if input.CurrentKey == "" {
		return TransitionDecision{Allow: true, ClearPending: true, Reason: "NO_ACTIVE_PATH"}, nil
	}
	if input.HardFailure {
		return TransitionDecision{Allow: true, ClearPending: true, Reason: "HARD_FAILURE_FAST_PATH"}, nil
	}
	wait := time.Duration(input.Policy.FailureHoldSeconds) * time.Second
	reason := "FAILURE_HOLD"
	if input.CurrentHealthy {
		wait = time.Duration(input.Policy.RecoveryStableSeconds) * time.Second
		reason = "RECOVERY_STABLE"
	}
	if input.Runtime.PendingCandidateKey != input.ProposedKey || input.Runtime.PendingCandidateSince == "" {
		return TransitionDecision{TrackPending: true, Reason: reason + "_STARTED"}, nil
	}
	since, err := time.Parse(time.RFC3339Nano, input.Runtime.PendingCandidateSince)
	if err != nil || since.After(input.Now) {
		return TransitionDecision{}, errors.New("stored pending access candidate time is invalid")
	}
	if input.Now.Sub(since) < wait {
		return TransitionDecision{Reason: reason + "_PENDING"}, nil
	}
	if input.Runtime.LastSwitchAt != "" {
		lastSwitch, err := time.Parse(time.RFC3339Nano, input.Runtime.LastSwitchAt)
		if err != nil || lastSwitch.After(input.Now) {
			return TransitionDecision{}, errors.New("stored access switch time is invalid")
		}
		cooldown := time.Duration(input.Policy.SwitchCooldownSeconds) * time.Second
		if input.Now.Sub(lastSwitch) < cooldown {
			return TransitionDecision{Reason: "SWITCH_COOLDOWN"}, nil
		}
	}
	return TransitionDecision{Allow: true, ClearPending: true, Reason: reason + "_SATISFIED"}, nil
}

func (repository *Repository) GetSelectionRuntime(ctx context.Context) (SelectionRuntime, error) {
	if repository == nil || repository.database == nil {
		return SelectionRuntime{}, errors.New("access policy database is required")
	}
	var result SelectionRuntime
	var pendingKey, pendingSince, lastSwitch, lastReason, bootID sql.NullString
	var directOnly int
	err := repository.database.QueryRowContext(ctx, `
SELECT pending_candidate_key, pending_candidate_since, last_switch_at,
       last_switch_reason, temporary_direct_only, temporary_direct_boot_id,
       updated_at
FROM access_selection_runtime WHERE singleton_id=1`).Scan(
		&pendingKey, &pendingSince, &lastSwitch, &lastReason,
		&directOnly, &bootID, &result.UpdatedAt,
	)
	if err != nil {
		return SelectionRuntime{}, fmt.Errorf("read access selection runtime: %w", err)
	}
	result.PendingCandidateKey = pendingKey.String
	result.PendingCandidateSince = pendingSince.String
	result.LastSwitchAt = lastSwitch.String
	result.LastSwitchReason = lastReason.String
	result.TemporaryDirectOnly = directOnly != 0
	result.TemporaryDirectBootID = bootID.String
	return result, nil
}

func (repository *Repository) TrackPendingCandidate(ctx context.Context, candidateKey string) error {
	if strings.TrimSpace(candidateKey) == "" || len(candidateKey) > 512 {
		return errors.New("pending access candidate key is invalid")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	_, err := repository.database.ExecContext(ctx, `
UPDATE access_selection_runtime
SET pending_candidate_since=CASE
        WHEN pending_candidate_key=? THEN pending_candidate_since
        ELSE ?
    END,
    pending_candidate_key=?, updated_at=?
WHERE singleton_id=1`, candidateKey, now, candidateKey, now)
	if err != nil {
		return fmt.Errorf("track pending access candidate: %w", err)
	}
	return nil
}

func (repository *Repository) ClearPendingCandidate(ctx context.Context) error {
	now := repository.now().UTC().Format(time.RFC3339Nano)
	_, err := repository.database.ExecContext(ctx, `
UPDATE access_selection_runtime
SET pending_candidate_key=NULL, pending_candidate_since=NULL, updated_at=?
WHERE singleton_id=1`, now)
	if err != nil {
		return fmt.Errorf("clear pending access candidate: %w", err)
	}
	return nil
}

func (repository *Repository) MarkSwitched(ctx context.Context, reason string) error {
	if strings.TrimSpace(reason) == "" || len(reason) > 128 {
		return errors.New("access switch reason is invalid")
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	_, err := repository.database.ExecContext(ctx, `
UPDATE access_selection_runtime
SET pending_candidate_key=NULL, pending_candidate_since=NULL,
    last_switch_at=?, last_switch_reason=?, updated_at=?
WHERE singleton_id=1`, now, reason, now)
	if err != nil {
		return fmt.Errorf("record access switch: %w", err)
	}
	return nil
}

// ReconcileBoot resets temporary direct-only when the host boot ID changes.
// A process restart in the same boot intentionally preserves the emergency
// mode; a host reboot always returns to the permanent ordered policy.
func (repository *Repository) ReconcileBoot(ctx context.Context, bootID string) (bool, error) {
	if !safeBootID(bootID) {
		return false, errors.New("boot id is invalid")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin access boot reconciliation: %w", err)
	}
	defer transaction.Rollback()
	var enabled int
	var stored sql.NullString
	if err := transaction.QueryRowContext(ctx, "SELECT temporary_direct_only, temporary_direct_boot_id FROM access_selection_runtime WHERE singleton_id=1").Scan(&enabled, &stored); err != nil {
		return false, fmt.Errorf("read temporary direct-only state: %w", err)
	}
	if enabled == 0 || stored.String == bootID {
		return false, transaction.Commit()
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
UPDATE access_selection_runtime
SET temporary_direct_only=0, temporary_direct_boot_id=NULL, updated_at=?
WHERE singleton_id=1`, now); err != nil {
		return false, fmt.Errorf("reset temporary direct-only state: %w", err)
	}
	if err := appendAccessEvent(ctx, transaction, now, "TEMPORARY_DIRECT_ONLY_RESET_AFTER_REBOOT", map[string]any{}); err != nil {
		return false, err
	}
	return true, transaction.Commit()
}

func (repository *Repository) SetTemporaryDirectOnly(ctx context.Context, enabled bool, bootID string) error {
	if enabled && !safeBootID(bootID) {
		return errors.New("boot id is required for temporary direct-only mode")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin temporary direct-only update: %w", err)
	}
	defer transaction.Rollback()
	now := repository.now().UTC().Format(time.RFC3339Nano)
	var storedBoot any
	if enabled {
		storedBoot = bootID
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE access_selection_runtime
SET temporary_direct_only=?, temporary_direct_boot_id=?, updated_at=?
WHERE singleton_id=1`, boolInt(enabled), storedBoot, now); err != nil {
		return fmt.Errorf("update temporary direct-only mode: %w", err)
	}
	if err := appendAccessEvent(ctx, transaction, now, "TEMPORARY_DIRECT_ONLY_CHANGED", map[string]any{"enabled": enabled}); err != nil {
		return err
	}
	return transaction.Commit()
}

func safeBootID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, current := range value {
		if current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z' || current >= '0' && current <= '9' || current == '-' {
			continue
		}
		return false
	}
	return true
}
