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

type BootReconciliation struct {
	NewBoot                    bool
	StartupBlockUntilQualified bool
	TemporaryDirectOnlyReset   bool
	QualificationInvalidated   bool
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

// ReconcileBoot atomically records the current host boot, resets boot-scoped
// temporary direct-only state, and invalidates old qualification evidence when
// the configured startup gate is enabled. A same-boot process restart leaves
// both the active tuple and its evidence untouched.
func (repository *Repository) ReconcileBoot(ctx context.Context, bootID string) (BootReconciliation, error) {
	if !safeBootID(bootID) {
		return BootReconciliation{}, errors.New("boot id is invalid")
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return BootReconciliation{}, fmt.Errorf("begin access boot reconciliation: %w", err)
	}
	defer transaction.Rollback()
	var startupBlock, directOnly int
	var directBootID, observedBootID sql.NullString
	if err := transaction.QueryRowContext(ctx, `
SELECT p.startup_block_until_qualified, r.temporary_direct_only,
       r.temporary_direct_boot_id, r.observed_boot_id
FROM access_policy AS p
JOIN access_selection_runtime AS r ON r.singleton_id=p.singleton_id
WHERE p.singleton_id=1`).Scan(&startupBlock, &directOnly, &directBootID, &observedBootID); err != nil {
		return BootReconciliation{}, fmt.Errorf("read access boot state: %w", err)
	}
	result := BootReconciliation{
		NewBoot:                    !observedBootID.Valid || observedBootID.String != bootID,
		StartupBlockUntilQualified: startupBlock != 0,
		TemporaryDirectOnlyReset:   directOnly != 0 && directBootID.String != bootID,
	}
	if !result.NewBoot && !result.TemporaryDirectOnlyReset {
		return result, transaction.Commit()
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if result.TemporaryDirectOnlyReset {
		if _, err := transaction.ExecContext(ctx, `
UPDATE access_selection_runtime
SET temporary_direct_only=0, temporary_direct_boot_id=NULL, updated_at=?
		WHERE singleton_id=1`, now); err != nil {
			return BootReconciliation{}, fmt.Errorf("reset temporary direct-only state: %w", err)
		}
		if err := appendAccessEvent(ctx, transaction, now, "TEMPORARY_DIRECT_ONLY_RESET_AFTER_REBOOT", map[string]any{}); err != nil {
			return BootReconciliation{}, err
		}
	}
	if result.NewBoot {
		if result.StartupBlockUntilQualified {
			if err := invalidateBootQualification(ctx, transaction, now); err != nil {
				return BootReconciliation{}, err
			}
			result.QualificationInvalidated = true
		}
		if _, err := transaction.ExecContext(ctx, `
UPDATE access_selection_runtime
SET observed_boot_id=?, pending_candidate_key=NULL,
    pending_candidate_since=NULL, updated_at=?
WHERE singleton_id=1`, bootID, now); err != nil {
			return BootReconciliation{}, fmt.Errorf("record reconciled host boot: %w", err)
		}
		if err := appendAccessEvent(ctx, transaction, now, "HOST_BOOT_RECONCILED", map[string]any{
			"startup_block_until_qualified": result.StartupBlockUntilQualified,
			"qualification_invalidated":     result.QualificationInvalidated,
		}); err != nil {
			return BootReconciliation{}, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return BootReconciliation{}, fmt.Errorf("commit access boot reconciliation: %w", err)
	}
	return result, nil
}

func invalidateBootQualification(ctx context.Context, transaction *sql.Tx, now string) error {
	statements := []struct {
		name string
		SQL  string
	}{
		{name: "subscription paths", SQL: `
UPDATE subscription_modem_paths
SET state='STALE', transport_state='UNKNOWN', selected_node_id=NULL,
    candidate_nodes=0, qualified_nodes=0,
    required_targets_passed=0, required_targets_total=0,
    optional_targets_passed=0, optional_targets_total=0,
    quality_class='UNKNOWN', functional_score=0, latency_ms=NULL,
    last_checked_at=NULL, expires_at=NULL, updated_at=?`},
		{name: "subscription nodes", SQL: `
UPDATE path_nodes
SET qualification_state='STALE', qualification_expires_at=NULL,
    latency_ms=NULL, failure_code=NULL`},
		{name: "subscription target evidence", SQL: "DELETE FROM path_node_target_results"},
		{name: "direct paths", SQL: `
UPDATE direct_modem_paths
SET state='STALE', transport_state='UNKNOWN', quality_class='UNKNOWN',
    functional_score=0, required_targets_passed=0, required_targets_total=0,
    optional_targets_passed=0, optional_targets_total=0, latency_ms=NULL,
    last_checked_at=NULL, expires_at=NULL, failure_code=NULL, updated_at=?`},
		{name: "direct target evidence", SQL: "DELETE FROM direct_path_target_results"},
		{name: "periodic schedules", SQL: `
UPDATE path_health_runtime
SET next_probe_at=?, last_probe_at=NULL, last_result='UNKNOWN',
    consecutive_successes=0, consecutive_failures=0,
    deferred_reason=NULL, updated_at=?`},
	}
	for _, statement := range statements {
		arguments := []any{}
		switch statement.name {
		case "subscription paths", "direct paths":
			arguments = []any{now}
		case "periodic schedules":
			arguments = []any{now, now}
		}
		if _, err := transaction.ExecContext(ctx, statement.SQL, arguments...); err != nil {
			return fmt.Errorf("invalidate boot %s: %w", statement.name, err)
		}
	}
	return nil
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
