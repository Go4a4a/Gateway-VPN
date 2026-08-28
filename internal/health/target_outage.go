package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gateway-vpn/internal/store"
)

const (
	TargetNormal  = "NORMAL"
	TargetSuspect = "TARGET_SUSPECT"
)

type TargetOutageConfig struct {
	FailureCombinations          int
	FailureDistinctModems        int
	FailureDistinctSubscriptions int
	RecoveryCombinations         int
	RecoveryDistinctModems       int
}

type TargetAssessment struct {
	TargetID                     string
	PreviousState                string
	State                        string
	Changed                      bool
	FailureCombinations          int
	SuccessCombinations          int
	DistinctFailureModems        int
	DistinctFailureSubscriptions int
}

type TargetObservation struct {
	ModemID        string
	SubscriptionID string
	Passed         bool
}

type TargetOutageEvaluator struct {
	Database *sql.DB
	Config   TargetOutageConfig
	Now      func() time.Time
}

func (evaluator TargetOutageEvaluator) Evaluate(ctx context.Context, targetID string) (TargetAssessment, error) {
	return evaluator.evaluate(ctx, targetID, nil)
}

// EvaluateWithObservation lets the active diagnostic probe override the last
// persisted result for its exact modem/subscription combination. This avoids
// publishing a failed active cell before a probable global target outage has
// been confirmed through independent standby paths.
func (evaluator TargetOutageEvaluator) EvaluateWithObservation(ctx context.Context, targetID string, observation TargetObservation) (TargetAssessment, error) {
	if observation.ModemID == "" || observation.SubscriptionID == "" {
		return TargetAssessment{}, errors.New("complete target observation scope is required")
	}
	return evaluator.evaluate(ctx, targetID, &observation)
}

func (evaluator TargetOutageEvaluator) evaluate(ctx context.Context, targetID string, observation *TargetObservation) (TargetAssessment, error) {
	config := evaluator.Config
	if config.FailureCombinations <= 0 || config.FailureDistinctModems <= 0 || config.FailureDistinctSubscriptions <= 0 || config.RecoveryCombinations <= 0 || config.RecoveryDistinctModems <= 0 {
		return TargetAssessment{}, errors.New("complete target outage thresholds are required")
	}
	if targetID == "" || evaluator.Database == nil {
		return TargetAssessment{}, errors.New("target outage evaluator database and target id are required")
	}
	now := time.Now
	if evaluator.Now != nil {
		now = evaluator.Now
	}
	transaction, err := evaluator.Database.BeginTx(ctx, nil)
	if err != nil {
		return TargetAssessment{}, fmt.Errorf("begin target outage evaluation: %w", err)
	}
	defer transaction.Rollback()
	var currentState string
	var enabled int
	if err := transaction.QueryRowContext(ctx, "SELECT state, enabled FROM bypass_probe_targets WHERE id=?", targetID).Scan(&currentState, &enabled); errors.Is(err, sql.ErrNoRows) {
		return TargetAssessment{}, store.ErrNotFound
	} else if err != nil {
		return TargetAssessment{}, fmt.Errorf("read target outage state: %w", err)
	}
	assessment := TargetAssessment{TargetID: targetID, PreviousState: currentState, State: currentState}
	if enabled == 0 {
		return assessment, nil
	}
	rows, err := transaction.QueryContext(ctx, `
SELECT p.uplink_id, p.subscription_id,
       MAX(CASE WHEN r.state='PASSED' THEN 1 ELSE 0 END) AS any_passed
FROM uplink_path_node_target_results AS r
JOIN subscription_uplink_paths AS p ON p.id=r.path_id
WHERE r.target_id=? AND r.expires_at>?
  AND r.policy_generation=p.policy_generation
  AND r.route_generation=p.route_generation
GROUP BY p.uplink_id, p.subscription_id`, targetID, now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return TargetAssessment{}, fmt.Errorf("read target path observations: %w", err)
	}
	type combination struct{ modemID, subscriptionID string }
	observations := make(map[combination]bool)
	for rows.Next() {
		var modemID, subscriptionID string
		var anyPassed int
		if err := rows.Scan(&modemID, &subscriptionID, &anyPassed); err != nil {
			rows.Close()
			return TargetAssessment{}, fmt.Errorf("scan target path observation: %w", err)
		}
		observations[combination{modemID: modemID, subscriptionID: subscriptionID}] = anyPassed != 0
	}
	if err := rows.Close(); err != nil {
		return TargetAssessment{}, fmt.Errorf("close target path observations: %w", err)
	}
	if err := rows.Err(); err != nil {
		return TargetAssessment{}, fmt.Errorf("iterate target path observations: %w", err)
	}
	if observation != nil {
		observations[combination{modemID: observation.ModemID, subscriptionID: observation.SubscriptionID}] = observation.Passed
	}
	failureModems := make(map[string]struct{})
	failureSubscriptions := make(map[string]struct{})
	successModems := make(map[string]struct{})
	for scope, passed := range observations {
		if passed {
			assessment.SuccessCombinations++
			successModems[scope.modemID] = struct{}{}
			continue
		}
		assessment.FailureCombinations++
		failureModems[scope.modemID] = struct{}{}
		failureSubscriptions[scope.subscriptionID] = struct{}{}
	}
	assessment.DistinctFailureModems = len(failureModems)
	assessment.DistinctFailureSubscriptions = len(failureSubscriptions)
	newState := currentState
	if currentState != TargetSuspect && assessment.FailureCombinations >= config.FailureCombinations && len(failureModems) >= config.FailureDistinctModems && len(failureSubscriptions) >= config.FailureDistinctSubscriptions {
		newState = TargetSuspect
	} else if currentState == TargetSuspect && assessment.SuccessCombinations >= config.RecoveryCombinations && len(successModems) >= config.RecoveryDistinctModems {
		newState = TargetNormal
	} else if currentState != TargetSuspect && currentState != TargetNormal && assessment.FailureCombinations+assessment.SuccessCombinations > 0 {
		newState = TargetNormal
	}
	if newState != currentState {
		occurredAt := now().UTC().Format(time.RFC3339Nano)
		if _, err := transaction.ExecContext(ctx, "UPDATE bypass_probe_targets SET state=?, updated_at=? WHERE id=?", newState, occurredAt, targetID); err != nil {
			return TargetAssessment{}, fmt.Errorf("update target outage state: %w", err)
		}
		assessment.State = newState
		assessment.Changed = true
		eventType, severity := "TARGET_STATE_NORMAL", "INFO"
		if newState == TargetSuspect {
			eventType, severity = "TARGET_OUTAGE_SUSPECTED", "WARNING"
		} else if currentState == TargetSuspect {
			eventType = "TARGET_OUTAGE_RECOVERED"
		}
		details, err := json.Marshal(map[string]any{
			"target_id": targetID, "previous_state": currentState, "state": newState,
			"failure_combinations":           assessment.FailureCombinations,
			"success_combinations":           assessment.SuccessCombinations,
			"distinct_failure_modems":        assessment.DistinctFailureModems,
			"distinct_failure_subscriptions": assessment.DistinctFailureSubscriptions,
		})
		if err != nil {
			return TargetAssessment{}, fmt.Errorf("encode target outage event: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, details_json)
VALUES (?, ?, ?, ?)`, occurredAt, severity, eventType, string(details)); err != nil {
			return TargetAssessment{}, fmt.Errorf("record target outage event: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return TargetAssessment{}, fmt.Errorf("commit target outage evaluation: %w", err)
	}
	return assessment, nil
}

func DefaultTargetOutageConfig() TargetOutageConfig {
	return TargetOutageConfig{
		FailureCombinations: 3, FailureDistinctModems: 2,
		FailureDistinctSubscriptions: 2,
		RecoveryCombinations:         2, RecoveryDistinctModems: 2,
	}
}
