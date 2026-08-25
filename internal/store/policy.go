package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const PolicyGracePeriod = 120 * time.Second

// InvalidatePathPolicy allocates a new global policy generation and invalidates
// every path result inside the caller's transaction.
func InvalidatePathPolicy(ctx context.Context, transaction *sql.Tx, updatedAt string) (int64, error) {
	generation, err := AllocateCounter(ctx, transaction, "next_policy_generation", 1, updatedAt)
	if err != nil {
		return 0, err
	}
	startedAt, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return 0, fmt.Errorf("parse policy invalidation time: %w", err)
	}
	deadline := startedAt.Add(PolicyGracePeriod).UTC().Format(time.RFC3339Nano)
	_, err = transaction.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state='VERIFYING_POLICY',
    policy_transition_generation=?, policy_transition_started_at=?,
    policy_transition_deadline=?, updated_at=?
WHERE singleton_id=1 AND path_state='PATH_ACTIVE'
  AND active_modem_id IS NOT NULL AND active_path_id IS NOT NULL
  AND active_subscription_id IS NOT NULL AND active_node_id IS NOT NULL`,
		generation, updatedAt, deadline, updatedAt)
	if err != nil {
		return 0, fmt.Errorf("start runtime policy transition: %w", err)
	}
	var modemID, pathID, subscriptionID, nodeID string
	err = transaction.QueryRowContext(ctx, `
SELECT active_modem_id, active_path_id, active_subscription_id, active_node_id
FROM runtime_state
WHERE singleton_id=1 AND gateway_state='VERIFYING_POLICY'
  AND policy_transition_generation=?`, generation).Scan(&modemID, &pathID, &subscriptionID, &nodeID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return 0, fmt.Errorf("read runtime policy transition tuple: %w", err)
	default:
		details, marshalErr := json.Marshal(map[string]any{
			"node_id": nodeID, "policy_generation": generation,
			"started_at": updatedAt, "deadline": deadline,
		})
		if marshalErr != nil {
			return 0, fmt.Errorf("encode policy transition event: %w", marshalErr)
		}
		_, err = transaction.ExecContext(ctx, `
INSERT INTO events(occurred_at, severity, type, modem_id, subscription_id, path_id, details_json)
VALUES (?, 'INFO', 'POLICY_VERIFICATION_STARTED', ?, ?, ?, ?)`,
			updatedAt, modemID, subscriptionID, pathID, string(details))
		if err != nil {
			return 0, fmt.Errorf("record policy transition event: %w", err)
		}
	}
	_, err = transaction.ExecContext(ctx, `
UPDATE subscription_modem_paths
SET policy_generation=?,
    state=CASE
        WHEN state IN ('MODEM_DISABLED', 'SUBSCRIPTION_DISABLED', 'MODEM_OFFLINE') THEN state
        ELSE 'STALE'
    END,
    transport_state=CASE
        WHEN state IN ('MODEM_DISABLED', 'SUBSCRIPTION_DISABLED', 'MODEM_OFFLINE') THEN transport_state
        ELSE 'UNKNOWN'
    END,
    selected_node_id=NULL, qualified_nodes=0, required_targets_passed=0,
    last_checked_at=NULL, expires_at=NULL, updated_at=?`, generation, updatedAt)
	if err != nil {
		return 0, fmt.Errorf("invalidate path policy results: %w", err)
	}
	return generation, nil
}
