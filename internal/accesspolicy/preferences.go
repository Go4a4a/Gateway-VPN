package accesspolicy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gateway-vpn/internal/store"
)

type PreferenceRepository struct {
	database *sql.DB
	now      func() time.Time
}

type NodePreference struct {
	SubscriptionID    string
	Fingerprint       string
	SelectionOverride string
	PreferredRank     int64
	UserLabel         string
	LastSeenVersionID string
	MissingSince      string
	ActiveNodeID      string
	ActiveNodeName    string
}

func NewPreferenceRepository(database *sql.DB) *PreferenceRepository {
	return &PreferenceRepository{database: database, now: time.Now}
}

func (repository *PreferenceRepository) List(ctx context.Context, subscriptionID string) ([]NodePreference, error) {
	if repository == nil || repository.database == nil || strings.TrimSpace(subscriptionID) == "" {
		return nil, errors.New("preference database and subscription id are required")
	}
	rows, err := repository.database.QueryContext(ctx, `
SELECT p.subscription_id, p.fingerprint, p.selection_override,
       p.preferred_rank, p.user_label, p.last_seen_version_id, p.missing_since,
       n.id, n.external_name
FROM subscription_node_preferences AS p
LEFT JOIN subscriptions AS s ON s.id=p.subscription_id
LEFT JOIN nodes AS n
       ON n.version_id=s.active_version_id AND n.fingerprint=p.fingerprint
WHERE p.subscription_id=?
ORDER BY p.missing_since IS NOT NULL, p.preferred_rank IS NULL,
         p.preferred_rank, COALESCE(n.normalized_name, p.fingerprint)`, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("list subscription node preferences: %w", err)
	}
	defer rows.Close()
	result := []NodePreference{}
	for rows.Next() {
		var item NodePreference
		var rank sql.NullInt64
		var missing, nodeID, nodeName sql.NullString
		if err := rows.Scan(
			&item.SubscriptionID, &item.Fingerprint, &item.SelectionOverride,
			&rank, &item.UserLabel, &item.LastSeenVersionID, &missing,
			&nodeID, &nodeName,
		); err != nil {
			return nil, fmt.Errorf("scan subscription node preference: %w", err)
		}
		item.PreferredRank = rank.Int64
		item.MissingSince = missing.String
		item.ActiveNodeID = nodeID.String
		item.ActiveNodeName = nodeName.String
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscription node preferences: %w", err)
	}
	return result, nil
}

// ReorderPreferred accepts the ordered allowed active fingerprints. Omitted
// nodes remain available under matcher policy but have no explicit preferred
// rank. Excluded or stale/missing fingerprints cannot be ranked.
func (repository *PreferenceRepository) ReorderPreferred(ctx context.Context, subscriptionID string, fingerprints []string) error {
	if repository == nil || repository.database == nil || strings.TrimSpace(subscriptionID) == "" {
		return errors.New("preference database and subscription id are required")
	}
	seen := make(map[string]struct{}, len(fingerprints))
	for _, fingerprint := range fingerprints {
		if strings.TrimSpace(fingerprint) == "" {
			return store.ErrPrioritySetMismatch
		}
		if _, exists := seen[fingerprint]; exists {
			return store.ErrPrioritySetMismatch
		}
		seen[fingerprint] = struct{}{}
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin preferred node reorder: %w", err)
	}
	defer transaction.Rollback()
	var subscriptionExists int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM subscriptions WHERE id=?", subscriptionID).Scan(&subscriptionExists); err != nil {
		return fmt.Errorf("validate preferred node subscription: %w", err)
	}
	if subscriptionExists != 1 {
		return store.ErrNotFound
	}
	for _, fingerprint := range fingerprints {
		var count int
		if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM subscription_node_preferences AS p
JOIN subscriptions AS s ON s.id=p.subscription_id
JOIN nodes AS n ON n.version_id=s.active_version_id AND n.fingerprint=p.fingerprint
WHERE p.subscription_id=? AND p.fingerprint=?
  AND p.selection_override<>'exclude'
  AND n.enabled=1 AND n.selection_override<>'exclude'`, subscriptionID, fingerprint).Scan(&count); err != nil {
			return fmt.Errorf("validate preferred subscription node: %w", err)
		}
		if count != 1 {
			return store.ErrPrioritySetMismatch
		}
	}
	now := repository.now().UTC().Format(time.RFC3339Nano)
	if _, err := transaction.ExecContext(ctx, `
UPDATE subscription_node_preferences
SET preferred_rank=NULL, updated_at=?
WHERE subscription_id=? AND preferred_rank IS NOT NULL`, now, subscriptionID); err != nil {
		return fmt.Errorf("clear preferred subscription node ranks: %w", err)
	}
	for index, fingerprint := range fingerprints {
		result, err := transaction.ExecContext(ctx, `
UPDATE subscription_node_preferences
SET preferred_rank=?, updated_at=?
WHERE subscription_id=? AND fingerprint=?`, int64(index+1)*10, now, subscriptionID, fingerprint)
		if err != nil {
			return fmt.Errorf("set preferred subscription node rank: %w", err)
		}
		if count, countErr := result.RowsAffected(); countErr != nil || count != 1 {
			return store.ErrPrioritySetMismatch
		}
	}
	if err := bumpRankingGeneration(ctx, transaction, now); err != nil {
		return err
	}
	if err := appendAccessEvent(ctx, transaction, now, "SUBSCRIPTION_NODE_PRIORITY_REORDERED", map[string]any{
		"subscription_id": subscriptionID, "fingerprints": fingerprints,
	}); err != nil {
		return err
	}
	return transaction.Commit()
}
