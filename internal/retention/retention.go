// Package retention applies the bounded SQLite and subscription-payload
// retention policy. Every database category is pruned in a separate small
// transaction; VACUUM is intentionally outside this worker.
package retention

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gateway-vpn/internal/subscription"
)

type Policy struct {
	HealthDays                 int
	EventDays                  int
	TrafficMonths              int
	PreviousSuccessfulVersions int
	FailedVersions             int
	RowBatch                   int
	VersionBatch               int
}

func DefaultPolicy() Policy {
	return Policy{
		HealthDays: 7, EventDays: 30, TrafficMonths: 24,
		PreviousSuccessfulVersions: 2, FailedVersions: 2,
		RowBatch: 500, VersionBatch: 20,
	}
}

func (policy Policy) Validate() error {
	if policy.HealthDays < 1 || policy.HealthDays > 365 || policy.EventDays < 1 || policy.EventDays > 3650 || policy.TrafficMonths < 0 || policy.TrafficMonths > 120 {
		return errors.New("retention time policy is outside supported bounds")
	}
	if policy.PreviousSuccessfulVersions < 0 || policy.PreviousSuccessfulVersions > 20 || policy.FailedVersions < 0 || policy.FailedVersions > 20 {
		return errors.New("subscription version retention is outside supported bounds")
	}
	if policy.RowBatch < 1 || policy.RowBatch > 1000 || policy.VersionBatch < 1 || policy.VersionBatch > 100 {
		return errors.New("retention batch size is outside supported bounds")
	}
	return nil
}

type Result struct {
	HealthSamplesDeleted        int64
	EventsDeleted               int64
	TrafficDaysDeleted          int64
	SubscriptionVersionsDeleted int64
	PayloadDirectoriesDeleted   int64
	HasMore                     bool
}

func (result Result) TotalDeleted() int64 {
	return result.HealthSamplesDeleted + result.EventsDeleted + result.TrafficDaysDeleted + result.SubscriptionVersionsDeleted + result.PayloadDirectoriesDeleted
}

type Cleaner struct {
	Database    *sql.DB
	PayloadRoot string
	Policy      Policy
	Now         func() time.Time
}

func (cleaner *Cleaner) CleanBatch(ctx context.Context) (Result, error) {
	if cleaner == nil || cleaner.Database == nil || cleaner.PayloadRoot == "" {
		return Result{}, errors.New("retention database and payload root are required")
	}
	policy := cleaner.Policy
	if policy == (Policy{}) {
		policy = DefaultPolicy()
	}
	if err := policy.Validate(); err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	if cleaner.Now != nil {
		now = cleaner.Now().UTC()
	}
	var result Result
	var failures []error
	deleted, err := deleteHealthBatch(ctx, cleaner.Database, now.AddDate(0, 0, -policy.HealthDays).Format(time.RFC3339Nano), policy.RowBatch)
	result.HealthSamplesDeleted = deleted
	if err != nil {
		failures = append(failures, err)
	} else if deleted == int64(policy.RowBatch) {
		result.HasMore = true
	}
	deleted, err = deleteEventBatch(ctx, cleaner.Database, now.AddDate(0, 0, -policy.EventDays).Format(time.RFC3339Nano), policy.RowBatch)
	result.EventsDeleted = deleted
	if err != nil {
		failures = append(failures, err)
	} else if deleted == int64(policy.RowBatch) {
		result.HasMore = true
	}
	if policy.TrafficMonths > 0 {
		deleted, err = deleteTrafficBatch(ctx, cleaner.Database, now.AddDate(0, -policy.TrafficMonths, 0).Format("2006-01-02"), policy.RowBatch)
		result.TrafficDaysDeleted = deleted
		if err != nil {
			failures = append(failures, err)
		} else if deleted == int64(policy.RowBatch) {
			result.HasMore = true
		}
	}
	versions, err := pruneVersionBatch(ctx, cleaner.Database, policy)
	result.SubscriptionVersionsDeleted = int64(len(versions))
	if err != nil {
		failures = append(failures, err)
	} else if len(versions) == policy.VersionBatch {
		result.HasMore = true
	}
	for _, item := range versions {
		deleted, err := subscription.DeleteVersionPayload(cleaner.PayloadRoot, item.SubscriptionID, item.VersionID)
		if deleted {
			result.PayloadDirectoriesDeleted++
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("delete pruned subscription payload: %w", err))
			continue
		}
	}
	orphanDeleted, orphanMore, err := pruneOrphanPayloadBatch(ctx, cleaner.Database, cleaner.PayloadRoot, policy.VersionBatch)
	result.PayloadDirectoriesDeleted += orphanDeleted
	result.HasMore = result.HasMore || orphanMore
	if err != nil {
		failures = append(failures, err)
	}
	return result, errors.Join(failures...)
}

func deleteHealthBatch(ctx context.Context, database *sql.DB, cutoff string, limit int) (int64, error) {
	return deleteRows(ctx, database, `
DELETE FROM health_samples
WHERE id IN (SELECT id FROM health_samples WHERE measured_at < ? ORDER BY measured_at, id LIMIT ?)`, cutoff, limit, "health samples")
}

func deleteEventBatch(ctx context.Context, database *sql.DB, cutoff string, limit int) (int64, error) {
	return deleteRows(ctx, database, `
DELETE FROM events
WHERE id IN (SELECT id FROM events WHERE occurred_at < ? ORDER BY occurred_at, id LIMIT ?)`, cutoff, limit, "events")
}

func deleteTrafficBatch(ctx context.Context, database *sql.DB, cutoff string, limit int) (int64, error) {
	return deleteRows(ctx, database, `
DELETE FROM traffic_daily_totals
WHERE date IN (SELECT date FROM traffic_daily_totals WHERE date < ? ORDER BY date LIMIT ?)`, cutoff, limit, "traffic days")
}

func deleteRows(ctx context.Context, database *sql.DB, statement string, cutoff string, limit int, label string) (int64, error) {
	result, err := database.ExecContext(ctx, statement, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("prune %s: %w", label, err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read pruned %s count: %w", label, err)
	}
	return deleted, nil
}

type versionRef struct {
	SubscriptionID string
	VersionID      string
	State          string
}

func pruneVersionBatch(ctx context.Context, database *sql.DB, policy Policy) ([]versionRef, error) {
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin subscription version retention: %w", err)
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, `
WITH ranked AS (
    SELECT id, subscription_id, state, created_at,
           ROW_NUMBER() OVER (
               PARTITION BY subscription_id, state
               ORDER BY CASE WHEN state='RETAINED' THEN COALESCE(activated_at, created_at) ELSE created_at END DESC,
                        created_at DESC, id DESC
           ) AS retention_rank
    FROM subscription_versions AS version
    WHERE state IN ('RETAINED', 'FAILED')
      AND NOT EXISTS (
          SELECT 1 FROM subscriptions AS subscription
          WHERE subscription.active_version_id=version.id
      )
)
SELECT id, subscription_id, state
FROM ranked
WHERE (state='RETAINED' AND retention_rank > ?)
   OR (state='FAILED' AND retention_rank > ?)
ORDER BY created_at, id
LIMIT ?`, policy.PreviousSuccessfulVersions, policy.FailedVersions, policy.VersionBatch)
	if err != nil {
		return nil, fmt.Errorf("select subscription versions for retention: %w", err)
	}
	var candidates []versionRef
	for rows.Next() {
		var item versionRef
		if err := rows.Scan(&item.VersionID, &item.SubscriptionID, &item.State); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan subscription version retention candidate: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close subscription version retention candidates: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subscription version retention candidates: %w", err)
	}
	deleted := make([]versionRef, 0, len(candidates))
	for _, item := range candidates {
		result, err := transaction.ExecContext(ctx, `
DELETE FROM subscription_versions
WHERE id=? AND state=?
  AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE active_version_id=subscription_versions.id)`, item.VersionID, item.State)
		if err != nil {
			return nil, fmt.Errorf("prune subscription version: %w", err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("read pruned subscription version count: %w", err)
		}
		if count == 1 {
			deleted = append(deleted, item)
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit subscription version retention: %w", err)
	}
	return deleted, nil
}

func pruneOrphanPayloadBatch(ctx context.Context, database *sql.DB, root string, limit int) (int64, bool, error) {
	// A portable backup is already bounded to 4096 files. Scan that entire
	// bounded inventory rather than only the first deletion batch: the leading
	// payloads may all be referenced while an orphan sorts after them.
	items, err := subscription.ListVersionPayloads(root, 4096)
	if err != nil {
		return 0, false, fmt.Errorf("list subscription payloads for retention: %w", err)
	}
	var deleted int64
	for _, item := range items {
		var exists int
		if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM subscription_versions WHERE id=? AND subscription_id=?", item.VersionID, item.SubscriptionID).Scan(&exists); err != nil {
			return deleted, deleted == int64(limit), fmt.Errorf("check subscription payload retention reference: %w", err)
		}
		if exists != 0 {
			continue
		}
		removed, err := subscription.DeleteVersionPayload(root, item.SubscriptionID, item.VersionID)
		if removed {
			deleted++
		}
		if err != nil {
			return deleted, true, fmt.Errorf("delete orphan subscription payload: %w", err)
		}
		if deleted == int64(limit) {
			return deleted, true, nil
		}
	}
	return deleted, false, nil
}
