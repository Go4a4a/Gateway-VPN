package health

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"gateway-vpn/internal/store"
)

const (
	ProbeClassActive  = "ACTIVE"
	ProbeClassStandby = "STANDBY"
	PeriodicUnknown   = "UNKNOWN"
	PeriodicPassed    = "PASSED"
	PeriodicFailed    = "FAILED"
	PeriodicDeferred  = "DEFERRED_BUDGET"
)

type DuePath struct {
	PathID         string
	ModemID        string
	SubscriptionID string
	ProbeClass     string
	LastResult     string
	Successes      int
	Failures       int
}

type PeriodicPathStatus struct {
	PathID         string
	ProbeClass     string
	NextProbeAt    string
	LastProbeAt    string
	LastResult     string
	Successes      int
	Failures       int
	DeferredReason string
}

type PeriodicRepository struct {
	Database *sql.DB
	Now      func() time.Time
}

func (repository PeriodicRepository) Reconcile(ctx context.Context, activePathID string) error {
	if repository.Database == nil {
		return errors.New("periodic health database is required")
	}
	now := repository.now().Format(time.RFC3339Nano)
	transaction, err := repository.Database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin periodic health reconcile: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO path_health_runtime(path_id, probe_class, next_probe_at, updated_at)
SELECT p.id, CASE WHEN p.id=? THEN 'ACTIVE' ELSE 'STANDBY' END, ?, ?
FROM subscription_modem_paths AS p
WHERE 1=1
ON CONFLICT(path_id) DO NOTHING`, activePathID, now, now); err != nil {
		return fmt.Errorf("insert periodic health schedules: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE path_health_runtime
SET probe_class=CASE WHEN path_id=? THEN 'ACTIVE' ELSE 'STANDBY' END,
    next_probe_at=CASE
        WHEN probe_class<>CASE WHEN path_id=? THEN 'ACTIVE' ELSE 'STANDBY' END THEN ?
        ELSE next_probe_at
    END,
    last_result=CASE
        WHEN probe_class<>CASE WHEN path_id=? THEN 'ACTIVE' ELSE 'STANDBY' END THEN 'UNKNOWN'
        ELSE last_result
    END,
    consecutive_successes=CASE
        WHEN probe_class<>CASE WHEN path_id=? THEN 'ACTIVE' ELSE 'STANDBY' END THEN 0
        ELSE consecutive_successes
    END,
    consecutive_failures=CASE
        WHEN probe_class<>CASE WHEN path_id=? THEN 'ACTIVE' ELSE 'STANDBY' END THEN 0
        ELSE consecutive_failures
    END,
    deferred_reason=CASE
        WHEN probe_class<>CASE WHEN path_id=? THEN 'ACTIVE' ELSE 'STANDBY' END THEN NULL
        ELSE deferred_reason
    END,
    updated_at=?`, activePathID, activePathID, now, activePathID, activePathID, activePathID, activePathID, now); err != nil {
		return fmt.Errorf("update periodic health classes: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit periodic health reconcile: %w", err)
	}
	return nil
}

func (repository PeriodicRepository) Due(ctx context.Context, limit int) ([]DuePath, error) {
	if repository.Database == nil || limit <= 0 || limit > 100 {
		return nil, errors.New("periodic health database and due limit 1..100 are required")
	}
	rows, err := repository.Database.QueryContext(ctx, `
SELECT h.path_id, p.modem_id, p.subscription_id, h.probe_class,
       h.last_result, h.consecutive_successes, h.consecutive_failures
FROM path_health_runtime AS h
JOIN subscription_modem_paths AS p ON p.id=h.path_id
JOIN modems AS m ON m.id=p.modem_id
JOIN subscriptions AS s ON s.id=p.subscription_id
WHERE h.next_probe_at<=? AND m.enabled=1 AND m.state='MODEM_READY'
  AND s.enabled=1 AND s.active_version_id IS NOT NULL
ORDER BY CASE h.probe_class WHEN 'ACTIVE' THEN 0 ELSE 1 END,
         h.next_probe_at, h.path_id
LIMIT ?`, repository.now().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, fmt.Errorf("list due periodic paths: %w", err)
	}
	defer rows.Close()
	var result []DuePath
	for rows.Next() {
		var item DuePath
		if err := rows.Scan(&item.PathID, &item.ModemID, &item.SubscriptionID, &item.ProbeClass, &item.LastResult, &item.Successes, &item.Failures); err != nil {
			return nil, fmt.Errorf("scan due periodic path: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate due periodic paths: %w", err)
	}
	return result, nil
}

func (repository PeriodicRepository) Record(ctx context.Context, pathID, result string, interval time.Duration, jitterPercent int) (PeriodicPathStatus, error) {
	if repository.Database == nil || pathID == "" || (result != PeriodicPassed && result != PeriodicFailed) || interval <= 0 || jitterPercent < 0 || jitterPercent > 50 {
		return PeriodicPathStatus{}, errors.New("valid periodic result, interval, and jitter are required")
	}
	now := repository.now()
	next := now.Add(interval + deterministicJitter(pathID, now, interval, jitterPercent))
	if !next.After(now) {
		next = now.Add(time.Second)
	}
	query := `
UPDATE path_health_runtime
SET last_probe_at=?, next_probe_at=?, last_result=?, deferred_reason=NULL,
    consecutive_successes=CASE WHEN ?='PASSED' THEN consecutive_successes+1 ELSE 0 END,
    consecutive_failures=CASE WHEN ?='FAILED' THEN consecutive_failures+1 ELSE 0 END,
    updated_at=?
WHERE path_id=?`
	formattedNow := now.Format(time.RFC3339Nano)
	changed, err := repository.Database.ExecContext(ctx, query, formattedNow, next.Format(time.RFC3339Nano), result, result, result, formattedNow, pathID)
	if err != nil {
		return PeriodicPathStatus{}, fmt.Errorf("record periodic health result: %w", err)
	}
	if count, countErr := changed.RowsAffected(); countErr != nil {
		return PeriodicPathStatus{}, fmt.Errorf("read periodic health result count: %w", countErr)
	} else if count != 1 {
		return PeriodicPathStatus{}, store.ErrNotFound
	}
	return repository.Get(ctx, pathID)
}

func (repository PeriodicRepository) Defer(ctx context.Context, pathID, reason string, interval time.Duration, jitterPercent int) (PeriodicPathStatus, error) {
	if repository.Database == nil || pathID == "" || reason == "" || interval <= 0 || jitterPercent < 0 || jitterPercent > 50 {
		return PeriodicPathStatus{}, errors.New("valid deferred periodic schedule is required")
	}
	now := repository.now()
	next := now.Add(interval + deterministicJitter(pathID, now, interval, jitterPercent))
	result, err := repository.Database.ExecContext(ctx, `
UPDATE path_health_runtime
SET next_probe_at=?, last_result='DEFERRED_BUDGET',
    deferred_reason=?, updated_at=?
WHERE path_id=?`, next.Format(time.RFC3339Nano), reason, now.Format(time.RFC3339Nano), pathID)
	if err != nil {
		return PeriodicPathStatus{}, fmt.Errorf("defer periodic path: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil {
		return PeriodicPathStatus{}, countErr
	} else if count != 1 {
		return PeriodicPathStatus{}, store.ErrNotFound
	}
	return repository.Get(ctx, pathID)
}

func (repository PeriodicRepository) Acknowledge(ctx context.Context, pathID string) error {
	if repository.Database == nil || pathID == "" {
		return errors.New("path id is required for periodic acknowledgement")
	}
	result, err := repository.Database.ExecContext(ctx, `
UPDATE path_health_runtime
SET consecutive_successes=0, consecutive_failures=0, updated_at=?
WHERE path_id=?`, repository.now().Format(time.RFC3339Nano), pathID)
	if err != nil {
		return fmt.Errorf("acknowledge periodic threshold: %w", err)
	}
	if count, countErr := result.RowsAffected(); countErr != nil {
		return countErr
	} else if count != 1 {
		return store.ErrNotFound
	}
	return nil
}

func (repository PeriodicRepository) Get(ctx context.Context, pathID string) (PeriodicPathStatus, error) {
	if repository.Database == nil || pathID == "" {
		return PeriodicPathStatus{}, errors.New("periodic health database and path id are required")
	}
	var item PeriodicPathStatus
	var lastProbeAt, deferredReason sql.NullString
	err := repository.Database.QueryRowContext(ctx, `
SELECT path_id, probe_class, next_probe_at, last_probe_at, last_result,
       consecutive_successes, consecutive_failures, deferred_reason
FROM path_health_runtime WHERE path_id=?`, pathID).Scan(
		&item.PathID, &item.ProbeClass, &item.NextProbeAt, &lastProbeAt,
		&item.LastResult, &item.Successes, &item.Failures, &deferredReason,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return PeriodicPathStatus{}, store.ErrNotFound
	}
	if err != nil {
		return PeriodicPathStatus{}, fmt.Errorf("read periodic path status: %w", err)
	}
	item.LastProbeAt, item.DeferredReason = lastProbeAt.String, deferredReason.String
	return item, nil
}

func (repository PeriodicRepository) List(ctx context.Context) ([]PeriodicPathStatus, error) {
	if repository.Database == nil {
		return nil, errors.New("periodic health database is required")
	}
	rows, err := repository.Database.QueryContext(ctx, `
SELECT path_id, probe_class, next_probe_at, last_probe_at, last_result,
       consecutive_successes, consecutive_failures, deferred_reason
FROM path_health_runtime
ORDER BY CASE probe_class WHEN 'ACTIVE' THEN 0 ELSE 1 END, next_probe_at, path_id`)
	if err != nil {
		return nil, fmt.Errorf("list periodic path status: %w", err)
	}
	defer rows.Close()
	var result []PeriodicPathStatus
	for rows.Next() {
		var item PeriodicPathStatus
		var lastProbeAt, deferredReason sql.NullString
		if err := rows.Scan(&item.PathID, &item.ProbeClass, &item.NextProbeAt, &lastProbeAt, &item.LastResult, &item.Successes, &item.Failures, &deferredReason); err != nil {
			return nil, err
		}
		item.LastProbeAt, item.DeferredReason = lastProbeAt.String, deferredReason.String
		result = append(result, item)
	}
	return result, rows.Err()
}

func (repository PeriodicRepository) now() time.Time {
	if repository.Now != nil {
		return repository.Now().UTC()
	}
	return time.Now().UTC()
}

func deterministicJitter(pathID string, at time.Time, interval time.Duration, percent int) time.Duration {
	if percent == 0 {
		return 0
	}
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(pathID))
	_, _ = hash.Write([]byte(at.UTC().Format("2006-01-02T15:04")))
	span := int64(interval) * int64(percent) / 100
	if span <= 0 {
		return 0
	}
	return time.Duration(int64(hash.Sum64()%(uint64(2*span)+1)) - span)
}
