package diagnostics

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"

	retentionpkg "gateway-vpn/internal/retention"
)

const databaseRetentionSchemaVersion = 1

type temporalRetentionStats struct {
	Rows       int64  `json:"rows"`
	Oldest     string `json:"oldest,omitempty"`
	MostRecent string `json:"most_recent,omitempty"`
}

type versionRetentionStats struct {
	Total          int64 `json:"total"`
	LKG            int64 `json:"lkg"`
	Candidate      int64 `json:"candidate"`
	Retained       int64 `json:"retained"`
	Failed         int64 `json:"failed"`
	Other          int64 `json:"other"`
	ActiveLKG      int64 `json:"active_lkg"`
	ActiveNonLKG   int64 `json:"active_non_lkg"`
	RetainedExcess int64 `json:"retained_excess"`
	FailedExcess   int64 `json:"failed_excess"`
}

type databaseStorageStats struct {
	Available          bool  `json:"available"`
	DatabaseBytes      int64 `json:"database_bytes"`
	WALBytes           int64 `json:"wal_bytes"`
	PageSizeBytes      int64 `json:"page_size_bytes"`
	PageCount          int64 `json:"page_count"`
	FreelistPageCount  int64 `json:"freelist_page_count"`
	AllocatedPageBytes int64 `json:"allocated_page_bytes"`
	LivePageBytes      int64 `json:"live_page_bytes"`
}

type retentionPolicySummary struct {
	HealthDays                 int `json:"health_days"`
	EventDays                  int `json:"event_days"`
	OperationDays              int `json:"operation_days"`
	TrafficMonths              int `json:"traffic_months"`
	PreviousSuccessfulVersions int `json:"previous_successful_versions"`
	FailedVersions             int `json:"failed_versions"`
	RowBatch                   int `json:"row_batch"`
	VersionBatch               int `json:"version_batch"`
}

type databaseRetentionReport struct {
	SchemaVersion        int                    `json:"schema_version"`
	CollectedAt          string                 `json:"collected_at"`
	Policy               retentionPolicySummary `json:"policy"`
	HealthSamples        temporalRetentionStats `json:"health_samples"`
	Events               temporalRetentionStats `json:"events"`
	Operations           temporalRetentionStats `json:"operations"`
	TrafficDailyTotals   temporalRetentionStats `json:"traffic_daily_totals"`
	SubscriptionVersions versionRetentionStats  `json:"subscription_versions"`
	Storage              databaseStorageStats   `json:"storage"`
}

func buildDatabaseRetentionReport(ctx context.Context, database *sql.DB, now time.Time) (databaseRetentionReport, error) {
	if database == nil {
		return databaseRetentionReport{}, errors.New("database is required")
	}
	policy := retentionpkg.DefaultPolicy()
	report := databaseRetentionReport{
		SchemaVersion: databaseRetentionSchemaVersion,
		CollectedAt:   now.UTC().Format(time.RFC3339Nano),
		Policy: retentionPolicySummary{
			HealthDays: policy.HealthDays, EventDays: policy.EventDays, OperationDays: policy.OperationDays, TrafficMonths: policy.TrafficMonths,
			PreviousSuccessfulVersions: policy.PreviousSuccessfulVersions, FailedVersions: policy.FailedVersions,
			RowBatch: policy.RowBatch, VersionBatch: policy.VersionBatch,
		},
	}
	var err error
	if report.HealthSamples, err = readTemporalRetentionStats(ctx, database, "SELECT COUNT(*), COALESCE(MIN(measured_at), ''), COALESCE(MAX(measured_at), '') FROM health_samples"); err != nil {
		return databaseRetentionReport{}, err
	}
	if report.Events, err = readTemporalRetentionStats(ctx, database, "SELECT COUNT(*), COALESCE(MIN(occurred_at), ''), COALESCE(MAX(occurred_at), '') FROM events"); err != nil {
		return databaseRetentionReport{}, err
	}
	if report.Operations, err = readTemporalRetentionStats(ctx, database, "SELECT COUNT(*), COALESCE(MIN(created_at), ''), COALESCE(MAX(created_at), '') FROM operations"); err != nil {
		return databaseRetentionReport{}, err
	}
	if report.TrafficDailyTotals, err = readTemporalRetentionStats(ctx, database, "SELECT COUNT(*), COALESCE(MIN(date), ''), COALESCE(MAX(date), '') FROM traffic_daily_totals"); err != nil {
		return databaseRetentionReport{}, err
	}
	if report.SubscriptionVersions, err = readVersionRetentionStats(ctx, database); err != nil {
		return databaseRetentionReport{}, err
	}
	report.Storage = readDatabaseStorageStats(ctx, database)
	if !report.Storage.Available {
		return databaseRetentionReport{}, errors.New("database storage counters are unavailable")
	}
	return report, nil
}

func readTemporalRetentionStats(ctx context.Context, database *sql.DB, query string) (temporalRetentionStats, error) {
	var result temporalRetentionStats
	if err := database.QueryRowContext(ctx, query).Scan(&result.Rows, &result.Oldest, &result.MostRecent); err != nil {
		return temporalRetentionStats{}, err
	}
	return result, nil
}

func readVersionRetentionStats(ctx context.Context, database *sql.DB) (versionRetentionStats, error) {
	var result versionRetentionStats
	rows, err := database.QueryContext(ctx, "SELECT state, COUNT(*) FROM subscription_versions GROUP BY state")
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var count int64
		if err := rows.Scan(&state, &count); err != nil {
			return versionRetentionStats{}, err
		}
		result.Total += count
		switch state {
		case "LKG":
			result.LKG = count
		case "CANDIDATE":
			result.Candidate = count
		case "RETAINED":
			result.Retained = count
		case "FAILED":
			result.Failed = count
		default:
			result.Other += count
		}
	}
	if err := rows.Err(); err != nil {
		return versionRetentionStats{}, err
	}
	if err := database.QueryRowContext(ctx, `
SELECT
    COALESCE(SUM(CASE WHEN version.state='LKG' THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN version.state<>'LKG' THEN 1 ELSE 0 END), 0)
FROM subscriptions AS subscription
JOIN subscription_versions AS version ON version.id=subscription.active_version_id`).Scan(&result.ActiveLKG, &result.ActiveNonLKG); err != nil {
		return versionRetentionStats{}, err
	}
	if err := database.QueryRowContext(ctx, `
WITH ranked AS (
    SELECT state,
           ROW_NUMBER() OVER (
               PARTITION BY subscription_id, state
               ORDER BY CASE WHEN state='RETAINED' THEN COALESCE(activated_at, created_at) ELSE created_at END DESC,
                        created_at DESC, id DESC
           ) AS retention_rank
    FROM subscription_versions
    WHERE state IN ('RETAINED', 'FAILED')
)
SELECT
    COALESCE(SUM(CASE WHEN state='RETAINED' AND retention_rank > 2 THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(CASE WHEN state='FAILED' AND retention_rank > 2 THEN 1 ELSE 0 END), 0)
FROM ranked`).Scan(&result.RetainedExcess, &result.FailedExcess); err != nil {
		return versionRetentionStats{}, err
	}
	return result, nil
}

func readDatabaseStorageStats(ctx context.Context, database *sql.DB) databaseStorageStats {
	var result databaseStorageStats
	if database.QueryRowContext(ctx, "PRAGMA page_size").Scan(&result.PageSizeBytes) != nil ||
		database.QueryRowContext(ctx, "PRAGMA page_count").Scan(&result.PageCount) != nil ||
		database.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&result.FreelistPageCount) != nil ||
		result.PageSizeBytes <= 0 || result.PageCount < 0 || result.FreelistPageCount < 0 ||
		result.FreelistPageCount > result.PageCount || result.PageCount > int64(^uint64(0)>>1)/result.PageSizeBytes {
		return databaseStorageStats{}
	}
	result.AllocatedPageBytes = result.PageSizeBytes * result.PageCount
	result.LivePageBytes = result.PageSizeBytes * (result.PageCount - result.FreelistPageCount)
	rows, err := database.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return result
	}
	defer rows.Close()
	mainPath := ""
	for rows.Next() {
		var sequence int
		var name, path string
		if rows.Scan(&sequence, &name, &path) != nil {
			return result
		}
		if name == "main" {
			mainPath = path
		}
	}
	if rows.Err() != nil || mainPath == "" {
		return result
	}
	info, err := os.Lstat(mainPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 {
		return result
	}
	result.DatabaseBytes = info.Size()
	walInfo, err := os.Lstat(mainPath + "-wal")
	if err == nil {
		if walInfo.Mode()&os.ModeSymlink != 0 || !walInfo.Mode().IsRegular() || walInfo.Size() < 0 {
			return result
		}
		result.WALBytes = walInfo.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return result
	}
	result.Available = true
	return result
}
