package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/subscription"
)

func TestDatabaseRetentionReportContainsBoundedCountsAndNoPath(t *testing.T) {
	ctx, database := diagnosticDatabase(t)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	for _, stamp := range []string{"2026-08-01T00:00:00Z", "2026-08-26T11:00:00Z"} {
		if _, err := database.ExecContext(ctx, "INSERT INTO health_samples(measured_at,scope_type,state) VALUES(?, 'gateway', 'OK')", stamp); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx, "INSERT INTO traffic_daily_totals(date,checkpointed_at) VALUES('2026-08-25', ?)", now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO operations(id,kind,scope_type,status,requested_by,summary_code,created_at,started_at,finished_at,updated_at)
VALUES('operation-finished', 'SUBSCRIPTION_REFRESH', 'SUBSCRIPTION', 'SUCCEEDED', 'SYSTEM', 'DONE', ?, ?, ?, ?)`,
		now.Add(-2*time.Hour).Format(time.RFC3339Nano), now.Add(-time.Hour).Format(time.RFC3339Nano), now.Add(-30*time.Minute).Format(time.RFC3339Nano), now.Add(-30*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO operations(id,kind,scope_type,status,requested_by,created_at,updated_at)
VALUES('operation-running', 'SUBSCRIPTION_REFRESH', 'SUBSCRIPTION', 'QUEUED', 'SYSTEM', ?, ?)`, now.AddDate(0, 0, -90).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	repository := subscription.NewRepository(database)
	if _, err := repository.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/sub-a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		id, state string
	}{
		{id: "lkg-a", state: subscription.VersionLKG},
		{id: "candidate-a", state: subscription.VersionCandidate},
		{id: "retained-a", state: subscription.VersionRetained},
		{id: "failed-a", state: subscription.VersionFailed},
	} {
		if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_versions(id,subscription_id,content_sha256,nodes_total,state,created_at,activated_at)
VALUES(?, 'sub-a', ?, 1, ?, ?, ?)`, item.id, strings.Repeat("a", 64), item.state, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx, "UPDATE subscriptions SET active_version_id='lkg-a' WHERE id='sub-a'"); err != nil {
		t.Fatal(err)
	}

	report, err := buildDatabaseRetentionReport(ctx, database, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.Policy.HealthDays != 7 || report.Policy.EventDays != 30 || report.Policy.OperationDays != 30 || report.Policy.TrafficMonths != 24 || report.Policy.PreviousSuccessfulVersions != 2 || report.Policy.FailedVersions != 2 {
		t.Fatalf("policy report = %+v", report)
	}
	if report.HealthSamples.Rows != 2 || report.HealthSamples.Oldest != "2026-08-01T00:00:00Z" || report.HealthSamples.MostRecent != "2026-08-26T11:00:00Z" || report.Operations.Rows != 1 || report.Operations.Oldest != now.Add(-30*time.Minute).Format(time.RFC3339Nano) || report.Operations.MostRecent != now.Add(-30*time.Minute).Format(time.RFC3339Nano) || report.TrafficDailyTotals.Rows != 1 {
		t.Fatalf("temporal report = %+v", report)
	}
	versions := report.SubscriptionVersions
	if versions.Total != 4 || versions.LKG != 1 || versions.Candidate != 1 || versions.Retained != 1 || versions.Failed != 1 || versions.Other != 0 || versions.ActiveLKG != 1 || versions.ActiveNonLKG != 0 || versions.RetainedExcess != 0 || versions.FailedExcess != 0 {
		t.Fatalf("version report = %+v", versions)
	}
	if !report.Storage.Available || report.Storage.DatabaseBytes <= 0 || report.Storage.PageSizeBytes <= 0 || report.Storage.PageCount <= 0 || report.Storage.AllocatedPageBytes != report.Storage.PageSizeBytes*report.Storage.PageCount || report.Storage.LivePageBytes != report.Storage.PageSizeBytes*(report.Storage.PageCount-report.Storage.FreelistPageCount) {
		t.Fatalf("storage report = %+v", report.Storage)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "state.db") || strings.Contains(string(encoded), "\\") || strings.Contains(string(encoded), "/tmp/") {
		t.Fatalf("retention report leaked a filesystem path: %s", encoded)
	}
}
