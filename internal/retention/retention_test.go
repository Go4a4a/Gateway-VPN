package retention

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/subscription"
)

func TestCleanerAppliesTimeAndVersionRetentionAndPrunesPayloads(t *testing.T) {
	ctx := context.Background()
	database, root := retentionDatabase(t, ctx)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	for _, measured := range []time.Time{now.AddDate(0, 0, -8), now.AddDate(0, 0, -7)} {
		if _, err := database.ExecContext(ctx, "INSERT INTO health_samples(measured_at,scope_type,state) VALUES(?, 'gateway', 'OK')", measured.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	for _, occurred := range []time.Time{now.AddDate(0, 0, -31), now.AddDate(0, 0, -30)} {
		if _, err := database.ExecContext(ctx, "INSERT INTO events(occurred_at,severity,type,details_json) VALUES(?, 'INFO', 'RETENTION_TEST', '{}')", occurred.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	for index, finished := range []time.Time{now.AddDate(0, 0, -31), now.AddDate(0, 0, -30)} {
		stamp := finished.Format(time.RFC3339Nano)
		if _, err := database.ExecContext(ctx, `
INSERT INTO operations(id,kind,scope_type,status,requested_by,summary_code,created_at,started_at,finished_at,updated_at)
VALUES(?, 'SUBSCRIPTION_REFRESH', 'SUBSCRIPTION', 'SUCCEEDED', 'SYSTEM', 'DONE', ?, ?, ?, ?)`, "operation-"+string(rune('a'+index)), stamp, stamp, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	for _, date := range []string{now.AddDate(0, -25, 0).Format("2006-01-02"), now.AddDate(0, -24, 0).Format("2006-01-02")} {
		if _, err := database.ExecContext(ctx, "INSERT INTO traffic_daily_totals(date,checkpointed_at) VALUES(?, ?)", date, now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	repository := subscription.NewRepository(database)
	if _, err := repository.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/sub-a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	versions := []struct {
		id    string
		state string
		age   int
	}{
		{id: "retained-1", state: subscription.VersionRetained, age: 10},
		{id: "retained-2", state: subscription.VersionRetained, age: 9},
		{id: "retained-3", state: subscription.VersionRetained, age: 8},
		{id: "retained-4", state: subscription.VersionRetained, age: 7},
		{id: "failed-1", state: subscription.VersionFailed, age: 6},
		{id: "failed-2", state: subscription.VersionFailed, age: 5},
		{id: "failed-3", state: subscription.VersionFailed, age: 4},
		{id: "failed-4", state: subscription.VersionFailed, age: 3},
		{id: "candidate-current", state: subscription.VersionCandidate, age: 2},
		{id: "lkg-current", state: subscription.VersionLKG, age: 1},
	}
	imported, err := subscription.Import([]byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#one"))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range versions {
		created := now.AddDate(0, 0, -item.age).Format(time.RFC3339Nano)
		activated := any(nil)
		if item.state == subscription.VersionRetained || item.state == subscription.VersionLKG {
			activated = created
		}
		if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_versions(id,subscription_id,content_sha256,nodes_total,state,error,created_at,activated_at)
VALUES(?, 'sub-a', ?, 1, ?, NULL, ?, ?)`, item.id, hash64(item.id), item.state, created, activated); err != nil {
			t.Fatal(err)
		}
		if _, err := subscription.WriteNormalizedPayload(root, "sub-a", item.id, imported); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx, "UPDATE subscriptions SET active_version_id='lkg-current' WHERE id='sub-a'"); err != nil {
		t.Fatal(err)
	}
	if _, err := subscription.WriteNormalizedPayload(root, "sub-a", "orphan-version", imported); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub-a", ".payload-in-flight"), 0o700); err != nil {
		t.Fatal(err)
	}

	cleaner := &Cleaner{Database: database, PayloadRoot: root, Policy: DefaultPolicy(), Now: func() time.Time { return now }}
	result, err := cleaner.CleanBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.HealthSamplesDeleted != 1 || result.EventsDeleted != 1 || result.OperationsDeleted != 1 || result.TrafficDaysDeleted != 1 || result.SubscriptionVersionsDeleted != 4 || result.PayloadDirectoriesDeleted != 5 || result.HasMore {
		t.Fatalf("CleanBatch() = %+v", result)
	}
	assertCount(t, database, "SELECT COUNT(*) FROM health_samples", 1)
	// One current repository audit event plus the exact-cutoff test event stay.
	assertCount(t, database, "SELECT COUNT(*) FROM events WHERE type='RETENTION_TEST'", 1)
	assertCount(t, database, "SELECT COUNT(*) FROM operations", 1)
	assertCount(t, database, "SELECT COUNT(*) FROM traffic_daily_totals", 1)
	rows, err := database.QueryContext(ctx, "SELECT id FROM subscription_versions WHERE subscription_id='sub-a' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	var remaining []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		remaining = append(remaining, id)
	}
	rows.Close()
	want := []string{"candidate-current", "failed-3", "failed-4", "lkg-current", "retained-3", "retained-4"}
	if len(remaining) != len(want) {
		t.Fatalf("remaining versions = %v", remaining)
	}
	for index := range want {
		if remaining[index] != want[index] {
			t.Fatalf("remaining versions = %v", remaining)
		}
	}
	for _, removed := range []string{"retained-1", "retained-2", "failed-1", "failed-2", "orphan-version"} {
		if _, err := os.Stat(filepath.Join(root, "sub-a", removed)); !os.IsNotExist(err) {
			t.Fatalf("pruned payload %s remains: %v", removed, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "sub-a", ".payload-in-flight")); err != nil {
		t.Fatalf("in-flight payload disappeared: %v", err)
	}
	result, err = cleaner.CleanBatch(ctx)
	if err != nil || result.TotalDeleted() != 0 || result.HasMore {
		t.Fatalf("converged CleanBatch() = %+v, %v", result, err)
	}
}

func TestCleanerUsesSmallBatchesAndCanLeaveTrafficUnlimited(t *testing.T) {
	ctx := context.Background()
	database, root := retentionDatabase(t, ctx)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 3; index++ {
		stamp := now.AddDate(-1, 0, -index).Format(time.RFC3339Nano)
		if _, err := database.ExecContext(ctx, "INSERT INTO health_samples(measured_at,scope_type,state) VALUES(?, 'gateway', 'OK')", stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx, "INSERT INTO events(occurred_at,severity,type,details_json) VALUES(?, 'INFO', 'OLD', '{}')", stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx, "INSERT INTO traffic_daily_totals(date,checkpointed_at) VALUES(?, ?)", now.AddDate(-3, 0, index).Format("2006-01-02"), stamp); err != nil {
			t.Fatal(err)
		}
	}
	policy := DefaultPolicy()
	policy.RowBatch = 1
	policy.VersionBatch = 1
	policy.TrafficMonths = 0
	cleaner := &Cleaner{Database: database, PayloadRoot: root, Policy: policy, Now: func() time.Time { return now }}
	for cycle := 0; cycle < 3; cycle++ {
		result, err := cleaner.CleanBatch(ctx)
		if err != nil || result.HealthSamplesDeleted > 1 || result.EventsDeleted > 1 || result.TrafficDaysDeleted != 0 || !result.HasMore {
			t.Fatalf("small batch %d = %+v, %v", cycle, result, err)
		}
	}
	assertCount(t, database, "SELECT COUNT(*) FROM health_samples", 0)
	assertCount(t, database, "SELECT COUNT(*) FROM events", 0)
	assertCount(t, database, "SELECT COUNT(*) FROM traffic_daily_totals", 3)
}

func TestCleanerFindsOrphanAfterReferencedPayloads(t *testing.T) {
	ctx := context.Background()
	database, root := retentionDatabase(t, ctx)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	repository := subscription.NewRepository(database)
	if _, err := repository.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/sub-a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	imported, err := subscription.Import([]byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#one"))
	if err != nil {
		t.Fatal(err)
	}
	for _, versionID := range []string{"aaa-referenced", "bbb-referenced", "ccc-referenced"} {
		if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_versions(id,subscription_id,content_sha256,nodes_total,state,created_at)
VALUES(?, 'sub-a', ?, 1, 'CANDIDATE', ?)`, versionID, hash64(versionID), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := subscription.WriteNormalizedPayload(root, "sub-a", versionID, imported); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := subscription.WriteNormalizedPayload(root, "sub-a", "zzz-orphan", imported); err != nil {
		t.Fatal(err)
	}
	policy := DefaultPolicy()
	policy.VersionBatch = 1
	cleaner := &Cleaner{Database: database, PayloadRoot: root, Policy: policy, Now: func() time.Time { return now }}
	result, err := cleaner.CleanBatch(ctx)
	if err != nil || result.PayloadDirectoriesDeleted != 1 || !result.HasMore {
		t.Fatalf("CleanBatch() = %+v, %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, "sub-a", "zzz-orphan")); !os.IsNotExist(err) {
		t.Fatalf("orphan behind referenced payloads remains: %v", err)
	}
	result, err = cleaner.CleanBatch(ctx)
	if err != nil || result.TotalDeleted() != 0 || result.HasMore {
		t.Fatalf("converged CleanBatch() = %+v, %v", result, err)
	}
}

func retentionDatabase(t *testing.T, ctx context.Context) (*sql.DB, string) {
	t.Helper()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "subscriptions")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return database, root
}

func assertCount(t *testing.T, database *sql.DB, query string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRow(query).Scan(&got); err != nil || got != want {
		t.Fatalf("count for %q = %d, %v; want %d", query, got, err, want)
	}
}

func hash64(value string) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = "0123456789abcdef"[(index+len(value))%16]
	}
	return string(result)
}
