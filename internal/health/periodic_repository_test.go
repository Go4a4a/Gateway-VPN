package health

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/subscription"
)

type periodicTestPath struct {
	ID      string
	ModemID string
}

func TestPeriodicRepositoryPersistsStreaksAndBudgetDeferralAcrossRestart(t *testing.T) {
	ctx, database, paths := periodicRepositoryFixture(t)
	clock := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	repository := PeriodicRepository{Database: database, Now: func() time.Time { return clock }}

	if err := repository.Reconcile(ctx, paths[0].ID); err != nil {
		t.Fatal(err)
	}
	due, err := repository.Due(ctx, 10)
	if err != nil || len(due) != 2 || due[0].PathID != paths[0].ID || due[0].ProbeClass != ProbeClassActive || due[1].ProbeClass != ProbeClassStandby {
		t.Fatalf("Due() = %+v, %v", due, err)
	}

	first, err := repository.Record(ctx, paths[0].ID, PeriodicFailed, time.Minute, 0)
	if err != nil || first.Failures != 1 || first.Successes != 0 || first.LastResult != PeriodicFailed || first.LastProbeAt == "" {
		t.Fatalf("Record(first failure) = %+v, %v", first, err)
	}
	clock = clock.Add(time.Minute)
	second, err := repository.Record(ctx, paths[0].ID, PeriodicFailed, time.Minute, 0)
	if err != nil || second.Failures != 2 || second.Successes != 0 {
		t.Fatalf("Record(second failure) = %+v, %v", second, err)
	}

	// A new repository value models a process restart: the threshold streak is
	// durable and a scheduler budget deferral must not become a false failure.
	restarted := PeriodicRepository{Database: database, Now: func() time.Time { return clock }}
	persisted, err := restarted.Get(ctx, paths[0].ID)
	if err != nil || persisted.Failures != 2 || persisted.LastProbeAt != second.LastProbeAt {
		t.Fatalf("Get(after restart) = %+v, %v", persisted, err)
	}
	clock = clock.Add(time.Minute)
	deferred, err := restarted.Defer(ctx, paths[0].ID, "MOBILE_BUDGET", 5*time.Minute, 0)
	if err != nil || deferred.LastResult != PeriodicDeferred || deferred.DeferredReason != "MOBILE_BUDGET" || deferred.Failures != 2 || deferred.Successes != 0 || deferred.LastProbeAt != second.LastProbeAt {
		t.Fatalf("Defer() = %+v, %v", deferred, err)
	}

	clock = clock.Add(5 * time.Minute)
	passed, err := restarted.Record(ctx, paths[0].ID, PeriodicPassed, time.Minute, 0)
	if err != nil || passed.LastResult != PeriodicPassed || passed.Successes != 1 || passed.Failures != 0 || passed.DeferredReason != "" {
		t.Fatalf("Record(success after defer) = %+v, %v", passed, err)
	}
	if err := restarted.Acknowledge(ctx, paths[0].ID); err != nil {
		t.Fatal(err)
	}
	acknowledged, _ := restarted.Get(ctx, paths[0].ID)
	if acknowledged.Successes != 0 || acknowledged.Failures != 0 || acknowledged.LastResult != PeriodicPassed {
		t.Fatalf("Acknowledge() status = %+v", acknowledged)
	}
}

func TestPeriodicRepositoryReclassifiesImmediatelyAndFiltersUnavailablePaths(t *testing.T) {
	ctx, database, paths := periodicRepositoryFixture(t)
	clock := time.Date(2026, 8, 24, 14, 0, 0, 0, time.UTC)
	repository := PeriodicRepository{Database: database, Now: func() time.Time { return clock }}
	if err := repository.Reconcile(ctx, paths[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Record(ctx, paths[0].ID, PeriodicFailed, time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Record(ctx, paths[1].ID, PeriodicPassed, time.Hour, 0); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(time.Minute)
	if err := repository.Reconcile(ctx, paths[1].ID); err != nil {
		t.Fatal(err)
	}
	statuses, err := repository.List(ctx)
	if err != nil || len(statuses) != 2 {
		t.Fatalf("List() = %+v, %v", statuses, err)
	}
	byID := map[string]PeriodicPathStatus{statuses[0].PathID: statuses[0], statuses[1].PathID: statuses[1]}
	for _, path := range paths {
		status := byID[path.ID]
		wantClass := ProbeClassStandby
		if path.ID == paths[1].ID {
			wantClass = ProbeClassActive
		}
		if status.ProbeClass != wantClass || status.LastResult != PeriodicUnknown || status.Successes != 0 || status.Failures != 0 || status.NextProbeAt != clock.Format(time.RFC3339Nano) {
			t.Fatalf("reclassified status %s = %+v", path.ID, status)
		}
	}

	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_CONFIGURED_OFFLINE' WHERE id=?", paths[1].ModemID); err != nil {
		t.Fatal(err)
	}
	due, err := repository.Due(ctx, 10)
	if err != nil || len(due) != 1 || due[0].PathID != paths[0].ID || due[0].ProbeClass != ProbeClassStandby {
		t.Fatalf("Due(with active modem offline) = %+v, %v", due, err)
	}

	if _, err := database.ExecContext(ctx, "DELETE FROM subscription_modem_paths WHERE id=?", paths[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Get(ctx, paths[0].ID); err == nil {
		t.Fatal("cascade-deleted schedule remained readable")
	}
}

func periodicRepositoryFixture(t *testing.T) (context.Context, *sql.DB, []periodicTestPath) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	modems := modem.NewRepository(database, 1101, 0x1101)
	for index, id := range []string{"modem-a", "modem-b"} {
		digest := sha256.Sum256([]byte(id))
		if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: id, Name: id, IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
			t.Fatal(err)
		}
		lease := modem.LeaseInput{
			InterfaceName: "enx" + id, ManagementCIDR: "192.168.8.0/24",
			Gateway: "192.168.8.1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady,
		}
		if index == 1 {
			lease.ManagementCIDR, lease.Gateway = "192.168.9.0/24", "192.168.9.1"
		}
		if _, err := modems.ApplyLease(ctx, id, lease); err != nil {
			t.Fatal(err)
		}
	}
	subscriptions := subscription.NewRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_versions(id, subscription_id, content_sha256, nodes_total, state, created_at, activated_at)
VALUES ('version-a', 'sub-a', ?, 0, 'LKG', ?, ?)`, hex.EncodeToString(make([]byte, 32)), now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE subscriptions SET active_version_id='version-a' WHERE id='sub-a'"); err != nil {
		t.Fatal(err)
	}
	paths := []periodicTestPath{{ID: "path-a", ModemID: "modem-a"}, {ID: "path-b", ModemID: "modem-b"}}
	for _, path := range paths {
		if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_modem_paths(id, modem_id, subscription_id, created_at, updated_at)
VALUES (?, ?, 'sub-a', ?, ?)`, path.ID, path.ModemID, now, now); err != nil {
			t.Fatal(err)
		}
	}
	return ctx, database, paths
}
