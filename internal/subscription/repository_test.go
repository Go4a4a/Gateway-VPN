package subscription

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/store"
)

func TestCreateAndReorderSubscriptions(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database)

	for _, id := range []string{"sub-a", "sub-b", "sub-c"} {
		created, err := repository.Create(ctx, CreateInput{
			ID:              id,
			Name:            "Subscription " + id,
			SourceType:      "url",
			SourceSecretRef: "/var/lib/gateway-vpn/secrets/subscriptions/" + id,
			RefreshInterval: time.Hour,
		})
		if err != nil {
			t.Fatalf("Create(%s) error = %v", id, err)
		}
		if created.Priority == 0 || created.SourceSecretRef == "" {
			t.Fatalf("Create(%s) returned incomplete record: %+v", id, created)
		}
	}

	if err := repository.ReorderEnabled(ctx, []string{"sub-b", "sub-c", "sub-a"}); err != nil {
		t.Fatalf("ReorderEnabled() error = %v", err)
	}
	items, err := repository.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	for index, want := range []string{"sub-b", "sub-c", "sub-a"} {
		if items[index].ID != want || items[index].Priority != int64((index+1)*10) {
			t.Errorf("item[%d] = %s/%d, want %s/%d", index, items[index].ID, items[index].Priority, want, (index+1)*10)
		}
	}

	if err := repository.ReorderEnabled(ctx, []string{"sub-b", "sub-a"}); !errors.Is(err, store.ErrPrioritySetMismatch) {
		t.Fatalf("incomplete reorder error = %v, want ErrPrioritySetMismatch", err)
	}
	afterFailure, err := repository.List(ctx)
	if err != nil {
		t.Fatalf("List(after failure) error = %v", err)
	}
	for index := range items {
		if afterFailure[index].ID != items[index].ID || afterFailure[index].Priority != items[index].Priority {
			t.Fatal("failed reorder changed subscription order")
		}
	}
}

func TestCreateRejectsUnsafeOrIncompleteSource(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database)

	tests := []CreateInput{
		{ID: "", Name: "Missing ID", SourceType: "url", SourceSecretRef: "/secret", RefreshInterval: time.Hour},
		{ID: "sub", Name: "", SourceType: "url", SourceSecretRef: "/secret", RefreshInterval: time.Hour},
		{ID: "sub", Name: "Sub", SourceType: "file", SourceSecretRef: "/secret", RefreshInterval: time.Hour},
		{ID: "sub", Name: "Sub", SourceType: "url", SourceSecretRef: "", RefreshInterval: time.Hour},
		{ID: "sub", Name: "Sub", SourceType: "url", SourceSecretRef: "/secret", RefreshInterval: time.Second},
	}
	for index, input := range tests {
		if _, err := repository.Create(ctx, input); err == nil {
			t.Errorf("Create(invalid %d) error = nil", index)
		}
	}
}

func TestSubscriptionLifecycleOperationsAreSafeAndAudited(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database)
	created, err := repository.Create(ctx, CreateInput{ID: "sub-a", Name: "Primary", SourceType: "url", SourceSecretRef: "/secret/sub-a.url", RefreshInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(ctx, created.ID, UpdateInput{Name: "Primary LTE", AutoRefresh: false, RefreshInterval: 2 * time.Hour, FallbackWhenNamedCandidatesFail: true}); err != nil {
		t.Fatal(err)
	}
	updated, _ := repository.Get(ctx, created.ID)
	if updated.Name != "Primary LTE" || updated.AutoRefresh || updated.RefreshIntervalSeconds != 7200 || !updated.FallbackWhenNamedCandidatesFail {
		t.Fatalf("updated subscription = %+v", updated)
	}
	if _, err := repository.Delete(ctx, created.ID); err == nil {
		t.Fatal("enabled subscription was deleted")
	}
	if err := repository.SetEnabled(ctx, created.ID, false); err != nil {
		t.Fatal(err)
	}
	disabled, _ := repository.Get(ctx, created.ID)
	if disabled.Enabled || disabled.Status != "DISABLED" {
		t.Fatalf("disabled subscription = %+v", disabled)
	}
	secretRef, err := repository.Delete(ctx, created.ID)
	if err != nil || secretRef != "/secret/sub-a.url" {
		t.Fatalf("Delete() = %q, %v", secretRef, err)
	}
	if _, err := repository.Get(ctx, created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted subscription Get() error = %v", err)
	}
	next, err := repository.Create(ctx, CreateInput{ID: "sub-b", Name: "Replacement", SourceType: "url", SourceSecretRef: "/secret/sub-b.url", RefreshInterval: time.Hour})
	if err != nil || next.DisplayNumber != created.DisplayNumber+1 {
		t.Fatalf("replacement display number = %d, %v; previous was %d", next.DisplayNumber, err, created.DisplayNumber)
	}
	var auditCount int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE subscription_id='sub-a'").Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("subscription audit events = %d, %v", auditCount, err)
	}
}

func TestDeleteRejectsRuntimeReferencedDisabledSubscription(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database)
	if _, err := repository.Create(ctx, CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/sub-a.url", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := repository.SetEnabled(ctx, "sub-a", false); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE runtime_state SET active_subscription_id='sub-a' WHERE singleton_id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Delete(ctx, "sub-a"); err == nil {
		t.Fatal("runtime-referenced subscription was deleted")
	}
}

func migratedDatabase(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatalf("db.Open() error = %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatalf("db.Migrate() error = %v", err)
	}
	return ctx, database
}
