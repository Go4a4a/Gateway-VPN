package bypass

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

func TestStatusExpressionNormalizationAndMatching(t *testing.T) {
	canonical, err := NormalizeStatusExpression("302, 200-299 / 404")
	if err != nil || canonical != "200-299/302/404" {
		t.Fatalf("NormalizeStatusExpression() = %q, %v", canonical, err)
	}
	for _, status := range []int{200, 250, 302, 404} {
		if !StatusMatches(canonical, status) {
			t.Errorf("status %d must match %q", status, canonical)
		}
	}
	for _, invalid := range []string{"", "99", "600", "399-200", "200/200", "200-300/250-350", "200//204"} {
		if _, err := NormalizeStatusExpression(invalid); err == nil {
			t.Errorf("NormalizeStatusExpression(%q) error = nil", invalid)
		}
	}
}

func TestNormalizeTargetRejectsSSRFEndpoints(t *testing.T) {
	for _, value := range []string{"http://example.com", "https://127.0.0.1", "https://192.168.1.1", "https://router.local", "https://user:pass@example.com"} {
		if _, err := NormalizeTarget(KindURL, value); err == nil {
			t.Errorf("NormalizeTarget(%q) error = nil", value)
		}
	}
	if normalized, err := NormalizeTarget(KindDomain, "Example.COM"); err != nil || normalized != "https://example.com/" {
		t.Fatalf("NormalizeTarget(domain) = %q, %v", normalized, err)
	}
}

func TestCreateListAndAtomicReorderTargets(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database)
	if empty, err := repository.List(ctx); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("List(empty) = %#v, %v", empty, err)
	}
	for _, id := range []string{"one", "two", "three"} {
		created, err := repository.Create(ctx, CreateInput{ID: id, Name: id, Kind: KindDomain, Value: id + ".example.com", Required: true, Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("Create(%s) error = %v", id, err)
		}
		if created.NormalizedURL == "" || !created.Required {
			t.Fatalf("created target = %+v", created)
		}
	}
	if err := repository.ReorderEnabled(ctx, []string{"three", "one", "two"}); err != nil {
		t.Fatalf("ReorderEnabled() error = %v", err)
	}
	items, err := repository.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	for index, want := range []string{"three", "one", "two"} {
		if items[index].ID != want || items[index].Priority != int64((index+1)*10) {
			t.Errorf("target[%d] = %s/%d, want %s/%d", index, items[index].ID, items[index].Priority, want, (index+1)*10)
		}
	}
	if err := repository.ReorderEnabled(ctx, []string{"one"}); !errors.Is(err, store.ErrPrioritySetMismatch) {
		t.Fatalf("incomplete reorder error = %v", err)
	}
	if err := repository.Update(ctx, "one", UpdateInput{Name: "updated", Kind: KindURL, Value: "https://updated.example.com/check", Enabled: false, Required: true, Timeout: 7 * time.Second}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	updated, err := repository.Get(ctx, "one")
	if err != nil || updated.Enabled || updated.Name != "updated" || updated.TimeoutSeconds != 7 {
		t.Fatalf("updated target = %+v, error = %v", updated, err)
	}
	if err := repository.Delete(ctx, "two", false); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repository.Get(ctx, "two"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(deleted) error = %v", err)
	}
	var nextGeneration string
	if err := database.QueryRowContext(ctx, "SELECT value_json FROM settings WHERE key='next_policy_generation'").Scan(&nextGeneration); err != nil {
		t.Fatalf("read policy generation counter: %v", err)
	}
	if nextGeneration != "7" {
		t.Fatalf("next policy generation = %s, want 7", nextGeneration)
	}
}

func TestTargetPolicyValidationAndLastRequiredConfirmationAreAtomic(t *testing.T) {
	ctx, database := migratedDatabase(t)
	repository := NewRepository(database)
	created, err := repository.Create(ctx, CreateInput{
		ID: "only", Name: "Body", Kind: KindURL, Value: "https://example.com/check",
		Required: true, Timeout: 5 * time.Second, SuccessMode: SuccessExpectedBody,
		ExpectedStatus: "302,200-299", ExpectedBodySubstring: "access granted",
	})
	if err != nil || created.ExpectedStatus != "200-299/302" || created.ExpectedBodySubstring != "access granted" {
		t.Fatalf("Create(body target) = %+v, %v", created, err)
	}
	if _, err := repository.Create(ctx, CreateInput{ID: "invalid", Name: "Invalid", Kind: KindDomain, Value: "invalid.example", Required: true, Timeout: time.Second, SuccessMode: SuccessAnyHTTPResponse, ExpectedStatus: "200"}); err == nil {
		t.Fatal("Create(any_http_response with stale expected status) error = nil")
	}
	update := UpdateInput{Name: created.Name, Kind: created.Kind, Value: created.Value, Enabled: false, Required: true, Timeout: 5 * time.Second, SuccessMode: created.SuccessMode, ExpectedStatus: created.ExpectedStatus, ExpectedBodySubstring: created.ExpectedBodySubstring}
	if err := repository.Update(ctx, created.ID, update); !errors.Is(err, ErrLastRequiredConfirmation) {
		t.Fatalf("Update(last required without confirmation) error = %v", err)
	}
	unchanged, _ := repository.Get(ctx, created.ID)
	if !unchanged.Enabled {
		t.Fatal("rejected update changed the target")
	}
	update.AllowNoRequired = true
	if err := repository.Update(ctx, created.ID, update); err != nil {
		t.Fatalf("Update(last required with confirmation) error = %v", err)
	}
	if err := repository.Delete(ctx, created.ID, false); err != nil {
		t.Fatalf("Delete(disabled target) error = %v", err)
	}

	second, err := repository.Create(ctx, CreateInput{ID: "second", Name: "Second", Kind: KindDomain, Value: "second.example", Required: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Delete(ctx, second.ID, false); !errors.Is(err, ErrLastRequiredConfirmation) {
		t.Fatalf("Delete(last required without confirmation) error = %v", err)
	}
	if err := repository.Delete(ctx, second.ID, true); err != nil {
		t.Fatalf("Delete(last required with confirmation) error = %v", err)
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
