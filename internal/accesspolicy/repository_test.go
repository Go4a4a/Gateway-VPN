package accesspolicy

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
)

func TestRepositorySeedsDirectAndSynchronizesSubscriptionMethods(t *testing.T) {
	ctx, database := accessDatabase(t)
	repository := NewRepository(database)
	methods, err := repository.ListMethods(ctx)
	if err != nil || len(methods) != 1 || methods[0].ID != DirectMethodID || methods[0].Kind != MethodDirect || !methods[0].Enabled || !methods[0].Immutable || methods[0].Priority != 10 {
		t.Fatalf("initial methods = %+v, %v", methods, err)
	}
	subscriptions := subscription.NewRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	methods, err = repository.ListMethods(ctx)
	if err != nil || len(methods) != 2 || methods[0].ID != DirectMethodID || methods[1].SubscriptionID != "sub-a" || methods[1].Priority != 20 {
		t.Fatalf("methods after subscription create = %+v, %v", methods, err)
	}
	if err := repository.ReorderEnabled(ctx, []string{"access:subscription:sub-a", DirectMethodID}); err != nil {
		t.Fatal(err)
	}
	methods, _ = repository.ListMethods(ctx)
	if methods[0].SubscriptionID != "sub-a" || methods[0].Priority != 10 || methods[1].ID != DirectMethodID || methods[1].Priority != 20 {
		t.Fatalf("reordered methods = %+v", methods)
	}
	if err := repository.SetMethodEnabled(ctx, DirectMethodID, false); err != nil {
		t.Fatal(err)
	}
	methods, _ = repository.ListMethods(ctx)
	if methods[len(methods)-1].ID != DirectMethodID || methods[len(methods)-1].Enabled {
		t.Fatalf("disabled direct method = %+v", methods)
	}
	policy, err := repository.GetPolicy(ctx)
	if err != nil || !policy.DirectServiceRefresh || policy.RankingGeneration < 4 {
		t.Fatalf("policy after method changes = %+v, %v", policy, err)
	}
	if err := repository.ReorderEnabled(ctx, []string{DirectMethodID}); !errors.Is(err, store.ErrPrioritySetMismatch) {
		t.Fatalf("invalid reorder error = %v", err)
	}
}

func TestRepositoryValidatesAndPersistsStartupAndHysteresisPolicy(t *testing.T) {
	ctx, database := accessDatabase(t)
	repository := NewRepository(database)
	updated, err := repository.UpdatePolicy(ctx, PolicyUpdate{
		StartupBlockUntilQualified: false,
		DirectServiceRefresh:       true,
		FailureHoldSeconds:         15,
		RecoveryStableSeconds:      90,
		SwitchCooldownSeconds:      45,
	})
	if err != nil || updated.StartupBlockUntilQualified || !updated.DirectServiceRefresh || updated.FailureHoldSeconds != 15 || updated.RecoveryStableSeconds != 90 || updated.SwitchCooldownSeconds != 45 || updated.RankingGeneration != 2 {
		t.Fatalf("UpdatePolicy() = %+v, %v", updated, err)
	}
	if _, err := repository.UpdatePolicy(ctx, PolicyUpdate{FailureHoldSeconds: 301}); err == nil {
		t.Fatal("unsafe access policy interval accepted")
	}
}

func TestNodePreferencesSurviveVersionRefreshByFingerprint(t *testing.T) {
	ctx, database := accessDatabase(t)
	subscriptions := subscription.NewRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	versions := subscription.NewVersionRepository(database)
	first, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-a", SubscriptionID: "sub-a", Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-old")})
	if err != nil || len(first.Nodes) != 1 {
		t.Fatalf("first Stage() = %+v, %v", first, err)
	}
	if err := versions.Activate(ctx, first.Version.ID); err != nil {
		t.Fatal(err)
	}
	nodes := subscription.NewNodeRepository(database)
	if _, err := nodes.SetOverride(ctx, first.Nodes[0].ID, subscription.OverrideInclude); err != nil {
		t.Fatal(err)
	}
	preferences := NewPreferenceRepository(database)
	if err := preferences.ReorderPreferred(ctx, "sub-a", []string{first.Nodes[0].Fingerprint}); err != nil {
		t.Fatal(err)
	}
	overrides, err := versions.ActiveOverrides(ctx, "sub-a")
	if err != nil || overrides[first.Nodes[0].Fingerprint] != subscription.OverrideInclude {
		t.Fatalf("durable overrides = %+v, %v", overrides, err)
	}
	second, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-b", SubscriptionID: "sub-a", Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#renamed"), Overrides: overrides})
	if err != nil || len(second.Nodes) != 1 || second.Nodes[0].Fingerprint != first.Nodes[0].Fingerprint || second.Nodes[0].SelectionOverride != subscription.OverrideInclude {
		t.Fatalf("second Stage() = %+v, %v", second, err)
	}
	if err := versions.Activate(ctx, second.Version.ID); err != nil {
		t.Fatal(err)
	}
	items, err := preferences.List(ctx, "sub-a")
	if err != nil || len(items) != 1 || items[0].PreferredRank != 10 || items[0].SelectionOverride != subscription.OverrideInclude || items[0].ActiveNodeName != "renamed" || items[0].MissingSince != "" {
		t.Fatalf("preferences after refresh = %+v, %v", items, err)
	}
}

func accessDatabase(t *testing.T) (context.Context, *sql.DB) {
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
	return ctx, database
}
