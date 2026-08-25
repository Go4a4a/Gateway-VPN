package subscription

import (
	"testing"
	"time"
)

func TestMatcherMutationAndManualOverrideReclassifyActiveNodes(t *testing.T) {
	ctx, database := migratedDatabase(t)
	subscriptions := NewRepository(database)
	if _, err := subscriptions.Create(ctx, CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	matchers := NewMatcherRepository(database)
	if _, err := matchers.EnsureDefaults(ctx); err != nil {
		t.Fatal(err)
	}
	versions := NewVersionRepository(database)
	staged, err := versions.Stage(ctx, StageInput{VersionID: "version-a", SubscriptionID: "sub-a", Payload: []byte(
		"vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-route\n" +
			"vless://22222222-2222-2222-2222-222222222222@two.example:443#ordinary\n"), Matchers: DefaultMatchers()})
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.Activate(ctx, staged.Version.ID); err != nil {
		t.Fatal(err)
	}
	nodes := NewNodeRepository(database)
	items, err := nodes.ListActive(ctx, "sub-a")
	if err != nil || len(items) != 2 || items[0].ExternalName != "LTE-route" || !items[0].Enabled || items[1].Enabled {
		t.Fatalf("initial active nodes = %+v, %v", items, err)
	}

	preview, err := matchers.Preview(ctx, MatcherPreviewInput{ID: "default-2", Pattern: "^ordinary$", Type: MatcherRegex, Enabled: true})
	if err != nil || len(preview) != 1 || preview[0].Candidates != 1 || preview[0].Filtered != 1 {
		t.Fatalf("matcher preview = %+v, %v", preview, err)
	}
	items, _ = nodes.ListActive(ctx, "sub-a")
	if !items[0].Enabled || items[1].Enabled {
		t.Fatalf("read-only preview mutated nodes: %+v", items)
	}

	if err := matchers.Update(ctx, "default-2", MatcherUpdateInput{Pattern: "^ordinary$", Type: MatcherRegex, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	items, err = nodes.ListActive(ctx, "sub-a")
	if err != nil || items[0].Enabled || !items[1].Enabled || items[1].MatchedMatcherID != "default-2" {
		t.Fatalf("nodes after matcher update = %+v, %v", items, err)
	}
	if _, err := nodes.SetOverride(ctx, items[0].ID, OverrideInclude); err != nil {
		t.Fatal(err)
	}
	items, err = nodes.ListActive(ctx, "sub-a")
	if err != nil || !items[0].Enabled || items[0].SelectionOverride != OverrideInclude || items[0].CandidateSource != "MANUAL_INCLUDE" || !items[1].Enabled {
		t.Fatalf("nodes after manual include = %+v, %v", items, err)
	}
	var overrideEvents int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE type='NODE_OVERRIDE_CHANGED' AND subscription_id='sub-a'").Scan(&overrideEvents); err != nil || overrideEvents != 1 {
		t.Fatalf("node override audit events = %d, %v", overrideEvents, err)
	}
}

func TestDisabledInvalidRegexIsRejected(t *testing.T) {
	if _, err := CompileMatchers([]Matcher{{ID: "bad", Pattern: `(?=lte)`, Type: MatcherRegex, Enabled: false}}); err == nil {
		t.Fatal("disabled invalid regex was accepted")
	}
}
