package subscription

import (
	"errors"
	"testing"
	"time"

	"gateway-vpn/internal/store"
)

func TestStageAndActivateSubscriptionVersionPreservesPreviousLKG(t *testing.T) {
	ctx, database := migratedDatabase(t)
	subscriptions := NewRepository(database)
	if _, err := subscriptions.Create(ctx, CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	repository := NewVersionRepository(database)
	payloadOne := []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE%20one\n")
	first, err := repository.Stage(ctx, StageInput{VersionID: "version-1", SubscriptionID: "sub-a", Payload: payloadOne})
	if err != nil {
		t.Fatalf("Stage(first) error = %v", err)
	}
	if len(first.Nodes) != 1 || !first.Nodes[0].Enabled || first.Nodes[0].CandidateSource != CandidateName {
		t.Fatalf("first staged nodes = %+v", first.Nodes)
	}
	if err := repository.Activate(ctx, first.Version.ID); err != nil {
		t.Fatalf("Activate(first) error = %v", err)
	}

	payloadTwo := []byte("vless://22222222-2222-2222-2222-222222222222@two.example:443#ordinary\n")
	second, err := repository.Stage(ctx, StageInput{VersionID: "version-2", SubscriptionID: "sub-a", Payload: payloadTwo})
	if err != nil {
		t.Fatalf("Stage(second) error = %v", err)
	}
	if second.Nodes[0].CandidateSource != CandidateFallback {
		t.Fatalf("second candidate source = %s", second.Nodes[0].CandidateSource)
	}
	if err := repository.Activate(ctx, second.Version.ID); err != nil {
		t.Fatalf("Activate(second) error = %v", err)
	}
	previous, _ := repository.Get(ctx, first.Version.ID)
	active, _ := repository.Get(ctx, second.Version.ID)
	if previous.State != VersionRetained || active.State != VersionLKG {
		t.Fatalf("version states = %s/%s", previous.State, active.State)
	}
	subscriptionRecord, err := subscriptions.Get(ctx, "sub-a")
	if err != nil || subscriptionRecord.ActiveVersionID != second.Version.ID {
		t.Fatalf("active subscription = %+v, error = %v", subscriptionRecord, err)
	}
}

func TestStageRollbackAndFailedCandidateDoNotReplaceLKG(t *testing.T) {
	ctx, database := migratedDatabase(t)
	subscriptions := NewRepository(database)
	if _, err := subscriptions.Create(ctx, CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	repository := NewVersionRepository(database)
	if _, err := repository.Stage(ctx, StageInput{VersionID: "bad", SubscriptionID: "sub-a", Payload: []byte("not a subscription")}); err == nil {
		t.Fatal("Stage(invalid) error = nil")
	}
	if _, err := repository.Get(ctx, "bad"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("invalid version persisted, error = %v", err)
	}
	staged, err := repository.Stage(ctx, StageInput{VersionID: "candidate", SubscriptionID: "sub-a", Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#one")})
	if err != nil {
		t.Fatalf("Stage(candidate) error = %v", err)
	}
	if err := repository.MarkFailed(ctx, staged.Version.ID, errors.New("mihomo validation failed")); err != nil {
		t.Fatalf("MarkFailed() error = %v", err)
	}
	failed, _ := repository.Get(ctx, staged.Version.ID)
	if failed.State != VersionFailed || failed.Error == "" {
		t.Fatalf("failed version = %+v", failed)
	}
	if err := repository.Activate(ctx, staged.Version.ID); err == nil {
		t.Fatal("Activate(failed) error = nil")
	}
}

func TestAbortActivationRestoresPreviousLKGAfterUncertainCommit(t *testing.T) {
	ctx, database := migratedDatabase(t)
	subscriptions := NewRepository(database)
	if _, err := subscriptions.Create(ctx, CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	repository := NewVersionRepository(database)
	first, err := repository.Stage(ctx, StageInput{VersionID: "version-1", SubscriptionID: "sub-a", Payload: []byte("vless://11111111-1111-1111-1111-111111111111@one.example:443#LTE-one")})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Activate(ctx, first.Version.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE nodes SET selection_override=? WHERE version_id=?", OverrideInclude, first.Version.ID); err != nil {
		t.Fatal(err)
	}
	overrides, err := repository.ActiveOverrides(ctx, "sub-a")
	if err != nil || len(overrides) != 1 {
		t.Fatalf("ActiveOverrides() = %+v, %v", overrides, err)
	}

	second, err := repository.Stage(ctx, StageInput{VersionID: "version-2", SubscriptionID: "sub-a", Payload: []byte("vless://22222222-2222-2222-2222-222222222222@two.example:443#LTE-two")})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Activate(ctx, second.Version.ID); err != nil {
		t.Fatal(err)
	}
	if err := repository.AbortActivation(ctx, second.Version.ID, errors.New(RefreshActivateFailed)); err != nil {
		t.Fatalf("AbortActivation() error = %v", err)
	}
	oldVersion, _ := repository.Get(ctx, first.Version.ID)
	failedVersion, _ := repository.Get(ctx, second.Version.ID)
	current, err := subscriptions.Get(ctx, "sub-a")
	if err != nil || oldVersion.State != VersionLKG || failedVersion.State != VersionFailed || failedVersion.Error != RefreshActivateFailed || current.ActiveVersionID != first.Version.ID {
		t.Fatalf("compensated versions old=%+v failed=%+v subscription=%+v error=%v", oldVersion, failedVersion, current, err)
	}
}
