package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
)

func TestActivationRequiresFreshPathEvidenceAndIsAudited(t *testing.T) {
	ctx, database := stateDatabase(t)
	digest := sha256.Sum256([]byte("modem-a"))
	if _, err := modem.NewRepository(database, 1101, 0x1101).Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatal(err)
	}
	if _, err := subscription.NewRepository(database).Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_versions(id, subscription_id, content_sha256, nodes_total, state, created_at, activated_at)
VALUES ('version-a', 'sub-a', ?, 1, 'LKG', ?, ?)`, hex.EncodeToString(make([]byte, 32)), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE subscriptions SET active_version_id='version-a' WHERE id='sub-a'"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO nodes(id, version_id, external_name, normalized_name, fingerprint, proxy_type)
VALUES ('node-a', 'version-a', 'A', 'a', 'fingerprint-a', 'vless')`); err != nil {
		t.Fatal(err)
	}
	matrix := pathmatrix.NewRepository(database)
	if err := matrix.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	cell, _ := matrix.Get(ctx, "modem-a", "sub-a")
	if _, _, err := NewRepository(database).BeginActivation(ctx, cell.ID, 0, 0); !errors.Is(err, store.ErrStaleGeneration) {
		t.Fatalf("BeginActivation(without evidence) error = %v", err)
	}
	expires := now.Add(time.Hour)
	if err := matrix.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: 0, ExpectedRouteGeneration: 0,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 10,
		CheckedAt: now, ExpiresAt: expires,
		Nodes: []pathmatrix.NodeEvidence{{NodeID: "node-a", State: pathmatrix.NodeBypassQualified, LatencyMS: 10}},
	}); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	verifying, changed, err := repository.BeginActivation(ctx, cell.ID, 0, 0)
	if err != nil || !changed || verifying.PathState != PathVerifying || verifying.ConfigGeneration != 1 {
		t.Fatalf("BeginActivation() = %+v/%v/%v", verifying, changed, err)
	}
	active, changed, err := repository.FinishActivation(ctx, cell.ID, 0, 0)
	if err != nil || !changed || active.PathState != PathActive || active.ActiveNodeID != "node-a" || active.ConfigGeneration != verifying.ConfigGeneration {
		t.Fatalf("FinishActivation() = %+v/%v/%v", active, changed, err)
	}
	blocked, changed, err := repository.Block(ctx, GatewayBlocked, "test")
	if err != nil || !changed || blocked.ActivePathID != "" || blocked.PathState != PathBlocked || blocked.ConfigGeneration != 2 {
		t.Fatalf("Block() = %+v/%v/%v", blocked, changed, err)
	}
	_, changed, err = repository.Block(ctx, GatewayBlocked, "test")
	if err != nil || changed {
		t.Fatalf("Block(idempotent) changed/error = %v/%v", changed, err)
	}
	events, err := repository.ListEvents(ctx, 10, 0)
	var pathEvents []Event
	for _, event := range events {
		if event.Type == "PATH_BLOCKED" || event.Type == "PATH_ACTIVATED" || event.Type == "PATH_ACTIVATION_STARTED" {
			pathEvents = append(pathEvents, event)
		}
	}
	if err != nil || len(pathEvents) != 3 || pathEvents[0].Type != "PATH_BLOCKED" || pathEvents[1].Type != "PATH_ACTIVATED" || pathEvents[2].Type != "PATH_ACTIVATION_STARTED" {
		t.Fatalf("events = %+v, %v", events, err)
	}
}

func TestBlockRepairsHalfClearedActiveTuple(t *testing.T) {
	ctx, database := stateDatabase(t)
	digest := sha256.Sum256([]byte("modem-half-state"))
	if _, err := modem.NewRepository(database, 1101, 0x1101).Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := subscription.NewRepository(database).Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE runtime_state
SET gateway_state='BLOCKED', path_state='PATH_BLOCKED', active_modem_id='modem-a',
    active_path_id=NULL, active_subscription_id='sub-a', active_node_id=NULL
WHERE singleton_id=1`); err != nil {
		t.Fatal(err)
	}
	blocked, changed, err := NewRepository(database).Block(ctx, GatewayBlocked, "repair-half-state")
	if err != nil || !changed {
		t.Fatalf("Block() = %+v, changed=%v, err=%v", blocked, changed, err)
	}
	if blocked.ActiveModemID != "" || blocked.ActivePathID != "" || blocked.ActiveSubscriptionID != "" || blocked.ActiveNodeID != "" {
		t.Fatalf("Block() retained partial active tuple: %+v", blocked)
	}
}

func TestPolicyTransitionIsDurableFinishesOnlyWithFreshActiveEvidenceAndRecoversBlocked(t *testing.T) {
	ctx, database := stateDatabase(t)
	repository, matrix, cell, now := seedActivePolicyState(t, ctx, database)
	generation, err := matrix.BumpPolicyGeneration(ctx)
	if err != nil || generation != 1 {
		t.Fatalf("BumpPolicyGeneration() = %d, %v", generation, err)
	}
	transition, err := repository.Get(ctx)
	if err != nil || !transition.PolicyTransitionActive() || transition.ActivePathID != cell.ID || transition.PolicyTransitionGeneration != generation || transition.PathState != PathActive {
		t.Fatalf("policy transition = %+v, %v", transition, err)
	}
	started, startErr := time.Parse(time.RFC3339Nano, transition.PolicyTransitionStartedAt)
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, transition.PolicyTransitionDeadline)
	if startErr != nil || deadlineErr != nil || deadline.Sub(started) != store.PolicyGracePeriod {
		t.Fatalf("policy transition times = %s/%s, %v/%v", transition.PolicyTransitionStartedAt, transition.PolicyTransitionDeadline, startErr, deadlineErr)
	}
	if _, _, err := repository.FinishPolicyVerification(ctx, generation); !errors.Is(err, store.ErrStaleGeneration) {
		t.Fatalf("FinishPolicyVerification(with stale evidence) error = %v", err)
	}
	if err := matrix.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: generation, ExpectedRouteGeneration: cell.RouteGeneration,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 11,
		CheckedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour),
		Nodes: []pathmatrix.NodeEvidence{{NodeID: "node-a", State: pathmatrix.NodeBypassQualified, LatencyMS: 11}},
	}); err != nil {
		t.Fatal(err)
	}
	active, changed, err := repository.FinishPolicyVerification(ctx, generation)
	if err != nil || !changed || active.GatewayState != GatewayActive || active.PathState != PathActive || active.PolicyTransitionActive() || active.ConfigGeneration != transition.ConfigGeneration {
		t.Fatalf("FinishPolicyVerification() = %+v/%v/%v", active, changed, err)
	}

	if _, err := matrix.BumpPolicyGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE runtime_state SET policy_transition_deadline=NULL WHERE singleton_id=1"); err == nil {
		t.Fatal("partial policy transition update was accepted")
	}
	recovered, err := repository.RecoverPolicyTransition(ctx)
	if err != nil || !recovered {
		t.Fatalf("RecoverPolicyTransition() = %v, %v", recovered, err)
	}
	blocked, _ := repository.Get(ctx)
	if blocked.PathState != PathBlocked || blocked.GatewayState != GatewayBlocked || blocked.ActivePathID != "" || blocked.PolicyTransitionActive() || blocked.ConfigGeneration != active.ConfigGeneration+1 {
		t.Fatalf("recovered policy transition = %+v", blocked)
	}
	events, err := repository.ListEvents(ctx, 20, 0)
	if err != nil || len(events) == 0 || events[0].Type != "POLICY_VERIFICATION_INTERRUPTED" {
		t.Fatalf("policy recovery events = %+v, %v", events, err)
	}
}

func seedActivePolicyState(t *testing.T, ctx context.Context, database *sql.DB) (*Repository, *pathmatrix.Repository, pathmatrix.Cell, time.Time) {
	t.Helper()
	digest := sha256.Sum256([]byte("policy-modem"))
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE modems SET state='MODEM_READY'"); err != nil {
		t.Fatal(err)
	}
	if _, err := subscription.NewRepository(database).Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := database.ExecContext(ctx, `
INSERT INTO subscription_versions(id, subscription_id, content_sha256, nodes_total, state, created_at, activated_at)
VALUES ('version-a', 'sub-a', ?, 1, 'LKG', ?, ?);
UPDATE subscriptions SET active_version_id='version-a' WHERE id='sub-a';
INSERT INTO nodes(id, version_id, external_name, normalized_name, fingerprint, proxy_type)
VALUES ('node-a', 'version-a', 'A', 'a', 'fingerprint-a', 'vless')`,
		hex.EncodeToString(make([]byte, 32)), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	matrix := pathmatrix.NewRepository(database)
	if err := matrix.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	cell, err := matrix.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := matrix.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: cell.PolicyGeneration, ExpectedRouteGeneration: cell.RouteGeneration,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 10,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []pathmatrix.NodeEvidence{{NodeID: "node-a", State: pathmatrix.NodeBypassQualified, LatencyMS: 10}},
	}); err != nil {
		t.Fatal(err)
	}
	repository := NewRepository(database)
	intent, _, err := repository.BeginActivation(ctx, cell.ID, cell.PolicyGeneration, cell.RouteGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.FinishActivation(ctx, cell.ID, cell.PolicyGeneration, cell.RouteGeneration); err != nil {
		t.Fatal(err)
	}
	if intent.ConfigGeneration != 1 {
		t.Fatalf("activation generation = %d", intent.ConfigGeneration)
	}
	return repository, matrix, cell, now
}

func stateDatabase(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	return ctx, database
}
