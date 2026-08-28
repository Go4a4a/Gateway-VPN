package accesspolicy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
)

func TestDirectPathsReconcilePublishAndRejectStaleGenerations(t *testing.T) {
	ctx, database := accessDatabase(t)
	modems := seedAccessModems(t, ctx, database, "modem-a", "modem-b")
	makeAccessModemReady(t, ctx, modems, "modem-a", 8)

	repository := NewDirectPathRepository(database)
	if err := repository.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	paths, err := repository.List(ctx)
	if err != nil || len(paths) != 2 {
		t.Fatalf("List() = %+v, %v", paths, err)
	}
	if paths[0].UplinkID != "modem-a" || paths[0].State != "UNTESTED" || paths[0].RouteGeneration != 1 {
		t.Fatalf("ready direct path = %+v", paths[0])
	}
	if paths[1].UplinkID != "modem-b" || paths[1].State != "UPLINK_OFFLINE" {
		t.Fatalf("offline direct path = %+v", paths[1])
	}

	makeAccessModemReady(t, ctx, modems, "modem-b", 9)
	if err := repository.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile(second modem) error = %v", err)
	}
	paths, err = repository.List(ctx)
	if err != nil || len(paths) != 2 || paths[1].State != "STALE" || paths[1].RouteGeneration != 1 {
		t.Fatalf("ready direct paths = %+v, %v", paths, err)
	}

	seedDirectTargets(t, ctx, database)
	checkedAt := time.Now().UTC()
	full := directUpdate(paths[0], checkedAt, QualityFull, 2001, "PASSED", "FAILED")
	incomplete := full
	incomplete.OptionalTargetsTotal = 0
	incomplete.Targets = incomplete.Targets[:1]
	if err := repository.Publish(ctx, incomplete); err == nil {
		t.Fatal("Publish() accepted incomplete active target evidence")
	}
	if err := repository.Publish(ctx, full); err != nil {
		t.Fatalf("Publish(FULL) error = %v", err)
	}
	limited := directUpdate(paths[1], checkedAt, QualityLimited, 1, "FAILED", "PASSED")
	if err := repository.Publish(ctx, limited); err != nil {
		t.Fatalf("Publish(LIMITED) error = %v", err)
	}
	decision, err := repository.BestCandidate(ctx, true, "")
	if err != nil || decision.Candidate.UplinkID != "modem-a" || decision.Candidate.Quality != QualityFull {
		t.Fatalf("BestCandidate() = %+v, %v", decision, err)
	}

	if _, err := database.ExecContext(ctx, "UPDATE modems SET route_generation=route_generation+1 WHERE id='modem-a'"); err != nil {
		t.Fatal(err)
	}
	decision, err = repository.BestCandidate(ctx, true, "")
	if err != nil || decision.Candidate.UplinkID != "modem-b" {
		t.Fatalf("candidate after route generation change = %+v, %v", decision, err)
	}
	if err := repository.Publish(ctx, full); !errors.Is(err, store.ErrStaleGeneration) {
		t.Fatalf("stale route Publish() error = %v", err)
	}
	if err := repository.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile(stale route) error = %v", err)
	}
	paths, _ = repository.List(ctx)
	if paths[0].State != "STALE" || paths[0].QualityClass != QualityUnknown || paths[0].RouteGeneration != 2 || paths[0].ExpiresAt != "" {
		t.Fatalf("reconciled stale route = %+v", paths[0])
	}

	if _, err := database.ExecContext(ctx, `
INSERT INTO settings(key, value_json, updated_at) VALUES ('next_policy_generation', '2', ?)
ON CONFLICT(key) DO UPDATE SET value_json='2', updated_at=excluded.updated_at`, checkedAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.BestCandidate(ctx, true, ""); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("stale policy BestCandidate() error = %v", err)
	}
	if err := repository.Publish(ctx, limited); !errors.Is(err, store.ErrStaleGeneration) {
		t.Fatalf("stale policy Publish() error = %v", err)
	}
	if err := repository.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile(stale policy) error = %v", err)
	}
	paths, _ = repository.List(ctx)
	for _, path := range paths {
		if path.PolicyGeneration != 1 || path.QualityClass != QualityUnknown || path.State != "STALE" {
			t.Fatalf("policy-invalidated path = %+v", path)
		}
	}
}

func TestDirectMethodCanBeDisabledWithoutRemovingServicePaths(t *testing.T) {
	ctx, database := accessDatabase(t)
	modems := seedAccessModems(t, ctx, database, "modem-a")
	makeAccessModemReady(t, ctx, modems, "modem-a", 8)
	seedDirectTargets(t, ctx, database)
	repository := NewDirectPathRepository(database)
	if err := repository.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	paths, _ := repository.List(ctx)
	checkedAt := time.Now().UTC()
	if err := repository.Publish(ctx, directUpdate(paths[0], checkedAt, QualityFull, 2001, "PASSED", "PASSED")); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.BestCandidate(ctx, true, ""); err != nil {
		t.Fatalf("enabled direct method has no candidate: %v", err)
	}
	if _, err := database.ExecContext(ctx, "UPDATE access_methods SET enabled=0 WHERE id=?", DirectMethodID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.BestCandidate(ctx, true, ""); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("disabled direct method candidate error = %v", err)
	}
	paths, err := repository.List(ctx)
	if err != nil || len(paths) != 1 || paths[0].MethodEnabled {
		t.Fatalf("disabled method service path = %+v, %v", paths, err)
	}
}

func TestUnifiedCandidatesRankDirectAndVPNByQualityThenPriority(t *testing.T) {
	ctx, database := accessDatabase(t)
	modems := seedAccessModems(t, ctx, database, "modem-a")
	makeAccessModemReady(t, ctx, modems, "modem-a", 8)
	seedDirectTargets(t, ctx, database)

	subscriptions := subscription.NewRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{
		ID: "sub-a", Name: "Subscription A", SourceType: "url",
		SourceSecretRef: "/secret/sub-a", RefreshInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	versions := subscription.NewVersionRepository(database)
	staged, err := versions.Stage(ctx, subscription.StageInput{
		VersionID: "version-a", SubscriptionID: "sub-a",
		Payload: []byte("vless://11111111-1111-1111-1111-111111111111@vpn.example:443#LTE"),
	})
	if err != nil || len(staged.Nodes) != 1 {
		t.Fatalf("Stage() = %+v, %v", staged, err)
	}
	if err := versions.Activate(ctx, staged.Version.ID); err != nil {
		t.Fatal(err)
	}

	directPaths := NewDirectPathRepository(database)
	if err := directPaths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	vpnPaths := pathmatrix.NewRepository(database)
	if err := vpnPaths.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	direct, _ := directPaths.List(ctx)
	vpn, err := vpnPaths.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	checkedAt := time.Now().UTC()
	if err := directPaths.Publish(ctx, directUpdate(direct[0], checkedAt, QualityLimited, 900, "FAILED", "PASSED")); err != nil {
		t.Fatal(err)
	}
	if err := publishVPNResult(ctx, vpnPaths, vpn, staged.Nodes[0].ID, checkedAt, QualityFull, 2000); err != nil {
		t.Fatal(err)
	}
	decision, err := directPaths.BestCandidate(ctx, false, "")
	if err != nil || decision.Candidate.MethodKind != MethodSubscription {
		t.Fatalf("FULL VPN versus LIMITED direct = %+v, %v", decision, err)
	}

	if err := publishVPNResult(ctx, vpnPaths, vpn, staged.Nodes[0].ID, checkedAt, QualityLimited, 100); err != nil {
		t.Fatal(err)
	}
	decision, err = directPaths.BestCandidate(ctx, false, "")
	if err != nil || decision.Candidate.MethodKind != MethodDirect || decision.Candidate.FunctionalScore != 900 {
		t.Fatalf("LIMITED functional ranking = %+v, %v", decision, err)
	}

	if err := directPaths.Publish(ctx, directUpdate(direct[0], checkedAt, QualityFull, 2000, "PASSED", "PASSED")); err != nil {
		t.Fatal(err)
	}
	if err := publishVPNResult(ctx, vpnPaths, vpn, staged.Nodes[0].ID, checkedAt, QualityFull, 2000); err != nil {
		t.Fatal(err)
	}
	decision, err = directPaths.BestCandidate(ctx, false, "")
	if err != nil || decision.Candidate.MethodKind != MethodDirect || decision.Candidate.MethodPriority != 10 {
		t.Fatalf("equal FULL priority ranking = %+v, %v", decision, err)
	}
}

func seedAccessModems(t *testing.T, ctx context.Context, database *sql.DB, ids ...string) *modem.Repository {
	t.Helper()
	repository := modem.NewRepository(database, 1101, 0x1101)
	for _, id := range ids {
		digest := sha256.Sum256([]byte(id))
		if _, err := repository.Adopt(ctx, modem.AdoptInput{
			ID: id, Name: id, IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:]),
		}); err != nil {
			t.Fatalf("adopt modem %s: %v", id, err)
		}
	}
	return repository
}

func makeAccessModemReady(t *testing.T, ctx context.Context, repository *modem.Repository, id string, subnet int) {
	t.Helper()
	if _, err := repository.ApplyLease(ctx, id, modem.LeaseInput{
		InterfaceName:  "enx-" + id,
		ManagementCIDR: fmt.Sprintf("192.168.%d.0/24", subnet),
		Gateway:        fmt.Sprintf("192.168.%d.1", subnet),
		DNS:            []string{fmt.Sprintf("192.168.%d.1", subnet)},
		MTU:            1500,
		State:          modem.StateReady,
	}); err != nil {
		t.Fatalf("ready modem %s: %v", id, err)
	}
}

func seedDirectTargets(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for index, item := range []struct {
		id          string
		required    int
		targetClass string
	}{{"target-required", 1, "GLOBAL_REQUIRED"}, {"target-optional", 0, "GLOBAL_OPTIONAL"}} {
		if _, err := database.ExecContext(ctx, `
INSERT INTO bypass_probe_targets (
    id, name, target_kind, target_value, normalized_url, enabled, required,
	    priority, timeout_seconds, success_mode, state, created_at, updated_at,
	    target_class
) VALUES (?, ?, 'url', ?, ?, 1, ?, ?, 5, 'any_http_response', 'UNKNOWN', ?, ?, ?)`,
			item.id, item.id, "https://"+item.id+".example/", "https://"+item.id+".example/", item.required, (index+1)*10, now, now, item.targetClass); err != nil {
			t.Fatalf("insert target %s: %v", item.id, err)
		}
	}
}

func directUpdate(path DirectPath, checkedAt time.Time, quality string, score int64, requiredState, optionalState string) DirectResultUpdate {
	requiredPassed := int64(0)
	if requiredState == "PASSED" {
		requiredPassed = 1
	}
	optionalPassed := int64(0)
	if optionalState == "PASSED" {
		optionalPassed = 1
	}
	expiresAt := checkedAt.Add(15 * time.Minute)
	return DirectResultUpdate{
		PathID: path.ID, ExpectedPolicyGeneration: path.PolicyGeneration,
		ExpectedRouteGeneration: path.RouteGeneration, TransportState: "PASSED",
		QualityClass: quality, FunctionalScore: score,
		RequiredTargetsPassed: requiredPassed, RequiredTargetsTotal: 1,
		OptionalTargetsPassed: optionalPassed, OptionalTargetsTotal: 1,
		LatencyMS: 50, CheckedAt: checkedAt, ExpiresAt: expiresAt,
		Targets: []DirectTargetResult{
			{TargetID: "target-required", TargetClass: "GLOBAL_REQUIRED", State: requiredState, LatencyMS: 40, CheckedAt: checkedAt, ExpiresAt: expiresAt},
			{TargetID: "target-optional", TargetClass: "GLOBAL_OPTIONAL", State: optionalState, LatencyMS: 50, CheckedAt: checkedAt, ExpiresAt: expiresAt},
		},
	}
}

func publishVPNResult(ctx context.Context, repository *pathmatrix.Repository, path pathmatrix.Cell, nodeID string, checkedAt time.Time, quality string, score int64) error {
	state := pathmatrix.StateQualified
	nodeState := pathmatrix.NodeBypassQualified
	requiredPassed := int64(1)
	requiredState := "PASSED"
	if quality == QualityLimited {
		state = pathmatrix.StateDegraded
		nodeState = pathmatrix.NodeBypassLimited
		requiredPassed = 0
		requiredState = "FAILED"
	}
	return repository.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: path.ID, ExpectedPolicyGeneration: path.PolicyGeneration,
		ExpectedRouteGeneration: path.RouteGeneration, State: state,
		TransportState: "PASSED", SelectedNodeID: nodeID,
		RequiredTargetsPassed: requiredPassed, RequiredTargetsTotal: 1,
		OptionalTargetsPassed: 1, OptionalTargetsTotal: 1, FunctionalScore: score,
		LatencyMS: 70, CheckedAt: checkedAt, ExpiresAt: checkedAt.Add(15 * time.Minute),
		Nodes: []pathmatrix.NodeEvidence{{
			NodeID: nodeID, State: nodeState, LatencyMS: 70,
			Targets: []pathmatrix.TargetEvidence{
				{TargetID: "target-required", State: requiredState, LatencyMS: 30},
				{TargetID: "target-optional", State: "PASSED", LatencyMS: 30},
			},
		}},
	})
}
