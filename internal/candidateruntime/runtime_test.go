package candidateruntime

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
)

type recordedApply struct {
	Generation string
	Bundle     mihomo.Bundle
}

type fakeController struct {
	current  string
	applies  []recordedApply
	restores []string
}

func (controller *fakeController) Apply(_ context.Context, generation string, bundle mihomo.Bundle) (mihomo.ApplyResult, error) {
	previous := controller.current
	controller.current = generation
	controller.applies = append(controller.applies, recordedApply{Generation: generation, Bundle: bundle})
	return mihomo.ApplyResult{Generation: generation, PreviousGeneration: previous}, nil
}

func (controller *fakeController) Restore(_ context.Context, generation string) error {
	controller.restores = append(controller.restores, generation)
	controller.current = generation
	return nil
}

type selection struct {
	Group  string
	Target string
}

type fakeSelector struct {
	selections []selection
}

type fakeRoutingSynchronizer struct {
	calls int
	err   error
}

type fakeEndpointAuthorizer struct {
	requests [][]string
	err      error
}

func (authorizer *fakeEndpointAuthorizer) AuthorizeMihomoVersions(_ context.Context, versions []string) error {
	authorizer.requests = append(authorizer.requests, append([]string(nil), versions...))
	return authorizer.err
}

func (synchronizer *fakeRoutingSynchronizer) SyncRouting(context.Context) error {
	synchronizer.calls++
	return synchronizer.err
}

func (selector *fakeSelector) Select(_ context.Context, group, target string) error {
	selector.selections = append(selector.selections, selection{Group: group, Target: target})
	return nil
}

type modemScopedProber struct {
	passing map[string]bool
}

func (prober modemScopedProber) ProbeTransport(_ context.Context, _ health.Path, _ health.Candidate) health.ProbeResult {
	return health.ProbeResult{State: health.ProbePassed, LatencyMS: 5}
}

func (prober modemScopedProber) ProbeTarget(_ context.Context, currentPath health.Path, _ health.Candidate, _ health.Target) health.ProbeResult {
	if prober.passing[currentPath.ModemID] {
		return health.ProbeResult{State: health.ProbePassed, LatencyMS: 10}
	}
	return health.ProbeResult{State: health.ProbeFailed, ErrorCode: "TARGET_UNREACHABLE"}
}

type runtimeFixture struct {
	ctx              context.Context
	database         *sql.DB
	payloadRoot      string
	subscriptions    *subscription.Repository
	versions         *subscription.VersionRepository
	modems           *modem.Repository
	targets          *bypass.Repository
	paths            *pathmatrix.Repository
	controller       *fakeController
	selector         *fakeSelector
	oldVersionID     string
	candidate        subscription.Candidate
	candidateRuntime *Runtime
}

func TestPreferredNodeOrderAndStickyIdentityTransferByFingerprint(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true})
	defer fixture.database.Close()
	stored, err := fixture.versions.ListNodes(fixture.ctx, fixture.oldVersionID, true)
	if err != nil || len(stored) != 1 {
		t.Fatalf("old active nodes = %+v, %v", stored, err)
	}
	if err := fixture.candidateRuntime.Preferences.ReorderPreferred(fixture.ctx, "sub-a", []string{stored[0].Fingerprint}); err != nil {
		t.Fatal(err)
	}
	material := candidateMaterial{
		Subscription: subscription.Subscription{ID: "sub-a"},
		NodesByID: map[string]nodeIdentity{
			"node-new-version": {ID: "node-new-version", Fingerprint: stored[0].Fingerprint, ExternalName: "renamed"},
		},
	}
	ordered, err := fixture.candidateRuntime.preferredNodeIDs(fixture.ctx, material, stored[0].ID)
	if err != nil || len(ordered) != 1 || ordered[0] != "node-new-version" {
		t.Fatalf("transferred preferred order = %+v, %v", ordered, err)
	}
}

func TestPreferredNodeOrderSelectsFirstQualifiedNodeInRuntimePath(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": true})
	defer fixture.database.Close()
	staged, err := fixture.versions.Stage(fixture.ctx, subscription.StageInput{
		VersionID: "version-preferred", SubscriptionID: "sub-a",
		Payload: []byte("vless://33333333-3333-3333-3333-333333333333@first.example.com:443#LTE-first\n" +
			"vless://44444444-4444-4444-4444-444444444444@second.example.com:443#LTE-second\n"),
	})
	if err != nil || len(staged.Nodes) != 2 {
		t.Fatalf("stage preferred runtime nodes = %+v, %v", staged, err)
	}
	if _, err := subscription.WriteNormalizedPayload(fixture.payloadRoot, "sub-a", staged.Version.ID, staged.Import); err != nil {
		t.Fatal(err)
	}
	if err := fixture.versions.Activate(fixture.ctx, staged.Version.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.candidateRuntime.Preferences.ReorderPreferred(fixture.ctx, "sub-a", []string{staged.Nodes[1].Fingerprint, staged.Nodes[0].Fingerprint}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.paths.ReconcileCells(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	cell, err := fixture.paths.Get(fixture.ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	operation, err := fixture.candidateRuntime.QualifyPath(fixture.ctx, cell.ID)
	if err != nil || operation.Result.SelectedNodeID != staged.Nodes[1].ID || len(operation.Result.Nodes) != 1 {
		t.Fatalf("preferred runtime qualification = %+v, %v", operation, err)
	}
	stored, err := fixture.paths.GetByID(fixture.ctx, cell.ID)
	if err != nil || stored.SelectedNodeID != staged.Nodes[1].ID || stored.State != pathmatrix.StateQualified {
		t.Fatalf("stored preferred runtime path = %+v, %v", stored, err)
	}
}

func TestDisabledSubscriptionLKGRemainsServiceOnlyInMihomoBundle(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true})
	defer fixture.database.Close()
	if err := fixture.subscriptions.SetEnabled(fixture.ctx, "sub-a", false); err != nil {
		t.Fatal(err)
	}
	ready, err := fixture.candidateRuntime.readyModems(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := fixture.candidateRuntime.buildBundle(fixture.ctx, ready, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Paths) != 2 {
		t.Fatalf("service-only path count = %d", len(bundle.Paths))
	}
	for _, path := range bundle.Paths {
		if !path.QualificationOnly || path.SubscriptionID != "sub-a" {
			t.Fatalf("disabled subscription entered user routing bundle: %+v", path)
		}
	}
	versions, err := fixture.candidateRuntime.endpointVersionIDs(fixture.ctx, nil)
	if err != nil || len(versions) != 1 || versions[0] != fixture.oldVersionID {
		t.Fatalf("service-only endpoint versions = %v, %v", versions, err)
	}
}

func TestDisabledSubscriptionCanRefreshLKGWithoutPublishingUserPath(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true})
	defer fixture.database.Close()
	if err := fixture.subscriptions.SetEnabled(fixture.ctx, "sub-a", false); err != nil {
		t.Fatal(err)
	}
	fixture.candidate.Subscription.Enabled = false
	promoted, err := fixture.candidateRuntime.Promote(fixture.ctx, fixture.candidate)
	if err != nil {
		t.Fatalf("Promote(disabled subscription) error = %v", err)
	}
	if err := fixture.versions.Activate(fixture.ctx, fixture.candidate.Version.Version.ID); err != nil {
		t.Fatal(err)
	}
	if err := promoted.Commit(fixture.ctx); err != nil {
		t.Fatalf("Commit(disabled subscription) error = %v", err)
	}
	cell, err := fixture.paths.Get(fixture.ctx, "modem-a", "sub-a")
	if err != nil || cell.State != pathmatrix.StateSubscriptionDisabled || cell.SelectedNodeID != "" || cell.QualityClass != "UNKNOWN" {
		t.Fatalf("disabled refreshed user path = %+v, %v", cell, err)
	}
	lastBundle := fixture.controller.applies[len(fixture.controller.applies)-1].Bundle
	for _, path := range lastBundle.Paths {
		if !path.QualificationOnly {
			t.Fatalf("disabled refresh exposed user path: %+v", path)
		}
	}
}

func TestPromotionQualifiesCandidateThroughEveryReadyModemBeforePublishingEvidence(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": false})
	defer fixture.database.Close()

	promoted, err := fixture.candidateRuntime.Promote(fixture.ctx, fixture.candidate)
	if err != nil {
		t.Fatalf("Promote() error = %v", err)
	}
	if len(fixture.controller.applies) != 1 {
		t.Fatalf("temporary generation applies = %d", len(fixture.controller.applies))
	}
	temporary := fixture.controller.applies[0].Bundle
	shadowPaths, activePaths := 0, 0
	for _, item := range temporary.Paths {
		if item.QualificationOnly {
			shadowPaths++
		} else {
			activePaths++
		}
	}
	if shadowPaths != 2 || activePaths != 2 {
		t.Fatalf("temporary active/shadow path counts = %d/%d", activePaths, shadowPaths)
	}
	assertEvidenceCount(t, fixture.database, fixture.candidate.Version.Version.ID, 0)
	version, err := fixture.versions.Get(fixture.ctx, fixture.candidate.Version.Version.ID)
	if err != nil || version.State != subscription.VersionCandidate {
		t.Fatalf("candidate before SQLite activation = %+v, %v", version, err)
	}

	if err := fixture.versions.Activate(fixture.ctx, fixture.candidate.Version.Version.ID); err != nil {
		t.Fatal(err)
	}
	if err := promoted.Commit(fixture.ctx); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if len(fixture.controller.applies) != 2 {
		t.Fatalf("all generation applies = %d", len(fixture.controller.applies))
	}
	for _, item := range fixture.controller.applies[1].Bundle.Paths {
		if item.QualificationOnly {
			t.Fatalf("final bundle retained qualification-only path: %+v", item)
		}
	}
	if len(fixture.selector.selections) != 1 {
		t.Fatalf("qualified node selections = %+v", fixture.selector.selections)
	}
	modemA, err := fixture.paths.Get(fixture.ctx, "modem-a", "sub-a")
	if err != nil || modemA.State != pathmatrix.StateQualified || modemA.QualifiedNodes != 1 || modemA.SelectedNodeID == "" {
		t.Fatalf("modem-a path = %+v, %v", modemA, err)
	}
	modemB, err := fixture.paths.Get(fixture.ctx, "modem-b", "sub-a")
	if err != nil || modemB.State != pathmatrix.StateFailed || modemB.QualifiedNodes != 0 || modemB.SelectedNodeID != "" {
		t.Fatalf("modem-b path = %+v, %v", modemB, err)
	}
	assertEvidenceCount(t, fixture.database, fixture.candidate.Version.Version.ID, 2)
}

func TestPromotionCommitFailureCanRestoreRuntimeAndInvalidatePartialEvidence(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": true})
	defer fixture.database.Close()
	promoted, err := fixture.candidateRuntime.Promote(fixture.ctx, fixture.candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.versions.Activate(fixture.ctx, fixture.candidate.Version.Version.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.paths.BumpRouteGeneration(fixture.ctx, "modem-b"); err != nil {
		t.Fatal(err)
	}
	if err := promoted.Commit(fixture.ctx); !errors.Is(err, store.ErrStaleGeneration) {
		t.Fatalf("Commit(stale second modem) error = %v", err)
	}
	assertEvidenceCount(t, fixture.database, fixture.candidate.Version.Version.ID, 1)
	if err := promoted.Rollback(fixture.ctx); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if len(fixture.controller.restores) != 1 || fixture.controller.restores[0] != "base-generation" || fixture.controller.current != "base-generation" {
		t.Fatalf("runtime restores/current = %v/%s", fixture.controller.restores, fixture.controller.current)
	}
	if err := fixture.versions.AbortActivation(fixture.ctx, fixture.candidate.Version.Version.ID, errors.New("test compensation")); err != nil {
		t.Fatal(err)
	}
	active, err := fixture.versions.Active(fixture.ctx, "sub-a")
	if err != nil || active.ID != fixture.oldVersionID {
		t.Fatalf("active subscription after compensation = %+v, %v", active, err)
	}
	assertEvidenceCount(t, fixture.database, fixture.candidate.Version.Version.ID, 0)
	modemA, err := fixture.paths.Get(fixture.ctx, "modem-a", "sub-a")
	if err != nil || modemA.State != pathmatrix.StateStale || modemA.SelectedNodeID != "" {
		t.Fatalf("partially persisted path after invalidation = %+v, %v", modemA, err)
	}
}

func TestPromotionRejectsCandidateWhenNoReadyModemPathQualifies(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{})
	defer fixture.database.Close()
	promoted, err := fixture.candidateRuntime.Promote(fixture.ctx, fixture.candidate)
	if err == nil || promoted != nil {
		t.Fatalf("Promote(unqualified) = %v, %v", promoted, err)
	}
	if len(fixture.controller.applies) != 1 || len(fixture.controller.restores) != 1 || fixture.controller.restores[0] != "base-generation" {
		t.Fatalf("unqualified apply/restore = %d/%v", len(fixture.controller.applies), fixture.controller.restores)
	}
	assertEvidenceCount(t, fixture.database, fixture.candidate.Version.Version.ID, 0)
}

func TestRequalifyModemRefreshesOnlyRequestedActiveLKGCells(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": false})
	defer fixture.database.Close()
	result, err := fixture.candidateRuntime.RequalifyModem(fixture.ctx, "modem-a")
	if err != nil || result.SubscriptionsChecked != 1 || result.Qualified != 1 || result.Failed != 0 {
		t.Fatalf("RequalifyModem(A) = %+v, %v", result, err)
	}
	modemA, err := fixture.paths.Get(fixture.ctx, "modem-a", "sub-a")
	if err != nil || modemA.State != pathmatrix.StateQualified || modemA.SelectedNodeID == "" {
		t.Fatalf("requalified modem A = %+v, %v", modemA, err)
	}
	var selectedVersion string
	if err := fixture.database.QueryRowContext(fixture.ctx, "SELECT version_id FROM nodes WHERE id=?", modemA.SelectedNodeID).Scan(&selectedVersion); err != nil || selectedVersion != fixture.oldVersionID {
		t.Fatalf("requalified node version = %s, %v", selectedVersion, err)
	}
	modemB, err := fixture.paths.Get(fixture.ctx, "modem-b", "sub-a")
	if err != nil || modemB.State == pathmatrix.StateFailed || modemB.SelectedNodeID != "" {
		t.Fatalf("non-requested modem B changed = %+v, %v", modemB, err)
	}
	if len(fixture.controller.applies) != 1 || len(fixture.controller.applies[0].Bundle.Paths) != 2 {
		t.Fatalf("requalification bundle must retain all ready modems: %+v", fixture.controller.applies)
	}
	var targetState string
	if err := fixture.database.QueryRowContext(fixture.ctx, "SELECT state FROM bypass_probe_targets WHERE id='target-a'").Scan(&targetState); err != nil || targetState != health.TargetNormal {
		t.Fatalf("target state after fresh evidence = %s, %v", targetState, err)
	}

	result, err = fixture.candidateRuntime.RequalifyModem(fixture.ctx, "modem-b")
	if err != nil || result.SubscriptionsChecked != 1 || result.Qualified != 0 || result.Failed != 1 {
		t.Fatalf("RequalifyModem(B) = %+v, %v", result, err)
	}
	modemB, _ = fixture.paths.Get(fixture.ctx, "modem-b", "sub-a")
	if modemB.State != pathmatrix.StateFailed || modemB.SelectedNodeID != "" {
		t.Fatalf("failed modem B requalification = %+v", modemB)
	}
}

func TestExactNodeProbeIsDiagnosticAndQualificationPublishesFreshEvidence(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": true})
	defer fixture.database.Close()
	if err := fixture.paths.ReconcileCells(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	cell, err := fixture.paths.Get(fixture.ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := fixture.versions.ListNodes(fixture.ctx, fixture.oldVersionID, true)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("active nodes = %+v, %v", nodes, err)
	}
	nodeID := nodes[0].ID
	probe, err := fixture.candidateRuntime.ProbeNode(fixture.ctx, cell.ID, nodeID)
	if err != nil || probe.Authoritative || probe.Result.State != health.CellQualified || len(fixture.controller.restores) != 1 || fixture.controller.current != "base-generation" {
		t.Fatalf("ProbeNode() = %+v restores=%v current=%s err=%v", probe, fixture.controller.restores, fixture.controller.current, err)
	}
	var evidence int
	if err := fixture.database.QueryRowContext(fixture.ctx, "SELECT COUNT(*) FROM path_nodes WHERE path_id=?", cell.ID).Scan(&evidence); err != nil || evidence != 0 {
		t.Fatalf("diagnostic evidence count = %d, %v", evidence, err)
	}
	qualified, err := fixture.candidateRuntime.QualifyNode(fixture.ctx, cell.ID, nodeID)
	if err != nil || !qualified.Authoritative || qualified.Result.State != health.CellQualified || len(fixture.controller.restores) != 1 {
		t.Fatalf("QualifyNode() = %+v restores=%v err=%v", qualified, fixture.controller.restores, err)
	}
	stored, err := fixture.paths.GetByID(fixture.ctx, cell.ID)
	if err != nil || stored.State != pathmatrix.StateQualified || stored.SelectedNodeID != nodeID || stored.RequiredTargetsPassed != 1 {
		t.Fatalf("stored exact qualification = %+v, %v", stored, err)
	}
	if _, err := fixture.candidateRuntime.ProbeNode(fixture.ctx, cell.ID, "missing-node"); !errors.Is(err, ErrNodeNotEligible) {
		t.Fatalf("ProbeNode(missing) error = %v", err)
	}
}

func TestPolicyGracePreservesExcludedActiveNodeInBundleButNotCandidatePool(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": true})
	defer fixture.database.Close()
	if _, err := fixture.candidateRuntime.RequalifyModem(fixture.ctx, "modem-a"); err != nil {
		t.Fatal(err)
	}
	cell, err := fixture.paths.Get(fixture.ctx, "modem-a", "sub-a")
	if err != nil || cell.SelectedNodeID == "" {
		t.Fatalf("initial qualified cell = %+v, %v", cell, err)
	}
	states := fixture.candidateRuntime.State
	if _, _, err := states.BeginActivation(fixture.ctx, cell.ID, cell.PolicyGeneration, cell.RouteGeneration); err != nil {
		t.Fatal(err)
	}
	if _, _, err := states.FinishActivation(fixture.ctx, cell.ID, cell.PolicyGeneration, cell.RouteGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, "UPDATE nodes SET enabled=0, candidate_source='MANUAL_EXCLUDE' WHERE id=?", cell.SelectedNodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.paths.BumpPolicyGeneration(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	transition, _ := states.Get(fixture.ctx)
	if !transition.PolicyTransitionActive() || transition.ActiveNodeID != cell.SelectedNodeID {
		t.Fatalf("policy transition = %+v", transition)
	}
	result, err := fixture.candidateRuntime.RequalifyModem(fixture.ctx, "modem-a")
	if err != nil || result.Qualified != 0 || result.Failed != 1 {
		t.Fatalf("excluded active-node requalification = %+v, %v", result, err)
	}
	failed, _ := fixture.paths.Get(fixture.ctx, "modem-a", "sub-a")
	if failed.State != pathmatrix.StateFailed || failed.CandidateNodes != 0 || failed.SelectedNodeID != "" {
		t.Fatalf("new policy candidate cell = %+v", failed)
	}
	lastBundle := fixture.controller.applies[len(fixture.controller.applies)-1].Bundle
	foundGraceNode := false
	for _, payload := range lastBundle.Providers {
		if strings.Contains(string(payload), "LTE-old") {
			foundGraceNode = true
		}
	}
	if !foundGraceNode {
		t.Fatalf("excluded active node disappeared from grace bundle: %+v", lastBundle.Paths)
	}
	stillTransitioning, _ := states.Get(fixture.ctx)
	if !stillTransitioning.PolicyTransitionActive() {
		t.Fatalf("failed active node ended grace prematurely: %+v", stillTransitioning)
	}
}

func newRuntimeFixture(t *testing.T, passing map[string]bool) runtimeFixture {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: filepath.Join(t.TempDir(), "state.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	subscriptions := subscription.NewRepository(database)
	versions := subscription.NewVersionRepository(database)
	modems := modem.NewRepository(database, 1101, 0x1101)
	targets := bypass.NewRepository(database)
	paths := pathmatrix.NewRepository(database)
	for index, id := range []string{"modem-a", "modem-b"} {
		digest := sha256.Sum256([]byte(id))
		if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: id, Name: id, IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
			database.Close()
			t.Fatal(err)
		}
		if _, err := modems.ApplyLease(ctx, id, modem.LeaseInput{InterfaceName: "enx" + string(rune('a'+index)), ManagementCIDR: "192.168." + string(rune('8'+index)) + ".0/24", Gateway: "192.168." + string(rune('8'+index)) + ".1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
			database.Close()
			t.Fatal(err)
		}
	}
	created, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "Subscription A", SourceType: "url", SourceSecretRef: "/run/secrets/sub-a", RefreshInterval: time.Hour})
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := targets.Create(ctx, bypass.CreateInput{ID: "target-a", Name: "Required", Kind: bypass.KindDomain, Value: "example.com", Required: true, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessAnyHTTPResponse}); err != nil {
		database.Close()
		t.Fatal(err)
	}
	payloadRoot := filepath.Join(t.TempDir(), "payloads")
	oldPayload := []byte("vless://11111111-1111-1111-1111-111111111111@old.example.com:443#LTE-old")
	oldVersion, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-old", SubscriptionID: created.ID, Payload: oldPayload})
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := subscription.WriteNormalizedPayload(payloadRoot, created.ID, oldVersion.Version.ID, oldVersion.Import); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := versions.Activate(ctx, oldVersion.Version.ID); err != nil {
		database.Close()
		t.Fatal(err)
	}
	candidatePayload := []byte("vless://22222222-2222-2222-2222-222222222222@new.example.com:443#LTE-new")
	staged, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-candidate", SubscriptionID: created.ID, Payload: candidatePayload})
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	payloadPath, err := subscription.WriteNormalizedPayload(payloadRoot, created.ID, staged.Version.ID, staged.Import)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	created, err = subscriptions.Get(ctx, created.ID)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	controller := &fakeController{current: "base-generation"}
	selector := &fakeSelector{}
	runtime := &Runtime{
		Subscriptions:  subscriptions,
		Versions:       versions,
		Modems:         modems,
		Targets:        targets,
		Paths:          paths,
		Preferences:    accesspolicy.NewPreferenceRepository(database),
		State:          state.NewRepository(database),
		TargetStates:   &health.TargetOutageEvaluator{Database: database, Config: health.DefaultTargetOutageConfig()},
		Controller:     controller,
		Selector:       selector,
		Routing:        &fakeRoutingSynchronizer{},
		EndpointAccess: &fakeEndpointAuthorizer{},
		Prober:         modemScopedProber{passing: passing},
		Qualifier:      health.Qualifier{MaxConcurrency: 2},
		PayloadRoot:    payloadRoot,
		BaseInput: mihomo.Input{
			ExternalController: "127.0.0.1:9090",
			ProbeListener:      "127.0.0.1:17890",
			APISecret:          "test-secret",
			TUNName:            "gateway-vpn-tun",
			TUNStack:           "mixed",
			LANInterface:       "enp2s0",
			ProviderDirectory:  "providers",
			BootstrapDNS:       []string{"1.1.1.1"},
		},
		EvidenceTTL: time.Minute,
		Now:         time.Now,
	}
	return runtimeFixture{
		ctx:              ctx,
		database:         database,
		payloadRoot:      payloadRoot,
		subscriptions:    subscriptions,
		versions:         versions,
		modems:           modems,
		targets:          targets,
		paths:            paths,
		controller:       controller,
		selector:         selector,
		oldVersionID:     oldVersion.Version.ID,
		candidate:        subscription.Candidate{Subscription: created, Version: staged, PayloadPath: payloadPath},
		candidateRuntime: runtime,
	}
}

func assertEvidenceCount(t *testing.T, database *sql.DB, versionID string, expected int) {
	t.Helper()
	var count int
	if err := database.QueryRow(`
SELECT COUNT(*)
FROM path_nodes AS pn
JOIN nodes AS n ON n.id=pn.node_id
WHERE n.version_id=?`, versionID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("evidence rows for %s = %d, want %d", versionID, count, expected)
	}
}
