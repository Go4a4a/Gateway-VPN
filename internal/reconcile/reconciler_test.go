package reconcile

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gateway-vpn/internal/accesspolicy"
	"gateway-vpn/internal/bypass"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/store"
	"gateway-vpn/internal/subscription"
)

type staticObserver struct {
	observed Observed
	err      error
}

func (observer staticObserver) Observe(context.Context) (Observed, error) {
	return observer.observed, observer.err
}

type fakeActuator struct {
	blocks      []string
	activations []Candidate
}

func (actuator *fakeActuator) Block(_ context.Context, reason string) error {
	actuator.blocks = append(actuator.blocks, reason)
	return nil
}

func (actuator *fakeActuator) Activate(_ context.Context, candidate Candidate) error {
	actuator.activations = append(actuator.activations, candidate)
	return nil
}

func TestReconcilerActivatesBestFreshPathAndBecomesIdempotent(t *testing.T) {
	ctx, database, candidate := reconcileFixture(t, true)
	actuator := &fakeActuator{}
	observer := &staticObserver{observed: Observed{FirewallReady: true, MihomoReady: true, TUNReady: true}}
	reconciler := &Reconciler{Observer: observer, Inventory: SQLiteInventory{Database: database}, State: state.NewRepository(database), Actuator: actuator}
	result, err := reconciler.Reconcile(ctx)
	if err != nil || result.Action != "PATH_ACTIVATED" || len(actuator.activations) != 1 || actuator.activations[0].PathID != candidate.PathID {
		t.Fatalf("Reconcile() = %+v, activations=%+v, error=%v", result, actuator.activations, err)
	}
	observer.observed.ActivePathID = candidate.PathID
	observer.observed.ActiveNodeID = candidate.NodeID
	result, err = reconciler.Reconcile(ctx)
	if err != nil || result.Action != "NO_CHANGE" || len(actuator.activations) != 1 {
		t.Fatalf("Reconcile(idempotent) = %+v, activations=%+v, error=%v", result, actuator.activations, err)
	}
}

func TestReconcilerKeepsExactTargetDegradedTupleAndRecoversWithoutReactivation(t *testing.T) {
	ctx, database, candidate := reconcileFixture(t, true)
	actuator := &fakeActuator{}
	observer := &staticObserver{observed: Observed{FirewallReady: true, MihomoReady: true, TUNReady: true}}
	states := state.NewRepository(database)
	matrix := pathmatrix.NewRepository(database)
	reconciler := &Reconciler{Observer: observer, Inventory: SQLiteInventory{Database: database}, State: states, Actuator: actuator}
	if _, err := reconciler.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	observer.observed.ActivePathID, observer.observed.ActiveNodeID = candidate.PathID, candidate.NodeID
	cell, err := matrix.GetByID(ctx, candidate.PathID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	failedEvidence := pathmatrix.NodeQualificationSnapshot{
		PathID: candidate.PathID, ExpectedPolicyGeneration: cell.PolicyGeneration,
		ExpectedRouteGeneration: cell.RouteGeneration, CandidateNodes: 1,
		RequiredTargetsTotal: 1, CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Node: pathmatrix.NodeEvidence{
			NodeID: candidate.NodeID, State: pathmatrix.NodeBypassFailed,
			ErrorCode: "TARGET_UNREACHABLE",
			Targets:   []pathmatrix.TargetEvidence{{TargetID: "target-a", State: health.ProbeFailed, ErrorCode: "TARGET_UNREACHABLE"}},
		},
	}
	if _, err := matrix.StoreNodeQualification(ctx, failedEvidence); err != nil {
		t.Fatal(err)
	}
	if _, err := matrix.MarkTargetDegraded(ctx, candidate.PathID, candidate.NodeID, cell.PolicyGeneration, cell.RouteGeneration, now); err == nil {
		t.Fatal("ordinary target failure was outage-suppressed before independent target classification")
	}
	if _, err := database.ExecContext(ctx, "UPDATE bypass_probe_targets SET state='TARGET_SUSPECT' WHERE id='target-a'"); err != nil {
		t.Fatal(err)
	}
	if _, err := matrix.MarkTargetDegraded(ctx, candidate.PathID, candidate.NodeID, cell.PolicyGeneration, cell.RouteGeneration, now); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := states.MarkTargetDegraded(ctx, candidate.PathID, candidate.NodeID, cell.PolicyGeneration, cell.RouteGeneration); err != nil || !changed {
		t.Fatalf("MarkTargetDegraded() changed=%v err=%v", changed, err)
	}
	result, err := reconciler.Reconcile(ctx)
	if err != nil || result.Action != "NO_CHANGE_DEGRADED_TARGET" || result.Candidate.NodeID != candidate.NodeID || len(actuator.activations) != 1 || len(actuator.blocks) != 0 {
		t.Fatalf("Reconcile(degraded) = %+v activations=%+v blocks=%+v err=%v", result, actuator.activations, actuator.blocks, err)
	}

	if _, err := matrix.StoreNodeQualification(ctx, pathmatrix.NodeQualificationSnapshot{
		PathID: candidate.PathID, ExpectedPolicyGeneration: cell.PolicyGeneration,
		ExpectedRouteGeneration: cell.RouteGeneration, CandidateNodes: 1,
		RequiredTargetsTotal: 1, CheckedAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour),
		Node: pathmatrix.NodeEvidence{
			NodeID: candidate.NodeID, State: pathmatrix.NodeBypassQualified, LatencyMS: 6,
			Targets: []pathmatrix.TargetEvidence{{TargetID: "target-a", State: health.ProbePassed, LatencyMS: 6, HTTPStatus: 204}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	result, err = reconciler.Reconcile(ctx)
	if err != nil || result.Action != "TARGET_DEGRADED_RECOVERED" || len(actuator.activations) != 1 || len(actuator.blocks) != 0 {
		t.Fatalf("Reconcile(recovered) = %+v activations=%+v blocks=%+v err=%v", result, actuator.activations, actuator.blocks, err)
	}
	snapshot, err := states.Get(ctx)
	if err != nil || snapshot.GatewayState != state.GatewayActive || snapshot.PathState != state.PathActive || snapshot.ActivePathID != candidate.PathID || snapshot.ActiveNodeID != candidate.NodeID {
		t.Fatalf("recovered runtime = %+v, %v", snapshot, err)
	}
}

func TestReconcilerBlocksWhenRequiredTargetMissing(t *testing.T) {
	ctx, database, _ := reconcileFixture(t, false)
	actuator := &fakeActuator{}
	reconciler := &Reconciler{Observer: staticObserver{observed: Observed{FirewallReady: true, MihomoReady: true, TUNReady: true}}, Inventory: SQLiteInventory{Database: database}, State: state.NewRepository(database), Actuator: actuator}
	result, err := reconciler.Reconcile(ctx)
	if err != nil || result.Action != "PATH_BLOCKED" || len(actuator.blocks) != 1 || actuator.blocks[0] != "NO_BYPASS_TARGETS" {
		t.Fatalf("Reconcile(no target) = %+v, blocks=%v, error=%v", result, actuator.blocks, err)
	}
	snapshot, _ := state.NewRepository(database).Get(ctx)
	if snapshot.GatewayState != state.GatewayNoBypassTargets || snapshot.PathState != state.PathBlocked {
		t.Fatalf("blocked snapshot = %+v", snapshot)
	}
}

func TestPolicyGraceKeepsActiveTupleThenCommitsFreshSameNodeWithoutReactivation(t *testing.T) {
	ctx, database, candidate := reconcileFixture(t, true)
	actuator := &fakeActuator{}
	observer := &staticObserver{observed: Observed{FirewallReady: true, MihomoReady: true, TUNReady: true}}
	reconciler := &Reconciler{Observer: observer, Inventory: SQLiteInventory{Database: database}, State: state.NewRepository(database), Actuator: actuator}
	if result, err := reconciler.Reconcile(ctx); err != nil || result.Action != "PATH_ACTIVATED" {
		t.Fatalf("initial activation = %+v, %v", result, err)
	}
	observer.observed.ActivePathID, observer.observed.ActiveNodeID = candidate.PathID, candidate.NodeID
	matrix := pathmatrix.NewRepository(database)
	generation, err := matrix.BumpPolicyGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := reconciler.Reconcile(ctx)
	if err != nil || result.Action != "POLICY_VERIFICATION_PENDING" || len(actuator.activations) != 1 || len(actuator.blocks) != 0 {
		t.Fatalf("pending policy transition = %+v activations=%d blocks=%v err=%v", result, len(actuator.activations), actuator.blocks, err)
	}
	cell, err := matrix.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := matrix.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: generation, ExpectedRouteGeneration: cell.RouteGeneration,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 9,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []pathmatrix.NodeEvidence{{NodeID: "node-a", State: pathmatrix.NodeBypassQualified, LatencyMS: 9}},
	}); err != nil {
		t.Fatal(err)
	}
	result, err = reconciler.Reconcile(ctx)
	if err != nil || result.Action != "POLICY_VERIFIED" || len(actuator.activations) != 1 || len(actuator.blocks) != 0 {
		t.Fatalf("verified policy transition = %+v activations=%d blocks=%v err=%v", result, len(actuator.activations), actuator.blocks, err)
	}
	snapshot, _ := state.NewRepository(database).Get(ctx)
	if snapshot.GatewayState != state.GatewayActive || snapshot.PathState != state.PathActive || snapshot.PolicyTransitionActive() || snapshot.ActiveNodeID != "node-a" {
		t.Fatalf("verified runtime snapshot = %+v", snapshot)
	}
}

func TestRemovingLastRequiredTargetUsesGraceThenBlocks(t *testing.T) {
	ctx, database, candidate := reconcileFixture(t, true)
	actuator := &fakeActuator{}
	observer := &staticObserver{observed: Observed{FirewallReady: true, MihomoReady: true, TUNReady: true}}
	reconciler := &Reconciler{Observer: observer, Inventory: SQLiteInventory{Database: database}, State: state.NewRepository(database), Actuator: actuator}
	if _, err := reconciler.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	observer.observed.ActivePathID, observer.observed.ActiveNodeID = candidate.PathID, candidate.NodeID
	if err := bypass.NewRepository(database).Delete(ctx, "target-a", true); err != nil {
		t.Fatal(err)
	}
	transition, _ := state.NewRepository(database).Get(ctx)
	result, err := reconciler.Reconcile(ctx)
	if err != nil || result.Action != "POLICY_VERIFICATION_PENDING" || len(actuator.blocks) != 0 {
		t.Fatalf("no-target policy grace = %+v blocks=%v err=%v", result, actuator.blocks, err)
	}
	deadline, err := time.Parse(time.RFC3339Nano, transition.PolicyTransitionDeadline)
	if err != nil {
		t.Fatal(err)
	}
	reconciler.Now = func() time.Time { return deadline.Add(time.Nanosecond) }
	result, err = reconciler.Reconcile(ctx)
	if err != nil || result.Action != "PATH_BLOCKED" || len(actuator.blocks) != 1 || actuator.blocks[0] != "NO_BYPASS_TARGETS_AFTER_POLICY_GRACE" {
		t.Fatalf("expired no-target policy grace = %+v blocks=%v err=%v", result, actuator.blocks, err)
	}
	snapshot, _ := state.NewRepository(database).Get(ctx)
	if snapshot.GatewayState != state.GatewayNoBypassTargets || snapshot.PathState != state.PathBlocked || snapshot.ActivePathID != "" {
		t.Fatalf("expired no-target state = %+v", snapshot)
	}
}

func TestPolicyGraceSwitchesToQualifiedReplacementWhenActiveNodeFailsNewPolicy(t *testing.T) {
	ctx, database, candidate := reconcileFixture(t, true)
	actuator := &fakeActuator{}
	observer := &staticObserver{observed: Observed{FirewallReady: true, MihomoReady: true, TUNReady: true}}
	reconciler := &Reconciler{Observer: observer, Inventory: SQLiteInventory{Database: database}, State: state.NewRepository(database), Actuator: actuator}
	if _, err := reconciler.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	observer.observed.ActivePathID, observer.observed.ActiveNodeID = candidate.PathID, candidate.NodeID
	if _, err := database.ExecContext(ctx, `
INSERT INTO nodes(id, version_id, external_name, normalized_name, fingerprint, proxy_type)
VALUES ('node-b', 'version-a', 'B', 'b', 'fingerprint-b', 'vless')`); err != nil {
		t.Fatal(err)
	}
	matrix := pathmatrix.NewRepository(database)
	generation, err := matrix.BumpPolicyGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cell, _ := matrix.Get(ctx, "modem-a", "sub-a")
	now := time.Now().UTC()
	if err := matrix.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: generation, ExpectedRouteGeneration: cell.RouteGeneration,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: "node-b",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 8,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []pathmatrix.NodeEvidence{
			{NodeID: "node-a", State: pathmatrix.NodeBypassFailed, LatencyMS: 20, ErrorCode: "NEW_POLICY_FAILED"},
			{NodeID: "node-b", State: pathmatrix.NodeBypassQualified, LatencyMS: 8},
		},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := reconciler.Reconcile(ctx)
	if err != nil || result.Action != "PATH_ACTIVATED" || result.Candidate.NodeID != "node-b" || len(actuator.activations) != 2 {
		t.Fatalf("policy replacement activation = %+v activations=%+v err=%v", result, actuator.activations, err)
	}
	snapshot, _ := state.NewRepository(database).Get(ctx)
	if snapshot.ActiveNodeID != "node-b" || snapshot.PathState != state.PathActive || snapshot.PolicyTransitionActive() {
		t.Fatalf("replacement runtime state = %+v", snapshot)
	}
}

func TestManualActivationUsesExactFreshNodeAndRemainsStableDuringReconcile(t *testing.T) {
	ctx, database, candidate := reconcileFixture(t, true)
	if _, err := database.ExecContext(ctx, `
INSERT INTO nodes(id, version_id, external_name, normalized_name, fingerprint, proxy_type)
VALUES ('node-b', 'version-a', 'B', 'b', 'fingerprint-b', 'vless')`); err != nil {
		t.Fatal(err)
	}
	matrix := pathmatrix.NewRepository(database)
	cell, err := matrix.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := matrix.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: cell.PolicyGeneration, ExpectedRouteGeneration: cell.RouteGeneration,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 5,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []pathmatrix.NodeEvidence{
			{NodeID: "node-a", State: pathmatrix.NodeBypassQualified, LatencyMS: 5},
			{NodeID: "node-b", State: pathmatrix.NodeBypassQualified, LatencyMS: 20},
		},
	}); err != nil {
		t.Fatal(err)
	}
	actuator := &fakeActuator{}
	observer := &staticObserver{observed: Observed{FirewallReady: true, MihomoReady: true, TUNReady: true}}
	reconciler := &Reconciler{Observer: observer, Inventory: SQLiteInventory{Database: database}, State: state.NewRepository(database), Actuator: actuator}
	result, err := reconciler.ActivateExact(ctx, candidate.PathID, "node-b")
	if err != nil || result.Action != "PATH_ACTIVATED" || len(actuator.activations) != 1 || actuator.activations[0].NodeID != "node-b" {
		t.Fatalf("ActivateExact() = %+v activations=%+v err=%v", result, actuator.activations, err)
	}
	snapshot, _ := state.NewRepository(database).Get(ctx)
	if snapshot.ActiveNodeID != "node-b" || snapshot.ActivePathID != candidate.PathID {
		t.Fatalf("manual active snapshot = %+v", snapshot)
	}
	observer.observed.ActivePathID, observer.observed.ActiveNodeID = candidate.PathID, "node-b"
	result, err = reconciler.Reconcile(ctx)
	if err != nil || result.Action != "NO_CHANGE" || result.Candidate.NodeID != "node-b" || len(actuator.activations) != 1 {
		t.Fatalf("Reconcile(manual exact stable) = %+v activations=%+v err=%v", result, actuator.activations, err)
	}
	if _, err := reconciler.ActivateExact(ctx, candidate.PathID, "missing"); !errors.Is(err, store.ErrNotFound) || len(actuator.activations) != 1 {
		t.Fatalf("ActivateExact(stale) error=%v activations=%+v", err, actuator.activations)
	}
}

func TestUnifiedReconcilerUsesDirectWithoutMihomoThenFailsOverWithHold(t *testing.T) {
	ctx, database, vpn := reconcileFixture(t, true)
	paths := accesspolicy.NewDirectPathRepository(database)
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	directPaths, err := paths.List(ctx)
	if err != nil || len(directPaths) != 1 {
		t.Fatalf("direct paths = %+v, %v", directPaths, err)
	}
	now := time.Now().UTC()
	direct := directPaths[0]
	if err := paths.Publish(ctx, accesspolicy.DirectResultUpdate{
		PathID: direct.ID, ExpectedPolicyGeneration: direct.PolicyGeneration, ExpectedRouteGeneration: direct.RouteGeneration,
		TransportState: "PASSED", QualityClass: accesspolicy.QualityFull, FunctionalScore: 1000,
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 9,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Targets: []accesspolicy.DirectTargetResult{{TargetID: "target-a", TargetClass: "GLOBAL_REQUIRED", State: "PASSED", LatencyMS: 9, HTTPStatus: 204, CheckedAt: now, ExpiresAt: now.Add(time.Hour)}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE access_policy
SET failure_hold_seconds=5, recovery_stable_seconds=5, switch_cooldown_seconds=0
WHERE singleton_id=1`); err != nil {
		t.Fatal(err)
	}
	actuator := &fakeActuator{}
	observer := &staticObserver{observed: Observed{FirewallReady: true, MihomoReady: false, TUNReady: false}}
	states := state.NewRepository(database)
	reconciler := &Reconciler{
		Observer: observer, Inventory: SQLiteInventory{Database: database}, State: states, Actuator: actuator,
		AccessPaths: paths, AccessPolicy: accesspolicy.NewRepository(database), Now: func() time.Time { return now },
	}
	result, err := reconciler.Reconcile(ctx)
	if err != nil || result.Action != "ACCESS_METHOD_ACTIVATED" || result.Candidate.MethodKind != accesspolicy.MethodDirect || len(actuator.activations) != 1 {
		t.Fatalf("direct without Mihomo = %+v activations=%+v err=%v", result, actuator.activations, err)
	}
	snapshot, err := states.Get(ctx)
	if err != nil || snapshot.ActiveDirectPathID != direct.ID || snapshot.ActiveMethodKind != accesspolicy.MethodDirect || snapshot.ActivePathID != "" {
		t.Fatalf("direct runtime = %+v, %v", snapshot, err)
	}
	observer.observed.MethodKind = accesspolicy.MethodDirect
	observer.observed.ActiveDirectPathID = direct.ID
	result, err = reconciler.Reconcile(ctx)
	if err != nil || result.Action != "NO_CHANGE" || len(actuator.activations) != 1 {
		t.Fatalf("stable direct = %+v activations=%+v err=%v", result, actuator.activations, err)
	}

	if _, err := database.ExecContext(ctx, "UPDATE direct_uplink_paths SET expires_at=? WHERE id=?", now.Add(-time.Second).Format(time.RFC3339Nano), direct.ID); err != nil {
		t.Fatal(err)
	}
	observer.observed.MihomoReady, observer.observed.TUNReady = true, true
	result, err = reconciler.Reconcile(ctx)
	if err != nil || result.Action != "FAILURE_HOLD_STARTED" || len(actuator.activations) != 1 {
		t.Fatalf("failure hold start = %+v activations=%+v err=%v", result, actuator.activations, err)
	}
	reconciler.Now = func() time.Time { return now.Add(6 * time.Second) }
	result, err = reconciler.Reconcile(ctx)
	if err != nil || result.Action != "ACCESS_METHOD_ACTIVATED" || result.Candidate.PathID != vpn.PathID || result.Candidate.MethodKind != accesspolicy.MethodSubscription || len(actuator.activations) != 2 {
		t.Fatalf("VPN failover = %+v activations=%+v err=%v", result, actuator.activations, err)
	}
	snapshot, _ = states.Get(ctx)
	if snapshot.ActivePathID != vpn.PathID || snapshot.ActiveDirectPathID != "" || snapshot.ActiveMethodKind != accesspolicy.MethodSubscription {
		t.Fatalf("VPN runtime after failover = %+v", snapshot)
	}

	if _, err := database.ExecContext(ctx, "UPDATE access_methods SET enabled=0"); err != nil {
		t.Fatal(err)
	}
	result, err = reconciler.Reconcile(ctx)
	if err != nil || result.Action != "PATH_BLOCKED" || len(actuator.blocks) == 0 || actuator.blocks[len(actuator.blocks)-1] != "NO_FRESH_ACCESS_METHOD" {
		t.Fatalf("no method block = %+v blocks=%+v err=%v", result, actuator.blocks, err)
	}
}

func TestUnifiedStartupRecoveryIsExactAndOneShot(t *testing.T) {
	ctx, database, _ := reconcileFixture(t, true)
	paths := accesspolicy.NewDirectPathRepository(database)
	if err := paths.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	actuator := &fakeActuator{}
	observer := &staticObserver{observed: Observed{FirewallReady: true, MihomoReady: true, TUNReady: true}}
	states := state.NewRepository(database)
	reconciler := &Reconciler{
		Observer: observer, Inventory: SQLiteInventory{Database: database}, State: states, Actuator: actuator,
		AccessPaths: paths, AccessPolicy: accesspolicy.NewRepository(database),
	}
	initial, err := reconciler.Reconcile(ctx)
	if err != nil || initial.Action != "ACCESS_METHOD_ACTIVATED" || len(actuator.activations) != 1 {
		t.Fatalf("initial activation = %+v activations=%+v err=%v", initial, actuator.activations, err)
	}
	active, err := states.Get(ctx)
	if err != nil || active.PathState != state.PathActive || active.ActivePathID == "" || active.ActiveNodeID == "" {
		t.Fatalf("initial active tuple = %+v, %v", active, err)
	}
	prepared, changed, err := states.PrepareStartupRecovery(ctx)
	if err != nil || !changed || prepared.PathState != state.PathVerifying || prepared.ActivePathID != active.ActivePathID || prepared.ActiveNodeID != active.ActiveNodeID {
		t.Fatalf("PrepareStartupRecovery() = %+v/%v/%v", prepared, changed, err)
	}
	reconciler.StartupRecovery = true
	restored, err := reconciler.Reconcile(ctx)
	if err != nil || restored.Action != "STARTUP_MINIMAL_PATH_RESTORED" || len(actuator.activations) != 2 {
		t.Fatalf("startup recovery = %+v activations=%+v err=%v", restored, actuator.activations, err)
	}
	last := actuator.activations[len(actuator.activations)-1]
	if !last.StartupRecovery || last.PathID != active.ActivePathID || last.NodeID != active.ActiveNodeID || reconciler.StartupRecovery {
		t.Fatalf("startup recovery candidate/permit = %+v permit=%v", last, reconciler.StartupRecovery)
	}
	final, err := states.Get(ctx)
	if err != nil || final.PathState != state.PathActive || final.ActivePathID != active.ActivePathID || final.ActiveNodeID != active.ActiveNodeID {
		t.Fatalf("restored active tuple = %+v, %v", final, err)
	}
}

func reconcileFixture(t *testing.T, withTarget bool) (context.Context, *sql.DB, Candidate) {
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
	digest := sha256.Sum256([]byte("modem-a"))
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{
		InterfaceName: "enxmodema", ManagementCIDR: "192.168.8.0/24",
		Gateway: "192.168.8.1", DNS: []string{"192.168.8.1"}, MTU: 1500,
		State: modem.StateReady,
	}); err != nil {
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
	if withTarget {
		if _, err := database.ExecContext(ctx, `
INSERT INTO bypass_probe_targets (
    id, name, target_kind, target_value, normalized_url, enabled, required,
    priority, timeout_seconds, success_mode, state, created_at, updated_at
) VALUES ('target-a', 'A', 'domain', 'example.com', 'https://example.com/', 1, 1, 10, 8, 'any_http_response', 'UNKNOWN', ?, ?)`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	matrix := pathmatrix.NewRepository(database)
	if err := matrix.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	cell, _ := matrix.Get(ctx, "modem-a", "sub-a")
	if err := matrix.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: cell.PolicyGeneration, ExpectedRouteGeneration: cell.RouteGeneration,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: "node-a",
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 10,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []pathmatrix.NodeEvidence{{NodeID: "node-a", State: pathmatrix.NodeBypassQualified, LatencyMS: 10}},
	}); err != nil {
		t.Fatal(err)
	}
	return ctx, database, Candidate{PathID: cell.ID, UplinkID: "modem-a", SubscriptionID: "sub-a", NodeID: "node-a", PolicyGeneration: cell.PolicyGeneration, RouteGeneration: cell.RouteGeneration}
}
