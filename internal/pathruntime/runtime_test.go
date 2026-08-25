package pathruntime

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"gateway-vpn/internal/bypass"
	"gateway-vpn/internal/dataplane"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/health"
	"gateway-vpn/internal/mihomo"
	"gateway-vpn/internal/modem"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/reconcile"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
)

type fakeBroker struct {
	state       dataplane.PathState
	events      []string
	activations []uint32
	failClosed  int
	err         error
	authorized  [][]string
}

func (broker *fakeBroker) AuthorizeMihomoVersions(_ context.Context, versionIDs []string) error {
	broker.events = append(broker.events, "mihomo:endpoints")
	broker.authorized = append(broker.authorized, append([]string(nil), versionIDs...))
	return broker.err
}

func (broker *fakeBroker) ActivatePath(_ context.Context, generation uint32) error {
	broker.events = append(broker.events, "firewall:activate")
	if broker.err == nil {
		broker.state = dataplane.PathState{Active: true, Generation: generation}
		broker.activations = append(broker.activations, generation)
	}
	return broker.err
}

func (broker *fakeBroker) BlockPath(context.Context) error {
	broker.events = append(broker.events, "firewall:block")
	if broker.err == nil {
		broker.state = dataplane.PathState{}
	}
	return broker.err
}

func (broker *fakeBroker) ObservePath(context.Context) (dataplane.PathState, error) {
	broker.events = append(broker.events, "firewall:observe")
	return broker.state, broker.err
}

func (broker *fakeBroker) FailClosedMihomo(context.Context) error {
	broker.events = append(broker.events, "mihomo:fail-closed")
	broker.failClosed++
	return nil
}

type fakeMihomo struct {
	version    string
	selected   map[string]string
	events     *[]string
	delayErr   error
	selectErr  error
	delayCalls int
}

func (control *fakeMihomo) GetVersion(context.Context) (mihomo.Version, error) {
	return mihomo.Version{Version: control.version}, nil
}

func (control *fakeMihomo) Select(_ context.Context, group, target string) error {
	*control.events = append(*control.events, "select:"+group+"="+target)
	if control.selectErr != nil {
		return control.selectErr
	}
	control.selected[group] = target
	return nil
}

func (control *fakeMihomo) Selected(_ context.Context, group string) (mihomo.ProxyState, error) {
	now := control.selected[group]
	if now == "" {
		return mihomo.ProxyState{}, errors.New("group has no selection")
	}
	return mihomo.ProxyState{Name: group, Type: "Selector", Now: now}, nil
}

func (control *fakeMihomo) ProxyDelay(_ context.Context, group, target string, _ time.Duration, _ string) (uint16, error) {
	*control.events = append(*control.events, "delay:"+group+"="+target)
	control.delayCalls++
	return 20, control.delayErr
}

type readyTUN struct{ ready bool }

type fakeBodyTargetProber struct {
	path      health.Path
	candidate health.Candidate
	target    health.Target
	result    health.ProbeResult
	calls     int
}

func (prober *fakeBodyTargetProber) ProbeTarget(_ context.Context, path health.Path, candidate health.Candidate, target health.Target) health.ProbeResult {
	prober.calls++
	prober.path, prober.candidate, prober.target = path, candidate, target
	return prober.result
}

func (tun readyTUN) RequireReady(context.Context, string) error {
	if tun.ready {
		return nil
	}
	return errors.New("TUN down")
}

type fixture struct {
	ctx        context.Context
	database   *sql.DB
	now        time.Time
	state      *state.Repository
	broker     *fakeBroker
	mihomo     *fakeMihomo
	reconciler *reconcile.Reconciler
	cell       pathmatrix.Cell
}

func TestReconcilerSelectsReverifiesAndOpensOnlyVerifiedTUNGate(t *testing.T) {
	fixture := newFixture(t)
	defer fixture.database.Close()
	result, err := fixture.reconciler.Reconcile(fixture.ctx)
	if err != nil || result.Action != "PATH_ACTIVATED" || result.Candidate.ConfigGeneration != 1 {
		t.Fatalf("Reconcile() = %+v, %v", result, err)
	}
	if fixture.broker.state != (dataplane.PathState{Active: true, Generation: 1}) || len(fixture.broker.activations) != 1 {
		t.Fatalf("firewall state/activations = %+v/%v", fixture.broker.state, fixture.broker.activations)
	}
	names, _ := mihomo.StablePathNames("modem-a", "sub-a")
	wantPrefix := []string{
		"firewall:observe",
		"firewall:block",
		"mihomo:endpoints",
		"select:" + names.GroupName + "=" + names.NodePrefix + "LTE node",
		"select:" + mihomo.ActiveGroupName + "=" + names.GroupName,
		"delay:" + mihomo.ActiveGroupName + "=https://example.com/",
		"firewall:activate",
	}
	if !reflect.DeepEqual(fixture.broker.events, wantPrefix) {
		t.Fatalf("activation event order = %v, want %v", fixture.broker.events, wantPrefix)
	}
	if fixture.mihomo.delayCalls != 1 {
		t.Fatalf("required target delay calls = %d", fixture.mihomo.delayCalls)
	}
	if len(fixture.broker.authorized) != 1 || !reflect.DeepEqual(fixture.broker.authorized[0], []string{"version-a"}) {
		t.Fatalf("active endpoint authorization = %v", fixture.broker.authorized)
	}
	snapshot, err := fixture.state.Get(fixture.ctx)
	if err != nil || snapshot.PathState != state.PathActive || snapshot.ConfigGeneration != 1 || snapshot.ActivePathID != fixture.cell.ID {
		t.Fatalf("active desired state = %+v, %v", snapshot, err)
	}
	result, err = fixture.reconciler.Reconcile(fixture.ctx)
	if err != nil || result.Action != "NO_CHANGE" {
		t.Fatalf("second Reconcile() = %+v, %v", result, err)
	}
}

func TestFailedEndToEndRecheckKeepsFirewallBlockedAndSelectsReject(t *testing.T) {
	fixture := newFixture(t)
	defer fixture.database.Close()
	fixture.mihomo.delayErr = errors.New("target failed")
	result, err := fixture.reconciler.Reconcile(fixture.ctx)
	if err == nil || result.Action != "PATH_BLOCKED" {
		t.Fatalf("Reconcile(failed target) = %+v, %v", result, err)
	}
	if fixture.broker.state.Active || len(fixture.broker.activations) != 0 || fixture.mihomo.selected[mihomo.ActiveGroupName] != "REJECT" {
		t.Fatalf("failed activation state = firewall %+v, activations %v, active group %q", fixture.broker.state, fixture.broker.activations, fixture.mihomo.selected[mihomo.ActiveGroupName])
	}
	snapshot, _ := fixture.state.Get(fixture.ctx)
	if snapshot.PathState != state.PathBlocked || snapshot.ActivePathID != "" {
		t.Fatalf("desired state after failed activation = %+v", snapshot)
	}
}

func TestActivationRechecksExpectedBodyThroughIsolatedProbePath(t *testing.T) {
	fixture := newFixture(t)
	defer fixture.database.Close()
	if _, err := fixture.database.ExecContext(fixture.ctx, `UPDATE bypass_probe_targets
SET success_mode=?, expected_status='200-299', expected_body_substring='access granted'
WHERE id='target-a'`, bypass.SuccessExpectedBody); err != nil {
		t.Fatal(err)
	}
	prober := &fakeBodyTargetProber{result: health.ProbeResult{State: health.ProbePassed, HTTPStatus: 200}}
	fixture.reconciler.Actuator.(*Actuator).BodyProber = prober
	result, err := fixture.reconciler.Reconcile(fixture.ctx)
	if err != nil || result.Action != "PATH_ACTIVATED" || prober.calls != 1 || fixture.mihomo.delayCalls != 0 || !fixture.broker.state.Active {
		t.Fatalf("body activation = %+v, %v, prober=%+v delay=%d firewall=%+v", result, err, prober, fixture.mihomo.delayCalls, fixture.broker.state)
	}
	names, _ := mihomo.StablePathNames("modem-a", "sub-a")
	if prober.path.ProbeGroupName != names.ProbeGroupName || prober.path.ProviderName != names.ProviderName || prober.candidate.ProviderNodeName != names.NodePrefix+"LTE node" || prober.target.ExpectedStatus != "200-299" || prober.target.ExpectedBodySubstring != "access granted" {
		t.Fatalf("body probe scope = path %+v candidate %+v target %+v", prober.path, prober.candidate, prober.target)
	}
}

func TestObserverRejectsFirewallGenerationThatDoesNotMatchSQLite(t *testing.T) {
	fixture := newFixture(t)
	defer fixture.database.Close()
	fixture.broker.state = dataplane.PathState{Active: true, Generation: 99}
	if _, err := (fixture.reconciler.Observer).(Observer).Observe(fixture.ctx); err == nil {
		t.Fatal("Observe(mismatched generation) error = nil")
	}
}

func newFixture(t *testing.T) fixture {
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
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte("modem-a"))
	modems := modem.NewRepository(database, 1101, 0x1101)
	if _, err := modems.Adopt(ctx, modem.AdoptInput{ID: "modem-a", Name: "A", IdentityKind: "usb_serial_hash", IdentityHash: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if _, err := modems.ApplyLease(ctx, "modem-a", modem.LeaseInput{InterfaceName: "enx1", ManagementCIDR: "192.168.8.0/24", Gateway: "192.168.8.1", DNS: []string{"1.1.1.1"}, MTU: 1500, State: modem.StateReady}); err != nil {
		t.Fatal(err)
	}
	subscriptions := subscription.NewRepository(database)
	if _, err := subscriptions.Create(ctx, subscription.CreateInput{ID: "sub-a", Name: "A", SourceType: "url", SourceSecretRef: "/secret/a", RefreshInterval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	versions := subscription.NewVersionRepository(database)
	staged, err := versions.Stage(ctx, subscription.StageInput{VersionID: "version-a", SubscriptionID: "sub-a", Payload: []byte("vless://11111111-1111-1111-1111-111111111111@proxy.example.com:443#LTE node")})
	if err != nil {
		t.Fatal(err)
	}
	if err := versions.Activate(ctx, staged.Version.ID); err != nil {
		t.Fatal(err)
	}
	targets := bypass.NewRepository(database)
	if _, err := targets.Create(ctx, bypass.CreateInput{ID: "target-a", Name: "A", Kind: bypass.KindDomain, Value: "example.com", Required: true, Timeout: 5 * time.Second, SuccessMode: bypass.SuccessAnyHTTPResponse}); err != nil {
		t.Fatal(err)
	}
	paths := pathmatrix.NewRepository(database)
	if err := paths.ReconcileCells(ctx); err != nil {
		t.Fatal(err)
	}
	cell, err := paths.Get(ctx, "modem-a", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	node := staged.Nodes[0]
	if err := paths.StoreQualification(ctx, pathmatrix.QualificationSnapshot{
		PathID: cell.ID, ExpectedPolicyGeneration: cell.PolicyGeneration, ExpectedRouteGeneration: cell.RouteGeneration,
		State: pathmatrix.StateQualified, TransportState: "PASSED", SelectedNodeID: node.ID,
		RequiredTargetsPassed: 1, RequiredTargetsTotal: 1, LatencyMS: 10,
		CheckedAt: now, ExpiresAt: now.Add(time.Hour),
		Nodes: []pathmatrix.NodeEvidence{{NodeID: node.ID, State: pathmatrix.NodeBypassQualified, LatencyMS: 10, Targets: []pathmatrix.TargetEvidence{{TargetID: "target-a", State: "PASSED", LatencyMS: 10}}}},
	}); err != nil {
		t.Fatal(err)
	}
	states := state.NewRepository(database)
	broker := &fakeBroker{}
	events := &broker.events
	control := &fakeMihomo{version: "v1.2.3", selected: map[string]string{}, events: events}
	actuator := &Actuator{Database: database, Targets: targets, Broker: broker, Mihomo: control, Now: func() time.Time { return now }}
	observer := Observer{Database: database, Broker: broker, Mihomo: control, TUN: readyTUN{ready: true}, State: states, TUNName: "gateway-vpn-tun", ExpectedVersion: "v1.2.3"}
	reconciler := &reconcile.Reconciler{Observer: observer, Inventory: reconcile.SQLiteInventory{Database: database, Now: func() time.Time { return now }}, State: states, Actuator: actuator}
	return fixture{ctx: ctx, database: database, now: now, state: states, broker: broker, mihomo: control, reconciler: reconciler, cell: cell}
}
