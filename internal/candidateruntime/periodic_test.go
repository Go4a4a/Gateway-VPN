package candidateruntime

import (
	"context"
	"testing"
	"time"

	"gateway-vpn/internal/health"
	"gateway-vpn/internal/pathmatrix"
	"gateway-vpn/internal/scheduler"
	"gateway-vpn/internal/state"
	"gateway-vpn/internal/subscription"
)

type fixedPeriodicProber struct {
	transport health.ProbeResult
	target    health.ProbeResult
}

func (prober fixedPeriodicProber) ProbeTransport(context.Context, health.Path, health.Candidate) health.ProbeResult {
	return prober.transport
}

func (prober fixedPeriodicProber) ProbeTarget(context.Context, health.Path, health.Candidate, health.Target) health.ProbeResult {
	return prober.target
}

func passingPeriodicProber() health.Prober {
	return fixedPeriodicProber{
		transport: health.ProbeResult{State: health.ProbePassed, LatencyMS: 3},
		target:    health.ProbeResult{State: health.ProbePassed, LatencyMS: 7, HTTPStatus: 204},
	}
}

func TestPeriodicRunnerPublishesOnlyAfterSuccessThreshold(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": true})
	defer fixture.database.Close()
	clock := time.Now().UTC().Add(time.Minute)
	active := activatePeriodicFixture(t, fixture, &clock)
	fixture.candidateRuntime.ProberForClass = func(string) health.Prober { return passingPeriodicProber() }
	reconciles := 0
	runner := newPeriodicTestRunner(fixture, &clock, func(context.Context) (any, error) {
		reconciles++
		return nil, nil
	})
	runner.Config.DueLimit = 1
	runner.Config.SuccessThreshold = 2
	runner.Config.FailureThreshold = 2

	first, err := runner.RunOnce(fixture.ctx)
	if err != nil || first.Probed != 1 || first.Published != 0 || reconciles != 0 {
		t.Fatalf("first success cycle = %+v, reconciles=%d, err=%v", first, reconciles, err)
	}
	before, err := fixture.paths.GetByID(fixture.ctx, active.ID)
	if err != nil || before.LastCheckedAt != active.LastCheckedAt {
		t.Fatalf("diagnostic cycle changed authoritative evidence: %+v, %v", before, err)
	}

	clock = clock.Add(time.Minute)
	second, err := runner.RunOnce(fixture.ctx)
	if err != nil || second.Probed != 1 || second.Published != 1 || reconciles != 1 {
		t.Fatalf("second success cycle = %+v, reconciles=%d, err=%v", second, reconciles, err)
	}
	after, err := fixture.paths.GetByID(fixture.ctx, active.ID)
	if err != nil || after.State != pathmatrix.StateQualified || after.SelectedNodeID != active.SelectedNodeID || after.LastCheckedAt == active.LastCheckedAt {
		t.Fatalf("published success evidence = %+v, %v", after, err)
	}
	status, err := runner.Schedules.Get(fixture.ctx, active.ID)
	if err != nil || status.Successes != 0 || status.Failures != 0 || status.LastResult != health.PeriodicPassed {
		t.Fatalf("acknowledged success status = %+v, %v", status, err)
	}
}

func TestPeriodicRunnerFailureStreakSurvivesRestartAndPublishesFailoverEvidence(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": true})
	defer fixture.database.Close()
	clock := time.Now().UTC().Add(time.Minute)
	active := activatePeriodicFixture(t, fixture, &clock)
	failing := fixedPeriodicProber{
		transport: health.ProbeResult{State: health.ProbeFailed, ErrorCode: "UPLINK_UNREACHABLE"},
		target:    health.ProbeResult{State: health.ProbeFailed, ErrorCode: "NOT_REACHED"},
	}
	fixture.candidateRuntime.ProberForClass = func(string) health.Prober { return failing }
	reconciles := 0
	callback := func(context.Context) (any, error) {
		reconciles++
		return nil, nil
	}
	runner := newPeriodicTestRunner(fixture, &clock, callback)
	runner.Config.DueLimit = 1
	runner.Config.SuccessThreshold = 2
	runner.Config.FailureThreshold = 2

	first, err := runner.RunOnce(fixture.ctx)
	if err != nil || first.Published != 0 {
		t.Fatalf("first failure cycle = %+v, %v", first, err)
	}
	stillQualified, _ := fixture.paths.GetByID(fixture.ctx, active.ID)
	if stillQualified.State != pathmatrix.StateQualified {
		t.Fatalf("diagnostic failure changed path before threshold: %+v", stillQualified)
	}
	status, _ := runner.Schedules.Get(fixture.ctx, active.ID)
	if status.Failures != 1 {
		t.Fatalf("first durable failure streak = %+v", status)
	}

	// Recreate both the repository value and runner to model a process restart.
	clock = clock.Add(time.Minute)
	restarted := newPeriodicTestRunner(fixture, &clock, callback)
	restarted.Config = runner.Config
	second, err := restarted.RunOnce(fixture.ctx)
	if err != nil || second.Published != 1 || reconciles != 1 {
		t.Fatalf("post-restart failure cycle = %+v, reconciles=%d, err=%v", second, reconciles, err)
	}
	failed, err := fixture.paths.GetByID(fixture.ctx, active.ID)
	if err != nil || failed.State != pathmatrix.StateFailed || failed.TransportState != health.ProbeFailed || failed.SelectedNodeID != "" {
		t.Fatalf("published transport failure = %+v, %v", failed, err)
	}
	status, _ = restarted.Schedules.Get(fixture.ctx, active.ID)
	if status.Failures != 0 || status.Successes != 0 || status.LastResult != health.PeriodicFailed {
		t.Fatalf("acknowledged failure status = %+v", status)
	}
}

func TestPeriodicRunnerStandbyBudgetDeferralPreservesEvidence(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": true})
	defer fixture.database.Close()
	clock := time.Now().UTC().Add(time.Minute)
	active := activatePeriodicFixture(t, fixture, &clock)
	standby, err := fixture.paths.Get(fixture.ctx, "modem-b", "sub-a")
	if err != nil || standby.State != pathmatrix.StateQualified {
		t.Fatalf("standby fixture = %+v, %v", standby, err)
	}
	fixture.candidateRuntime.ProberForClass = func(class string) health.Prober {
		if class == scheduler.ClassStandby {
			return fixedPeriodicProber{
				transport: health.ProbeResult{State: health.ProbeFailed, ErrorCode: scheduler.DecisionDeferredBudget},
				target:    health.ProbeResult{State: health.ProbeFailed, ErrorCode: scheduler.DecisionDeferredBudget},
			}
		}
		return passingPeriodicProber()
	}
	runner := newPeriodicTestRunner(fixture, &clock, nil)
	runner.Config.DueLimit = 4
	runner.Config.SuccessThreshold = 50
	runner.Config.FailureThreshold = 50
	cycle, err := runner.RunOnce(fixture.ctx)
	if err != nil || cycle.Due != 2 || cycle.Probed != 2 || cycle.Deferred != 1 || cycle.Published != 0 {
		t.Fatalf("budget-deferred cycle = %+v, %v", cycle, err)
	}
	after, err := fixture.paths.GetByID(fixture.ctx, standby.ID)
	if err != nil || after.State != standby.State || after.SelectedNodeID != standby.SelectedNodeID || after.LastCheckedAt != standby.LastCheckedAt {
		t.Fatalf("standby evidence after budget deferral = before=%+v after=%+v err=%v", standby, after, err)
	}
	status, err := runner.Schedules.Get(fixture.ctx, standby.ID)
	if err != nil || status.LastResult != health.PeriodicDeferred || status.DeferredReason != scheduler.DecisionDeferredBudget || status.Failures != 0 || status.Successes != 0 || status.LastProbeAt != "" {
		t.Fatalf("standby deferred schedule = %+v, %v", status, err)
	}
	activeStatus, _ := runner.Schedules.Get(fixture.ctx, active.ID)
	if activeStatus.Successes != 1 || activeStatus.LastResult != health.PeriodicPassed {
		t.Fatalf("active status in shared cycle = %+v", activeStatus)
	}
}

func TestPeriodicRunnerSuppressesFailoverForIndependentlyConfirmedTargetOutage(t *testing.T) {
	fixture := newRuntimeFixture(t, map[string]bool{"modem-a": true, "modem-b": true})
	defer fixture.database.Close()
	addPeriodicSubscription(t, fixture, "sub-b")
	clock := time.Now().UTC().Add(time.Minute)
	active := activatePeriodicFixture(t, fixture, &clock)
	targetFailure := fixedPeriodicProber{
		transport: health.ProbeResult{State: health.ProbePassed, LatencyMS: 2},
		target:    health.ProbeResult{State: health.ProbeFailed, ErrorCode: "TARGET_UNREACHABLE"},
	}
	fixture.candidateRuntime.ProberForClass = func(string) health.Prober { return targetFailure }
	reconciles := 0
	runner := newPeriodicTestRunner(fixture, &clock, func(context.Context) (any, error) {
		reconciles++
		return nil, nil
	})
	runner.Config.DueLimit = 1
	runner.Config.FailureThreshold = 1
	runner.Config.SuccessThreshold = 1
	runner.Config.ConfirmationLimit = 4
	cycle, err := runner.RunOnce(fixture.ctx)
	if err != nil || cycle.Published != 1 || cycle.OutageSuppressed != 1 || cycle.Probed != 4 || reconciles != 1 {
		t.Fatalf("target-outage cycle = %+v, reconciles=%d, err=%v", cycle, reconciles, err)
	}
	snapshot, err := fixture.candidateRuntime.State.Get(fixture.ctx)
	if err != nil || snapshot.GatewayState != state.GatewayDegradedTarget || snapshot.PathState != state.PathActive || snapshot.ActivePathID != active.ID || snapshot.ActiveNodeID != active.SelectedNodeID {
		t.Fatalf("target-degraded runtime = %+v, %v", snapshot, err)
	}
	degraded, err := fixture.paths.GetByID(fixture.ctx, active.ID)
	if err != nil || degraded.State != pathmatrix.StateDegraded || degraded.TransportState != health.ProbePassed || degraded.SelectedNodeID != active.SelectedNodeID {
		t.Fatalf("target-degraded active cell = %+v, %v", degraded, err)
	}
	var targetState string
	if err := fixture.database.QueryRowContext(fixture.ctx, "SELECT state FROM bypass_probe_targets WHERE id='target-a'").Scan(&targetState); err != nil || targetState != health.TargetSuspect {
		t.Fatalf("confirmed target state = %s, %v", targetState, err)
	}
}

func newPeriodicTestRunner(fixture runtimeFixture, clock *time.Time, reconcile func(context.Context) (any, error)) *PeriodicRunner {
	config := DefaultPeriodicConfig()
	config.PollInterval = time.Millisecond
	config.ActiveInterval = time.Minute
	config.StandbyInterval = 5 * time.Minute
	config.JitterPercent = 0
	return &PeriodicRunner{
		Runtime: fixture.candidateRuntime,
		Schedules: health.PeriodicRepository{
			Database: fixture.database,
			Now:      func() time.Time { return *clock },
		},
		Paths: fixture.paths, State: fixture.candidateRuntime.State,
		Reconcile: reconcile, Config: config,
	}
}

func activatePeriodicFixture(t *testing.T, fixture runtimeFixture, clock *time.Time) pathmatrix.Cell {
	t.Helper()
	fixture.candidateRuntime.Now = func() time.Time { return *clock }
	fixture.candidateRuntime.EvidenceTTL = time.Hour
	if _, err := fixture.candidateRuntime.RequalifyModem(fixture.ctx, "modem-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.candidateRuntime.RequalifyModem(fixture.ctx, "modem-b"); err != nil {
		t.Fatal(err)
	}
	cell, err := fixture.paths.Get(fixture.ctx, "modem-a", "sub-a")
	if err != nil || cell.State != pathmatrix.StateQualified || cell.SelectedNodeID == "" {
		t.Fatalf("active fixture cell = %+v, %v", cell, err)
	}
	if _, _, err := fixture.candidateRuntime.State.BeginActivation(fixture.ctx, cell.ID, cell.PolicyGeneration, cell.RouteGeneration); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.candidateRuntime.State.FinishNodeActivation(fixture.ctx, cell.ID, cell.SelectedNodeID, cell.PolicyGeneration, cell.RouteGeneration); err != nil {
		t.Fatal(err)
	}
	return cell
}

func addPeriodicSubscription(t *testing.T, fixture runtimeFixture, id string) {
	t.Helper()
	created, err := fixture.subscriptions.Create(fixture.ctx, subscription.CreateInput{
		ID: id, Name: id, SourceType: "url", SourceSecretRef: "/run/secrets/" + id, RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("vless://33333333-3333-3333-3333-333333333333@" + id + ".example.com:443#LTE-" + id)
	staged, err := fixture.versions.Stage(fixture.ctx, subscription.StageInput{VersionID: "version-" + id, SubscriptionID: created.ID, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := subscription.WriteNormalizedPayload(fixture.payloadRoot, created.ID, staged.Version.ID, staged.Import); err != nil {
		t.Fatal(err)
	}
	if err := fixture.versions.Activate(fixture.ctx, staged.Version.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.paths.ReconcileCells(fixture.ctx); err != nil {
		t.Fatal(err)
	}
}
