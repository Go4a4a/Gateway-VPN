package watchdog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixedPolicyReader struct{ policy Policy }

func (reader fixedPolicyReader) Get(context.Context) (Policy, error) { return reader.policy, nil }

type memoryHistory struct{ value DurableHistory }

func (history *memoryHistory) Load() (DurableHistory, error) { return cloneHistory(history.value), nil }
func (history *memoryHistory) Save(value DurableHistory) error {
	history.value = cloneHistory(value)
	return nil
}

type failingSaveHistory struct{ value DurableHistory }

func (history *failingSaveHistory) Load() (DurableHistory, error) {
	return cloneHistory(history.value), nil
}
func (history *failingSaveHistory) Save(DurableHistory) error { return os.ErrPermission }

type memoryStatus struct{ value Status }

func (status *memoryStatus) Write(value Status) error { status.value = value; return nil }

type fakeProbe struct {
	snapshot        ProbeSnapshot
	reconciles      []string
	restarts        []string
	actions         []string
	failClosed      int
	reboots         int
	failClosedError error
}

func (probe *fakeProbe) Snapshot(context.Context) (ProbeSnapshot, error) { return probe.snapshot, nil }
func (probe *fakeProbe) Reconcile(_ context.Context, id string) error {
	probe.reconciles = append(probe.reconciles, id)
	probe.actions = append(probe.actions, "reconcile:"+id)
	return nil
}
func (probe *fakeProbe) FailClosed(context.Context) error {
	probe.failClosed++
	probe.actions = append(probe.actions, "fail-closed")
	return probe.failClosedError
}
func (probe *fakeProbe) Restart(_ context.Context, id string) error {
	probe.restarts = append(probe.restarts, id)
	probe.actions = append(probe.actions, "restart:"+id)
	return nil
}
func (probe *fakeProbe) Reboot(context.Context) error {
	probe.reboots++
	probe.actions = append(probe.actions, "reboot")
	return nil
}

func TestExternalOutageNeverTriggersRecovery(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	probe := &fakeProbe{snapshot: healthySnapshot(now, "UNAVAILABLE")}
	status := &memoryStatus{}
	supervisor := testSupervisor(DefaultPolicy(), probe, status, now, &memoryHistory{value: NewDurableHistory()})
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(probe.reconciles) != 0 || len(probe.restarts) != 0 || probe.reboots != 0 || probe.failClosed != 0 {
		t.Fatalf("external outage caused recovery: %+v", probe)
	}
	if status.value.OverallState != OverallHealthy || status.value.ConnectivityClass != ClassificationExternal {
		t.Fatalf("status = %+v", status.value)
	}
}

func TestFailureThresholdReconcilesThenFailClosesAndRestarts(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold = 2
	probe := &fakeProbe{snapshot: failedSnapshot(now, ComponentNetworkBroker)}
	status := &memoryStatus{}
	history := &memoryHistory{value: NewDurableHistory()}
	supervisor := testSupervisor(policy, probe, status, now, history)
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(probe.reconciles) != 0 {
		t.Fatal("reconcile ran before failure threshold")
	}
	now = now.Add(15 * time.Second)
	supervisor.Now = func() time.Time { return now }
	probe.snapshot.ObservedAt = now
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(probe.reconciles) != 1 || probe.reconciles[0] != ComponentNetworkBroker {
		t.Fatalf("reconcile calls = %v", probe.reconciles)
	}
	now = now.Add(15 * time.Second)
	probe.snapshot.ObservedAt = now
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probe.failClosed != 1 || len(probe.restarts) != 1 || probe.restarts[0] != ComponentNetworkBroker {
		t.Fatalf("bounded restart sequence = failClosed:%d restart:%v", probe.failClosed, probe.restarts)
	}
	wantActions := []string{"reconcile:" + ComponentNetworkBroker, "fail-closed", "restart:" + ComponentNetworkBroker}
	if len(probe.actions) != len(wantActions) {
		t.Fatalf("recovery action order = %v", probe.actions)
	}
	for index := range wantActions {
		if probe.actions[index] != wantActions[index] {
			t.Fatalf("recovery action order = %v, want %v", probe.actions, wantActions)
		}
	}
	if len(history.value.RestartAttempts[ComponentNetworkBroker]) != 1 {
		t.Fatal("restart attempt was not persisted")
	}
}

func TestMaintenanceSuppressesLocalRecovery(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold = 1
	probe := &fakeProbe{snapshot: failedSnapshot(now, ComponentControl)}
	probe.snapshot.Maintenance = true
	probe.snapshot.MaintenanceCode = "UPDATE_ACTIVE"
	status := &memoryStatus{}
	supervisor := testSupervisor(policy, probe, status, now, &memoryHistory{value: NewDurableHistory()})
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(probe.reconciles) != 0 || len(probe.restarts) != 0 || probe.reboots != 0 {
		t.Fatal("maintenance transaction did not suppress recovery")
	}
	component := findComponent(t, status.value, ComponentControl)
	if !component.RecoverySuppressed || component.SuppressionReason != ClassificationMaintenance {
		t.Fatalf("maintenance component status = %+v", component)
	}
}

func TestRestartBudgetSurvivesSupervisorRestart(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold, policy.ReconcileEnabled, policy.MaxRestartsPerComponent = 1, false, 1
	history := &memoryHistory{value: NewDurableHistory()}
	firstProbe := &fakeProbe{snapshot: failedSnapshot(now, ComponentDNSMasq)}
	firstStatus := &memoryStatus{}
	first := testSupervisor(policy, firstProbe, firstStatus, now, history)
	if _, err := first.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(firstProbe.restarts) != 1 {
		t.Fatal("first supervisor did not consume restart budget")
	}
	secondProbe := &fakeProbe{snapshot: failedSnapshot(now.Add(time.Minute), ComponentDNSMasq)}
	secondStatus := &memoryStatus{}
	second := testSupervisor(policy, secondProbe, secondStatus, now.Add(time.Minute), history)
	if _, err := second.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(secondProbe.restarts) != 0 {
		t.Fatal("new supervisor ignored durable restart budget")
	}
	component := findComponent(t, secondStatus.value, ComponentDNSMasq)
	if component.SuppressionReason != "RESTART_BUDGET_EXHAUSTED" {
		t.Fatalf("suppression = %+v", component)
	}
}

func TestHostRebootRequiresExplicitPolicyCriticalDelayGraceAndDurableBudget(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold, policy.ReconcileEnabled, policy.ComponentRestartEnabled = 1, false, false
	policy.HostRebootEnabled = true
	policy.RebootAfterCriticalSeconds, policy.RebootGraceSeconds = 300, 10
	history := &memoryHistory{value: NewDurableHistory()}
	probe := &fakeProbe{snapshot: failedSnapshot(now, ComponentControl)}
	status := &memoryStatus{}
	supervisor := testSupervisor(policy, probe, status, now, history)
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probe.reboots != 0 || history.value.PendingRebootAt != "" {
		t.Fatal("reboot scheduled before continuous critical delay")
	}
	now = now.Add(300 * time.Second)
	supervisor.Now = func() time.Time { return now }
	probe.snapshot.ObservedAt = now
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probe.reboots != 0 || history.value.PendingRebootAt == "" {
		t.Fatal("reboot grace was not scheduled")
	}
	now = now.Add(10 * time.Second)
	probe.snapshot.ObservedAt = now
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probe.reboots != 1 || probe.failClosed != 1 || len(history.value.RebootAttempts) != 1 || history.value.PendingRebootAt != "" {
		t.Fatalf("reboot sequence = reboot:%d failClosed:%d history:%+v", probe.reboots, probe.failClosed, history.value)
	}
}

func TestRestartableComponentMatrixAlwaysFailsClosedBeforeFixedRestart(t *testing.T) {
	now := time.Date(2026, 8, 26, 11, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold, policy.ReconcileEnabled = 1, false
	for _, spec := range ComponentSpecs() {
		if !spec.Restartable {
			continue
		}
		t.Run(spec.ID, func(t *testing.T) {
			probe := &fakeProbe{snapshot: failedSnapshot(now, spec.ID)}
			supervisor := testSupervisor(policy, probe, &memoryStatus{}, now, &memoryHistory{value: NewDurableHistory()})
			if _, err := supervisor.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			want := []string{"fail-closed", "restart:" + spec.ID}
			if len(probe.actions) != len(want) || probe.actions[0] != want[0] || probe.actions[1] != want[1] {
				t.Fatalf("component recovery order = %v, want %v", probe.actions, want)
			}
		})
	}
}

func TestFailClosedFailurePreventsComponentRestart(t *testing.T) {
	now := time.Date(2026, 8, 26, 11, 30, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold, policy.ReconcileEnabled = 1, false
	probe := &fakeProbe{snapshot: failedSnapshot(now, ComponentMihomo), failClosedError: context.DeadlineExceeded}
	status := &memoryStatus{}
	supervisor := testSupervisor(policy, probe, status, now, &memoryHistory{value: NewDurableHistory()})
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(probe.restarts) != 0 || len(probe.actions) != 1 || probe.actions[0] != "fail-closed" {
		t.Fatalf("unsafe restart was not suppressed: actions=%v", probe.actions)
	}
	component := findComponent(t, status.value, ComponentMihomo)
	if !component.RecoverySuppressed || component.SuppressionReason != "FAIL_CLOSED_FAILED" {
		t.Fatalf("fail-closed suppression status = %+v", component)
	}
}

func TestRestartIsRefusedWhenDurableBudgetCannotBeCommitted(t *testing.T) {
	now := time.Date(2026, 8, 26, 11, 45, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold, policy.ReconcileEnabled = 1, false
	probe := &fakeProbe{snapshot: failedSnapshot(now, ComponentControl)}
	status := &memoryStatus{}
	history := &failingSaveHistory{value: NewDurableHistory()}
	supervisor := &Supervisor{Policies: fixedPolicyReader{policy: policy}, Probe: probe, History: history, Status: status, Now: func() time.Time { return now }}
	if _, err := supervisor.Tick(context.Background()); err == nil {
		t.Fatal("durable history failure was not surfaced")
	}
	if len(probe.restarts) != 0 || len(probe.actions) != 1 || probe.actions[0] != "fail-closed" {
		t.Fatalf("restart ran without durable budget: actions=%v", probe.actions)
	}
}

func TestHostRebootIsDefaultOffAndNonEligibleFailuresNeverReboot(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold, policy.ReconcileEnabled, policy.ComponentRestartEnabled = 1, false, false
	if policy.HostRebootEnabled {
		t.Fatal("host reboot default unexpectedly enabled")
	}
	probe := &fakeProbe{snapshot: failedSnapshot(now, ComponentControl)}
	status := &memoryStatus{}
	supervisor := testSupervisor(policy, probe, status, now, &memoryHistory{value: NewDurableHistory()})
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Duration(policy.RebootAfterCriticalSeconds+1) * time.Second)
	supervisor.Now = func() time.Time { return now }
	probe.snapshot.ObservedAt = now
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probe.reboots != 0 {
		t.Fatal("default policy rebooted the host")
	}
	if component := findComponent(t, status.value, ComponentControl); !component.RecoverySuppressed || component.SuppressionReason == "" {
		t.Fatalf("default-off reboot status = %+v", component)
	}

	policy.HostRebootEnabled = true
	for _, id := range []string{ComponentSQLite, ComponentResources} {
		nonEligibleProbe := &fakeProbe{snapshot: failedSnapshot(now, id)}
		nonEligible := testSupervisor(policy, nonEligibleProbe, &memoryStatus{}, now, &memoryHistory{value: NewDurableHistory()})
		if _, err := nonEligible.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		later := now.Add(time.Duration(policy.RebootAfterCriticalSeconds+policy.RebootGraceSeconds+1) * time.Second)
		nonEligible.Now = func() time.Time { return later }
		nonEligibleProbe.snapshot.ObservedAt = later
		if _, err := nonEligible.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		if nonEligibleProbe.reboots != 0 {
			t.Fatalf("non-reboot-eligible component %s rebooted host", id)
		}
	}
}

func TestDisablingHostRebootCancelsDurablePendingReboot(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 30, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold, policy.ReconcileEnabled, policy.ComponentRestartEnabled = 1, false, false
	history := NewDurableHistory()
	history.CriticalSince[ComponentControl] = now.Add(-time.Hour).Format(time.RFC3339Nano)
	history.PendingRebootAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	probe := &fakeProbe{snapshot: failedSnapshot(now, ComponentControl)}
	status := &memoryStatus{}
	persistence := &memoryHistory{value: history}
	supervisor := testSupervisor(policy, probe, status, now, persistence)
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probe.reboots != 0 || persistence.value.PendingRebootAt != "" || status.value.PendingRebootAt != "" {
		t.Fatalf("disabled reboot retained or executed pending action: probe=%+v history=%+v status=%+v", probe, persistence.value, status.value)
	}
}

func TestRebootBudgetSurvivesSupervisorRestartAndSuppressesLoop(t *testing.T) {
	now := time.Date(2026, 8, 26, 13, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold, policy.ReconcileEnabled, policy.ComponentRestartEnabled = 1, false, false
	policy.HostRebootEnabled = true
	policy.RebootAfterCriticalSeconds, policy.RebootGraceSeconds, policy.MaxRebootsPer24h = 300, 10, 1
	history := NewDurableHistory()
	history.RecordReboot(now.Add(-time.Hour))
	history.CriticalSince[ComponentControl] = now.Add(-10 * time.Minute).Format(time.RFC3339Nano)
	probe := &fakeProbe{snapshot: failedSnapshot(now, ComponentControl)}
	status := &memoryStatus{}
	supervisor := testSupervisor(policy, probe, status, now, &memoryHistory{value: history})
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probe.reboots != 0 || status.value.PendingRebootAt != "" {
		t.Fatalf("durable reboot budget did not suppress loop: status=%+v", status.value)
	}
	component := findComponent(t, status.value, ComponentControl)
	if !component.RecoverySuppressed || component.SuppressionReason != "REBOOT_BUDGET_EXHAUSTED" || status.value.OverallState != OverallRecoverySuppressed {
		t.Fatalf("reboot-loop suppression status = %+v overall=%s", component, status.value.OverallState)
	}
}

func TestSuccessThresholdKeepsRecoveringComponentDegradedUntilStable(t *testing.T) {
	now := time.Date(2026, 8, 26, 14, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.FailureThreshold, policy.ReconcileEnabled, policy.SuccessThreshold = 1, false, 2
	probe := &fakeProbe{snapshot: failedSnapshot(now, ComponentControl)}
	status := &memoryStatus{}
	history := &memoryHistory{value: NewDurableHistory()}
	supervisor := testSupervisor(policy, probe, status, now, history)
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	probe.snapshot = healthySnapshot(now.Add(15*time.Second), "AVAILABLE")
	now = now.Add(15 * time.Second)
	supervisor.Now = func() time.Time { return now }
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if component := findComponent(t, status.value, ComponentControl); component.State != ComponentDegraded || component.ConsecutiveSuccesses != 1 {
		t.Fatalf("first recovery success = %+v", component)
	}
	now = now.Add(15 * time.Second)
	probe.snapshot.ObservedAt = now
	if _, err := supervisor.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if component := findComponent(t, status.value, ComponentControl); component.State != ComponentHealthy || component.ConsecutiveSuccesses != 2 {
		t.Fatalf("stable recovery = %+v", component)
	}
	if _, exists := history.value.CriticalSince[ComponentControl]; exists {
		t.Fatal("stable recovery retained durable critical marker")
	}
}

func TestWatchdogIntervalJitterRemainsBounded(t *testing.T) {
	base := 15 * time.Second
	for index := 0; index < 100; index++ {
		value := jitterInterval(base)
		if value < 9*base/10 || value > 11*base/10 {
			t.Fatalf("jittered interval %s is outside ±10%%", value)
		}
	}
}

func TestSupervisorSignalsReadyOnlyAfterFirstStatus(t *testing.T) {
	now := time.Date(2026, 8, 26, 15, 0, 0, 0, time.UTC)
	probe := &fakeProbe{snapshot: healthySnapshot(now, "AVAILABLE")}
	status := &memoryStatus{}
	ctx, cancel := context.WithCancel(context.Background())
	readyCalls := 0
	supervisor := testSupervisor(DefaultPolicy(), probe, status, now, &memoryHistory{value: NewDurableHistory()})
	supervisor.OnReady = func() error {
		readyCalls++
		if status.value.ObservedAt == "" {
			t.Fatal("supervisor announced readiness before publishing status")
		}
		cancel()
		return nil
	}
	if err := supervisor.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if readyCalls != 1 {
		t.Fatalf("readiness notifications = %d", readyCalls)
	}
}

func TestHistoryStoreRoundTripAndRejectsSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "watchdog")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store := HistoryStore{Root: root}
	history := NewDurableHistory()
	history.RecordRestart(ComponentControl, time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC))
	if err := store.Save(history); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || len(loaded.RestartAttempts[ComponentControl]) != 1 {
		t.Fatalf("history round trip = %+v, %v", loaded, err)
	}
	if err := os.Remove(filepath.Join(root, "history.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), filepath.Join(root, "history.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("symlink history was accepted")
	}
}

func testSupervisor(policy Policy, probe *fakeProbe, status *memoryStatus, now time.Time, history *memoryHistory) *Supervisor {
	return &Supervisor{Policies: fixedPolicyReader{policy: policy}, Probe: probe, History: history, Status: status, Now: func() time.Time { return now }}
}

func healthySnapshot(now time.Time, connectivity string) ProbeSnapshot {
	items := make([]Observation, 0, len(ComponentSpecs()))
	for _, spec := range ComponentSpecs() {
		items = append(items, Observation{ComponentID: spec.ID, Applicable: true, Healthy: true})
	}
	return ProbeSnapshot{ObservedAt: now, Connectivity: connectivity, Components: items}
}

func failedSnapshot(now time.Time, failedID string) ProbeSnapshot {
	snapshot := healthySnapshot(now, "AVAILABLE")
	for index := range snapshot.Components {
		if snapshot.Components[index].ComponentID == failedID {
			snapshot.Components[index].Healthy = false
			snapshot.Components[index].ErrorCode = "TEST_FAILURE"
		}
	}
	return snapshot
}

func findComponent(t *testing.T, status Status, id string) ComponentStatus {
	t.Helper()
	for _, component := range status.Components {
		if component.ID == id {
			return component
		}
	}
	t.Fatalf("component %s missing", id)
	return ComponentStatus{}
}

func cloneHistory(history DurableHistory) DurableHistory {
	result := NewDurableHistory()
	result.PendingRebootAt = history.PendingRebootAt
	result.RebootAttempts = append([]string(nil), history.RebootAttempts...)
	for id, attempts := range history.RestartAttempts {
		result.RestartAttempts[id] = append([]string(nil), attempts...)
	}
	for id, value := range history.CriticalSince {
		result.CriticalSince[id] = value
	}
	return result
}
