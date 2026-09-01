package updateautomation

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/networkapply"
	"gateway-vpn/internal/power"
	"gateway-vpn/internal/state"
	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/updateremote"
)

type fakeStager struct {
	operation updatepkg.Operation
	pending   bool
	err       error
}

func (stager *fakeStager) Status() (updatepkg.Operation, bool, error) {
	return stager.operation, stager.pending, stager.err
}

type fakeRemote struct {
	stager       *fakeStager
	available    updateremote.Available
	checkErr     error
	stageErr     error
	operation    updatepkg.Operation
	checks       int
	downloads    int
	checkStarted chan struct{}
	checkRelease <-chan struct{}
}

func (remote *fakeRemote) Check(ctx context.Context, _ string) (updateremote.Available, error) {
	remote.checks++
	if remote.checkStarted != nil {
		select {
		case <-remote.checkStarted:
		default:
			close(remote.checkStarted)
		}
	}
	if remote.checkRelease != nil {
		select {
		case <-ctx.Done():
			return updateremote.Available{}, ctx.Err()
		case <-remote.checkRelease:
		}
	}
	return remote.available, remote.checkErr
}

func (remote *fakeRemote) StageAutomaticChannel(_ context.Context, channel string) (updatepkg.Operation, error) {
	remote.downloads++
	if remote.stageErr != nil {
		return updatepkg.Operation{}, remote.stageErr
	}
	operation := remote.operation
	operation.SourceKind = updatepkg.SourceAutomaticGitHub
	operation.SourceChannel = channel
	remote.stager.operation = operation
	remote.stager.pending = true
	return operation, nil
}

type fakeApply struct {
	maintenance    power.MaintenanceStatus
	maintenanceErr error
	root           networkapply.UpdateTransactionStatus
	rootErr        error
	applyErr       error
	applyCalls     int
}

func (apply *fakeApply) ApplyPendingUpdate(context.Context) error {
	apply.applyCalls++
	return apply.applyErr
}

func (apply *fakeApply) UpdateStatus(context.Context) (networkapply.UpdateTransactionStatus, error) {
	return apply.root, apply.rootErr
}

func (apply *fakeApply) MaintenanceStatus(context.Context) (power.MaintenanceStatus, error) {
	return apply.maintenance, apply.maintenanceErr
}

type fakePath struct {
	calls int
	err   error
}

type fakeReadiness struct {
	reason string
	err    error
	calls  int
}

func (readiness *fakeReadiness) Check(context.Context, time.Time) (string, error) {
	readiness.calls++
	return readiness.reason, readiness.err
}

func (path *fakePath) BlockPath(context.Context) error {
	path.calls++
	return path.err
}

type fakeState struct {
	blocks int
	events []state.EventInput
	err    error
}

func (recorder *fakeState) Block(context.Context, string, string) (state.Snapshot, bool, error) {
	recorder.blocks++
	return state.Snapshot{}, true, recorder.err
}

func (recorder *fakeState) AppendEvent(_ context.Context, input state.EventInput) error {
	recorder.events = append(recorder.events, input)
	return nil
}

type schedulerFixture struct {
	database               *sql.DB
	clock                  time.Time
	policy                 *updatepkg.AutomationPolicyRepository
	stager                 *fakeStager
	remote                 *fakeRemote
	apply                  *fakeApply
	path                   *fakePath
	states                 *fakeState
	readiness              *fakeReadiness
	scheduler              *Scheduler
	maximumApplyDelayHours int
}

func newSchedulerFixture(t *testing.T) *schedulerFixture {
	t.Helper()
	ctx := context.Background()
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: t.TempDir() + "/state.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := databasepkg.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	fixture := &schedulerFixture{database: database, clock: time.Date(2026, 9, 1, 3, 30, 0, 0, time.UTC)}
	fixture.policy = &updatepkg.AutomationPolicyRepository{Database: database, Now: func() time.Time { return fixture.clock }}
	fixture.stager = &fakeStager{}
	fixture.remote = &fakeRemote{stager: fixture.stager}
	fixture.apply = &fakeApply{}
	fixture.path = &fakePath{}
	fixture.states = &fakeState{}
	fixture.readiness = &fakeReadiness{}
	fixture.scheduler = &Scheduler{
		Repository: Repository{Database: database}, Policy: fixture.policy,
		Remote: fixture.remote, Stager: fixture.stager, Apply: fixture.apply,
		Path: fixture.path, State: fixture.states, Readiness: fixture.readiness, Owner: strings.Repeat("a", 32),
		Now: func() time.Time { return fixture.clock },
	}
	return fixture
}

func (fixture *schedulerFixture) setPolicy(t *testing.T, check, download, apply bool) updatepkg.AutomationPolicy {
	t.Helper()
	defaults := updatepkg.DefaultAutomationPolicy()
	maximumApplyDelayHours := fixture.maximumApplyDelayHours
	if maximumApplyDelayHours == 0 {
		maximumApplyDelayHours = defaults.MaximumApplyDelayHours
	}
	policy, err := fixture.policy.Update(context.Background(), updatepkg.AutomationPolicyInput{
		Channel: "stable", AutomaticCheckEnabled: check, AutomaticDownloadEnabled: download,
		AutomaticApplyEnabled: apply, CheckIntervalHours: 1, JitterMinutes: 10,
		MaintenanceWindowEnabled: apply, MaintenanceStartMinuteUTC: 180, MaintenanceDurationMinutes: 120,
		MaximumApplyDelayHours: maximumApplyDelayHours,
		RetentionMaximumPoints: defaults.RetentionMaximumPoints, RetentionMaximumBytes: defaults.RetentionMaximumBytes,
		RetentionMaximumAgeDays: defaults.RetentionMaximumAgeDays, RetentionMinimumOldPoints: defaults.RetentionMinimumOldPoints,
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func (fixture *schedulerFixture) makeDue(t *testing.T) {
	t.Helper()
	if _, err := fixture.database.ExecContext(context.Background(), `UPDATE software_update_scheduler SET next_check_at=? WHERE singleton_id=1`, fixture.clock.Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func availableFixture() updateremote.Available {
	return updateremote.Available{
		Available: true, Channel: "stable", CurrentVersion: "1.1.0", CandidateVersion: "1.2.0",
		ReleaseTag: "v1.2.0", PublishedAt: "2026-09-01T02:00:00Z", ArtifactBytes: 8192,
		ArtifactSHA256: strings.Repeat("b", 64), SourceReference: "Go4a4a/Gateway-VPN#v1.2.0", SourceCommit: strings.Repeat("c", 40),
	}
}

func automaticOperationFixture() updatepkg.Operation {
	return updatepkg.Operation{
		FormatVersion: updatepkg.StagingFormatVersion,
		UpdateID:      "update-20260901T033000Z-0123456789abcdef01234567", State: "STAGED",
		CreatedAt: "2026-09-01T03:30:00Z", GatewayVersion: "1.2.0", MihomoVersion: "1.19.0",
		SignerKeySHA256: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64),
		UncompressedBytes: 8192, FileCount: 8, SourceKind: updatepkg.SourceAutomaticGitHub,
		SourceChannel: "stable", SourceReference: "Go4a4a/Gateway-VPN#v1.2.0",
	}
}

func TestSchedulerPersistsDeterministicDeadlineAndHonorsLease(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.setPolicy(t, true, false, false)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || first.Phase != PhaseIdle || first.NextCheckAt == "" || first.JitterOffsetMinutes < 0 || first.JitterOffsetMinutes > 10 || fixture.remote.checks != 0 {
		t.Fatalf("initial status = %+v checks=%d error=%v", first, fixture.remote.checks, err)
	}
	fixture.makeDue(t)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	checked, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || checked.LastResultCode != "UP_TO_DATE" || fixture.remote.checks != 1 || checked.JitterOffsetMinutes != first.JitterOffsetMinutes {
		t.Fatalf("checked status = %+v checks=%d error=%v", checked, fixture.remote.checks, err)
	}
	owner := strings.Repeat("b", 32)
	if _, acquired, err := fixture.scheduler.Repository.Acquire(context.Background(), owner, fixture.clock, time.Minute); err != nil || !acquired {
		t.Fatalf("external lease = %t,%v", acquired, err)
	}
	if err := fixture.scheduler.RunOnce(context.Background()); !errors.Is(err, ErrLeaseBusy) {
		t.Fatalf("RunOnce under foreign lease = %v", err)
	}
}

func TestSchedulerStagesOnlyOwnedChannelAndDispatchesInsideUTCWindow(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.setPolicy(t, true, true, true)
	fixture.remote.available = availableFixture()
	fixture.remote.operation = automaticOperationFixture()
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.makeDue(t)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || status.Phase != PhaseApplyDispatched || status.StagedUpdateID != fixture.remote.operation.UpdateID || fixture.remote.checks != 1 || fixture.remote.downloads != 1 || fixture.path.calls != 1 || fixture.states.blocks != 1 || fixture.apply.applyCalls != 1 {
		t.Fatalf("dispatched status=%+v calls=%d/%d/%d/%d/%d error=%v", status, fixture.remote.checks, fixture.remote.downloads, fixture.path.calls, fixture.states.blocks, fixture.apply.applyCalls, err)
	}
	fixture.stager.pending = false
	fixture.apply.root = networkapply.UpdateTransactionStatus{Exists: true, UpdateID: fixture.remote.operation.UpdateID, State: string(updatepkg.StateFinalized)}
	fixture.clock = fixture.clock.Add(time.Minute)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	finished, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || finished.Phase != PhaseSucceeded || finished.LastResultCode != "AUTO_UPDATE_FINALIZED" || finished.StagedUpdateID != "" || fixture.apply.applyCalls != 1 {
		t.Fatalf("finished status=%+v apply=%d error=%v", finished, fixture.apply.applyCalls, err)
	}
}

func TestSchedulerNeverAdoptsManualPendingRelease(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.setPolicy(t, true, true, true)
	fixture.stager.operation = automaticOperationFixture()
	fixture.stager.operation.SourceKind = updatepkg.SourceGitHubChannel
	fixture.stager.pending = true
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || status.Phase != PhaseManualPending || status.StagedUpdateID != "" || fixture.remote.checks != 0 || fixture.remote.downloads != 0 || fixture.apply.applyCalls != 0 || fixture.path.calls != 0 {
		t.Fatalf("manual pending status=%+v calls=%d/%d/%d/%d error=%v", status, fixture.remote.checks, fixture.remote.downloads, fixture.apply.applyCalls, fixture.path.calls, err)
	}
}

func TestSchedulerSuppressesMaintenanceAndDoesNotRetryAmbiguousApplyIntent(t *testing.T) {
	fixture := newSchedulerFixture(t)
	policy := fixture.setPolicy(t, true, true, true)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.makeDue(t)
	fixture.apply.maintenance = power.MaintenanceStatus{Active: true, ReasonCode: "NETWORK_APPLY_ACTIVE"}
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	suppressed, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || suppressed.Phase != PhaseSuppressed || suppressed.LastErrorCode != "NETWORK_APPLY_ACTIVE" || fixture.remote.checks != 0 {
		t.Fatalf("suppressed status=%+v checks=%d error=%v", suppressed, fixture.remote.checks, err)
	}

	fixture.apply.maintenance = power.MaintenanceStatus{}
	fixture.stager.operation = automaticOperationFixture()
	fixture.stager.pending = true
	owner := strings.Repeat("c", 32)
	repository := fixture.scheduler.Repository
	if _, acquired, err := repository.Acquire(context.Background(), owner, fixture.clock, time.Minute); err != nil || !acquired {
		t.Fatal(err)
	}
	if _, err := repository.UpdateOwned(context.Background(), owner, func(status *Status) error {
		status.Phase = PhaseApplyIntent
		status.StagedUpdateID = fixture.stager.operation.UpdateID
		status.StagedVersion = fixture.stager.operation.GatewayVersion
		if err := setStagingEvidence(status, fixture.stager.operation, policy); err != nil {
			return err
		}
		status.ApplyIntentAt = fixture.clock.Format(time.RFC3339Nano)
		status.UpdatedAt = fixture.clock.Format(time.RFC3339Nano)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Release(context.Background(), owner, fixture.clock); err != nil {
		t.Fatal(err)
	}
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	unknown, err := repository.Get(context.Background())
	if err != nil || unknown.Phase != PhaseOutcomeUnknown || unknown.LastErrorCode != "AUTO_APPLY_OUTCOME_UNKNOWN" || fixture.apply.applyCalls != 0 {
		t.Fatalf("unknown status=%+v apply=%d error=%v", unknown, fixture.apply.applyCalls, err)
	}
	fixture.clock = fixture.clock.Add(time.Hour)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	stillUnknown, err := repository.Get(context.Background())
	if err != nil || stillUnknown.Phase != PhaseOutcomeUnknown || stillUnknown.NextApplyAt != "" || fixture.apply.applyCalls != 0 || fixture.path.calls != 0 {
		t.Fatalf("ambiguous apply was redispatched: status=%+v path/apply=%d/%d error=%v", stillUnknown, fixture.path.calls, fixture.apply.applyCalls, err)
	}
}

func TestSchedulerHonorsDeferredDeadlineAndAutomaticApplyReadiness(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.setPolicy(t, true, true, true)
	fixture.stager.operation = automaticOperationFixture()
	fixture.stager.pending = true
	fixture.readiness.reason = ReadinessFullPathUnavailable
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	deferred, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || deferred.Phase != PhaseStaged || deferred.LastErrorCode != ReadinessFullPathUnavailable || deferred.NextApplyAt != fixture.clock.Add(applyRetry).Format(time.RFC3339Nano) || fixture.readiness.calls != 1 || fixture.path.calls != 0 || fixture.apply.applyCalls != 0 {
		t.Fatalf("readiness deferred status=%+v calls=%d/%d/%d error=%v", deferred, fixture.readiness.calls, fixture.path.calls, fixture.apply.applyCalls, err)
	}
	fixture.readiness.reason = ""
	fixture.clock = fixture.clock.Add(time.Minute)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.readiness.calls != 1 || fixture.path.calls != 0 || fixture.apply.applyCalls != 0 {
		t.Fatalf("deferred deadline ignored: readiness/path/apply=%d/%d/%d", fixture.readiness.calls, fixture.path.calls, fixture.apply.applyCalls)
	}
	fixture.clock = fixture.clock.Add(applyRetry)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.readiness.calls != 2 || fixture.path.calls != 1 || fixture.apply.applyCalls != 1 {
		t.Fatalf("due deferred apply not dispatched: readiness/path/apply=%d/%d/%d", fixture.readiness.calls, fixture.path.calls, fixture.apply.applyCalls)
	}
}

func TestSchedulerStopsUnattendedRetriesAtMaximumApplyDelay(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.maximumApplyDelayHours = 1
	fixture.setPolicy(t, true, true, true)
	fixture.remote.available = availableFixture()
	fixture.remote.operation = automaticOperationFixture()
	fixture.readiness.reason = ReadinessFullPathUnavailable
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.makeDue(t)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	staged, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || staged.Phase != PhaseStaged || staged.StagedAt != fixture.remote.operation.CreatedAt || staged.ApplyDeadlineAt != fixture.clock.Add(time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("staged deadline status=%+v error=%v", staged, err)
	}
	fixture.clock = fixture.clock.Add(time.Hour)
	fixture.readiness.reason = ""
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	expired, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || expired.Phase != PhaseManualAttention || expired.LastErrorCode != "AUTO_APPLY_DEADLINE_EXPIRED" || expired.NextApplyAt != "" || fixture.readiness.calls != 1 || fixture.path.calls != 0 || fixture.apply.applyCalls != 0 {
		t.Fatalf("expired status=%+v readiness/path/apply=%d/%d/%d error=%v", expired, fixture.readiness.calls, fixture.path.calls, fixture.apply.applyCalls, err)
	}
	if len(fixture.states.events) == 0 || fixture.states.events[len(fixture.states.events)-1].Type != "AUTOMATIC_UPDATE_APPLY_DEADLINE_EXPIRED" || fixture.states.events[len(fixture.states.events)-1].Severity != "WARNING" {
		t.Fatalf("deadline audit events=%+v", fixture.states.events)
	}
	fixture.clock = fixture.clock.Add(24 * time.Hour)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.readiness.calls != 1 || fixture.path.calls != 0 || fixture.apply.applyCalls != 0 {
		t.Fatalf("manual-attention state retried readiness/path/apply=%d/%d/%d", fixture.readiness.calls, fixture.path.calls, fixture.apply.applyCalls)
	}
}

func TestSchedulerAdoptsCompletedAutomaticDownloadAfterInterruptedCaller(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.setPolicy(t, true, true, false)
	fixture.remote.available = availableFixture()
	operation := automaticOperationFixture()
	fixture.stager.operation, fixture.stager.pending = operation, true
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || status.Phase != PhaseStaged || status.StagedUpdateID != operation.UpdateID || status.StagedVersion != operation.GatewayVersion || fixture.remote.downloads != 0 || fixture.apply.applyCalls != 0 {
		t.Fatalf("adopted interrupted download status=%+v downloads=%d apply=%d error=%v", status, fixture.remote.downloads, fixture.apply.applyCalls, err)
	}
}

func TestSchedulerProjectsRootRollbackAndPolicyGenerationChange(t *testing.T) {
	fixture := newSchedulerFixture(t)
	first := fixture.setPolicy(t, true, true, false)
	operation := automaticOperationFixture()
	fixture.stager.operation, fixture.stager.pending = operation, true
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock = fixture.clock.Add(time.Nanosecond)
	second := fixture.setPolicy(t, true, true, false)
	if second.UpdatedAt == first.UpdatedAt {
		t.Fatal("policy generation timestamp did not change")
	}
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || after.PolicyUpdatedAt != second.UpdatedAt || after.JitterOffsetMinutes != deterministicJitter(second) || after.StagedUpdateID != operation.UpdateID {
		t.Fatalf("policy generation resync status before=%+v after=%+v error=%v", before, after, err)
	}
	fixture.stager.pending = false
	fixture.apply.root = networkapply.UpdateTransactionStatus{Exists: true, UpdateID: operation.UpdateID, State: string(updatepkg.StateRolledBack)}
	fixture.clock = fixture.clock.Add(time.Minute)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || rolledBack.Phase != PhaseFailed || rolledBack.LastResultCode != "AUTO_UPDATE_ROLLED_BACK" || rolledBack.LastErrorCode != "AUTO_UPDATE_ROLLED_BACK" || rolledBack.StagedUpdateID != "" {
		t.Fatalf("root rollback projection=%+v error=%v", rolledBack, err)
	}
}

func TestMalformedCandidateIsSanitizedToStableFailureCode(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.setPolicy(t, true, false, false)
	fixture.remote.available = availableFixture()
	fixture.remote.available.SourceReference = "https://user:secret@example.com/release?token=secret"
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.makeDue(t)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || status.Phase != PhaseFailed || status.LastErrorCode != "UPDATE_CANDIDATE_INVALID" || status.CandidateReference != "" || strings.Contains(status.String(), "secret") {
		t.Fatalf("malformed candidate projection=%+v error=%v", status, err)
	}
}

func TestSchedulerFailsSafeWhenMaintenanceStatusIsUnavailable(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.setPolicy(t, true, false, false)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.makeDue(t)
	fixture.apply.maintenanceErr = errors.New("private systemd path /etc/systemd/system")
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || status.Phase != PhaseSuppressed || status.LastErrorCode != "MAINTENANCE_STATUS_UNAVAILABLE" || status.NextCheckAt != fixture.clock.Add(maintenanceRetry).Format(time.RFC3339Nano) || fixture.remote.checks != 0 || fixture.remote.downloads != 0 || fixture.apply.applyCalls != 0 {
		t.Fatalf("maintenance fail-safe status=%+v calls=%d/%d/%d error=%v", status, fixture.remote.checks, fixture.remote.downloads, fixture.apply.applyCalls, err)
	}
}

func TestPolicyChangeCannotApplyAlreadyStagedRelease(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.clock = time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
	fixture.setPolicy(t, true, true, true)
	operation := automaticOperationFixture()
	fixture.stager.operation, fixture.stager.pending = operation, true
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	waiting, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || waiting.Phase != PhaseWaitingWindow || waiting.StagedUpdateID != operation.UpdateID || fixture.apply.applyCalls != 0 {
		t.Fatalf("initial staged status=%+v apply=%d error=%v", waiting, fixture.apply.applyCalls, err)
	}
	fixture.clock = fixture.clock.Add(time.Nanosecond)
	disabled := fixture.setPolicy(t, true, true, false)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := fixture.scheduler.Repository.Get(context.Background())
	if err != nil || status.PolicyUpdatedAt != disabled.UpdatedAt || status.Phase != PhaseStaged || status.StagedUpdateID != operation.UpdateID || status.NextApplyAt != "" || fixture.path.calls != 0 || fixture.apply.applyCalls != 0 {
		t.Fatalf("disabled apply policy status=%+v path/apply=%d/%d error=%v", status, fixture.path.calls, fixture.apply.applyCalls, err)
	}
}

func TestConcurrentSchedulersShareOneDurableLease(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.setPolicy(t, true, false, false)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.makeDue(t)
	started := make(chan struct{})
	release := make(chan struct{})
	fixture.remote.checkStarted = started
	fixture.remote.checkRelease = release
	firstDone := make(chan error, 1)
	go func() { firstDone <- fixture.scheduler.RunOnce(context.Background()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first scheduler did not enter remote check")
	}
	second := &Scheduler{
		Repository: fixture.scheduler.Repository, Policy: fixture.policy,
		Remote: fixture.remote, Stager: fixture.stager, Apply: fixture.apply,
		Path: fixture.path, State: fixture.states, Readiness: fixture.readiness,
		Owner: strings.Repeat("b", 32), Now: func() time.Time { return fixture.clock },
	}
	if err := second.RunOnce(context.Background()); !errors.Is(err, ErrLeaseBusy) {
		t.Fatalf("second scheduler under active lease = %v", err)
	}
	close(release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first scheduler did not finish")
	}
	if fixture.remote.checks != 1 || fixture.remote.downloads != 0 || fixture.apply.applyCalls != 0 {
		t.Fatalf("concurrent calls checks/downloads/apply=%d/%d/%d", fixture.remote.checks, fixture.remote.downloads, fixture.apply.applyCalls)
	}
}

func TestLeaseLossCancelsRemoteWorkAndReturnsAuthoritativeError(t *testing.T) {
	fixture := newSchedulerFixture(t)
	fixture.setPolicy(t, true, false, false)
	if err := fixture.scheduler.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.makeDue(t)
	started := make(chan struct{})
	fixture.remote.checkStarted = started
	fixture.remote.checkRelease = make(chan struct{})
	fixture.scheduler.leaseRenewInterval = 10 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- fixture.scheduler.RunOnce(context.Background()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not enter remote check")
	}
	if _, err := fixture.database.ExecContext(context.Background(), `UPDATE software_update_scheduler SET lease_owner=?,lease_expires_at=? WHERE singleton_id=1`, strings.Repeat("b", 32), fixture.clock.Add(time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "lease was lost") || errors.Is(err, context.Canceled) {
			t.Fatalf("lease-loss result = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lease loss did not cancel remote check")
	}
	if fixture.remote.checks != 1 || fixture.remote.downloads != 0 || fixture.path.calls != 0 || fixture.apply.applyCalls != 0 {
		t.Fatalf("lease loss crossed mutation boundary checks/downloads/path/apply=%d/%d/%d/%d", fixture.remote.checks, fixture.remote.downloads, fixture.path.calls, fixture.apply.applyCalls)
	}
}

func TestMaintenanceWindowAndRetryBounds(t *testing.T) {
	policy := updatepkg.DefaultAutomationPolicy()
	policy.MaintenanceWindowEnabled = true
	policy.MaintenanceStartMinuteUTC = 23*60 + 30
	policy.MaintenanceDurationMinutes = 120
	if !insideMaintenanceWindow(policy, time.Date(2026, 9, 2, 0, 15, 0, 0, time.UTC)) || insideMaintenanceWindow(policy, time.Date(2026, 9, 2, 2, 0, 0, 0, time.UTC)) {
		t.Fatal("cross-midnight UTC maintenance window was evaluated incorrectly")
	}
	if got := nextMaintenanceStart(policy, time.Date(2026, 9, 2, 20, 0, 0, 0, time.UTC)); !got.Equal(time.Date(2026, 9, 2, 23, 30, 0, 0, time.UTC)) {
		t.Fatalf("next maintenance = %s", got)
	}
	if failureBackoff(1) != 5*time.Minute || failureBackoff(100) != 6*time.Hour {
		t.Fatalf("backoff bounds = %s/%s", failureBackoff(1), failureBackoff(100))
	}
}
