package networkapply

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

type fakeBackend struct {
	calls       *[]string
	snapshotErr error
	applyErr    error
	commitErr   error
	rollbackErr error
	cancelApply context.CancelFunc
	rollbackCtx error
}

func (backend *fakeBackend) record(value string) {
	*backend.calls = append(*backend.calls, value)
}

func (backend *fakeBackend) Snapshot(context.Context, Manifest, string) error {
	backend.record("snapshot")
	return backend.snapshotErr
}

func (backend *fakeBackend) Apply(context.Context, Manifest, string) error {
	backend.record("apply")
	if backend.cancelApply != nil {
		backend.cancelApply()
	}
	return backend.applyErr
}

func (backend *fakeBackend) Commit(context.Context, Manifest, string) error {
	backend.record("commit")
	return backend.commitErr
}

func (backend *fakeBackend) Rollback(ctx context.Context, _ Manifest, _ string) error {
	backend.record("rollback")
	backend.rollbackCtx = ctx.Err()
	return backend.rollbackErr
}

type fakeTimer struct {
	calls     *[]string
	armErr    error
	disarmErr error
}

func (timer *fakeTimer) Arm(context.Context, string, time.Time) error {
	*timer.calls = append(*timer.calls, "arm")
	return timer.armErr
}

func (timer *fakeTimer) Disarm(context.Context, string) error {
	*timer.calls = append(*timer.calls, "disarm")
	return timer.disarmErr
}

func TestEngineArmsBeforeApplyAndConfirmsOnlyThroughNewDestination(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, backend, _ := testEngine(t, database)
	prepared, err := engine.Prepare(ctx, validCandidate())
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if prepared.ApplyID != "apply-01010101010101010101010101010101" || prepared.ConfirmToken != strings.Repeat("02", 32) || prepared.NewURL != "https://192.168.210.1:8443" {
		t.Fatalf("Prepare() = %+v", prepared)
	}
	if got := strings.Join(*backend.calls, ","); got != "snapshot,arm,apply" {
		t.Fatalf("operation order = %s", got)
	}
	item, err := engine.Repository.Get(ctx, prepared.ApplyID)
	if err != nil || item.State != StateApplied || item.ConfirmTokenSHA256 == prepared.ConfirmToken {
		t.Fatalf("stored transaction = %+v, %v", item, err)
	}
	_, status, err := engine.Store.Load(prepared.ApplyID)
	if err != nil || status.Phase != PhaseApplied {
		t.Fatalf("durable status = %+v, %v", status, err)
	}
	if err := engine.Confirm(ctx, prepared.ApplyID, ConfirmEvidence{Token: "wrong", LocalDestinationIP: "192.168.210.1"}); !errors.Is(err, ErrConfirmToken) {
		t.Fatalf("wrong token error = %v", err)
	}
	if err := engine.Confirm(ctx, prepared.ApplyID, ConfirmEvidence{Token: prepared.ConfirmToken, LocalDestinationIP: "192.168.200.1"}); !errors.Is(err, ErrConfirmSource) {
		t.Fatalf("old destination error = %v", err)
	}
	if err := engine.Confirm(ctx, prepared.ApplyID, ConfirmEvidence{Token: prepared.ConfirmToken, LocalDestinationIP: "192.168.210.1"}); err != nil {
		t.Fatalf("Confirm(new destination) error = %v", err)
	}
	if got := strings.Join(*backend.calls, ","); got != "snapshot,arm,apply,disarm,commit" {
		t.Fatalf("confirm operation order = %s", got)
	}
	item, _ = engine.Repository.Get(ctx, prepared.ApplyID)
	_, status, _ = engine.Store.Load(prepared.ApplyID)
	if item.State != StateConfirmed || item.ConfirmedAt == "" || status.Phase != PhaseConfirmed {
		t.Fatalf("confirmed state db=%+v disk=%+v", item, status)
	}
}

func TestEngineStageReturnsTokenBeforeSeparateNetworkApply(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, backend, _ := testEngine(t, database)
	prepared, err := engine.Stage(ctx, validCandidate())
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if got := strings.Join(*backend.calls, ","); got != "snapshot,arm" {
		t.Fatalf("Stage operation order = %s", got)
	}
	item, _ := engine.Repository.Get(ctx, prepared.ApplyID)
	_, status, _ := engine.Store.Load(prepared.ApplyID)
	if item.State != StateArmed || status.Phase != PhaseArmed || prepared.ConfirmToken == "" {
		t.Fatalf("armed state db=%+v disk=%+v prepared=%+v", item, status, prepared)
	}
	if err := engine.Apply(ctx, prepared.ApplyID); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if got := strings.Join(*backend.calls, ","); got != "snapshot,arm,apply" {
		t.Fatalf("Apply operation order = %s", got)
	}
}

func TestEngineAcceptsConfirmationThroughWireGuard(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	prepared, err := engine.Prepare(ctx, validCandidate())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Confirm(ctx, prepared.ApplyID, ConfirmEvidence{Token: prepared.ConfirmToken, LocalDestinationIP: "10.80.0.2", ViaWireGuard: true}); err != nil {
		t.Fatalf("Confirm(WireGuard) error = %v", err)
	}
}

func TestEngineApplyFailureRollsBackWithCancellationIndependentContext(t *testing.T) {
	baseContext, database := networkApplyDatabase(t)
	ctx, cancel := context.WithCancel(baseContext)
	engine, backend, _ := testEngine(t, database)
	backend.cancelApply = cancel
	backend.applyErr = context.Canceled
	_, err := engine.Prepare(ctx, validCandidate())
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("Prepare(failed apply) error = %v", err)
	}
	if backend.rollbackCtx != nil {
		t.Fatalf("rollback inherited canceled context: %v", backend.rollbackCtx)
	}
	if got := strings.Join(*backend.calls, ","); got != "snapshot,arm,apply,rollback,disarm" {
		t.Fatalf("failure operation order = %s", got)
	}
	item, err := engine.Repository.Get(baseContext, "apply-01010101010101010101010101010101")
	if err != nil || item.State != StateRolledBack || item.ErrorCode != "CANDIDATE_APPLY_FAILED" {
		t.Fatalf("rolled-back transaction = %+v, %v", item, err)
	}
}

func TestRollbackFromDiskWorksWithoutDatabaseAndRecoveryReconcilesState(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, backend, _ := testEngine(t, database)
	prepared, err := engine.Prepare(ctx, validCandidate())
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := RollbackFromDisk(ctx, engine.Store, backend, prepared.ApplyID)
	if err != nil || !rolledBack {
		t.Fatalf("RollbackFromDisk() = %v, %v", rolledBack, err)
	}
	_, status, err := engine.Store.Load(prepared.ApplyID)
	if err != nil || status.Phase != PhaseRolledBack {
		t.Fatalf("disk rollback status = %+v, %v", status, err)
	}
	if err := engine.Recover(ctx); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	item, err := engine.Repository.Get(ctx, prepared.ApplyID)
	if err != nil || item.State != StateRolledBack || item.ErrorCode != "RECOVERED_ROLLBACK" {
		t.Fatalf("recovered DB state = %+v, %v", item, err)
	}
}

func TestRecoverRollsBackUnconfirmedApplyEvenBeforeDeadline(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, backend, _ := testEngine(t, database)
	prepared, err := engine.Prepare(ctx, validCandidate())
	if err != nil {
		t.Fatal(err)
	}
	before := len(*backend.calls)
	if err := engine.Recover(ctx); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if strings.Join((*backend.calls)[before:], ",") != "rollback,disarm" {
		t.Fatalf("recovery calls = %+v", (*backend.calls)[before:])
	}
	item, _ := engine.Repository.Get(ctx, prepared.ApplyID)
	if item.State != StateRolledBack || item.ErrorCode != "REBOOT_RECOVERY" {
		t.Fatalf("reboot recovery state = %+v", item)
	}
}

func TestRecoverCompletesDurableConfirmationIntent(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, backend, _ := testEngine(t, database)
	prepared, err := engine.Prepare(ctx, validCandidate())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Store.SetPhase(prepared.ApplyID, PhaseConfirming); err != nil {
		t.Fatal(err)
	}
	if err := engine.Repository.Transition(ctx, prepared.ApplyID, []string{StateApplied}, StateConfirming, ""); err != nil {
		t.Fatal(err)
	}
	before := len(*backend.calls)
	if err := engine.Recover(ctx); err != nil {
		t.Fatalf("Recover(confirming) error = %v", err)
	}
	if strings.Join((*backend.calls)[before:], ",") != "disarm,commit" {
		t.Fatalf("confirmation recovery calls = %+v", (*backend.calls)[before:])
	}
	item, _ := engine.Repository.Get(ctx, prepared.ApplyID)
	if item.State != StateConfirmed {
		t.Fatalf("confirmation recovery state = %+v", item)
	}
}

func TestEngineRejectsConcurrentAndUnsafeCandidates(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	if _, err := engine.Prepare(ctx, validCandidate()); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Prepare(ctx, validCandidate()); !errors.Is(err, ErrApplyInProgress) {
		t.Fatalf("concurrent Prepare() error = %v", err)
	}
	for _, candidate := range []Candidate{
		{InterfaceName: "bad/interface", OldLANCIDR: "192.168.200.1/24", NewLANCIDR: "192.168.210.1/24", OldURL: "https://192.168.200.1:8443", NewURL: "https://192.168.210.1:8443"},
		{InterfaceName: "enp2s0", OldLANCIDR: "192.168.200.1/24", NewLANCIDR: "192.168.200.2/24", OldURL: "https://192.168.200.1:8443", NewURL: "https://192.168.200.2:8443"},
		{InterfaceName: "enp2s0", OldLANCIDR: "192.168.200.1/24", NewLANCIDR: "8.8.8.1/24", OldURL: "https://192.168.200.1:8443", NewURL: "https://8.8.8.1:8443"},
		{InterfaceName: "enp2s0", OldLANCIDR: "192.168.200.1/24", NewLANCIDR: "192.168.210.1/24", OldURL: "https://192.168.200.1:8443", NewURL: "https://192.168.200.1:8443"},
	} {
		if _, _, err := validateCandidate(candidate); err == nil {
			t.Errorf("validateCandidate(%+v) error = nil", candidate)
		}
	}
}

func TestDiskStoreRejectsTamperedManifest(t *testing.T) {
	ctx, database := networkApplyDatabase(t)
	engine, _, _ := testEngine(t, database)
	prepared, err := engine.Prepare(ctx, validCandidate())
	if err != nil {
		t.Fatal(err)
	}
	directory, _ := engine.Store.Directory(prepared.ApplyID)
	manifestPath := filepath.Join(directory, "manifest.json")
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), "192.168.210.1", "192.168.211.1", 1))
	if err := os.WriteFile(manifestPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Store.Load(prepared.ApplyID); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("Load(tampered) error = %v", err)
	}
}

func validCandidate() Candidate {
	return Candidate{
		InterfaceName: "enp2s0",
		OldLANCIDR:    "192.168.200.1/24",
		NewLANCIDR:    "192.168.210.1/24",
		OldURL:        "https://192.168.200.1:8443",
		NewURL:        "https://192.168.210.1:8443",
	}
}

func testEngine(t *testing.T, database *sql.DB) (*Engine, *fakeBackend, *fakeTimer) {
	t.Helper()
	calls := []string{}
	backend := &fakeBackend{calls: &calls}
	timer := &fakeTimer{calls: &calls}
	store := DiskStore{Root: filepath.Join(t.TempDir(), "transactions")}
	engine := NewEngine(NewRepository(database), store, backend, timer)
	fixed := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	engine.Now = func() time.Time { return fixed }
	engine.Repository.now = engine.Now
	engine.Store.Now = engine.Now
	engine.NewSecret = func(length int) ([]byte, error) {
		value := byte(1)
		if length == 32 {
			value = 2
		}
		return []byte(strings.Repeat(string([]byte{value}), length)), nil
	}
	return engine, backend, timer
}

func networkApplyDatabase(t *testing.T) (context.Context, *sql.DB) {
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
