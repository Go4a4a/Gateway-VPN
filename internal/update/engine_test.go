package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
)

func TestUpdateEngineAppliesSignedCandidateAndFinalizesAfterWindow(t *testing.T) {
	fixture := newEngineFixture(t)
	result, err := fixture.engine.Apply(context.Background(), fixture.operation.UpdateID)
	if err != nil {
		t.Fatal(err)
	}
	if result.OldVersion != "1.1.0" || result.NewVersion != "1.2.0" || result.State != string(StateStabilizing) || result.PreUpdateSnapshot == "" || !result.StagingCleaned {
		t.Fatalf("Apply() = %+v", result)
	}
	if target := readCurrentTarget(t, fixture.releaseRoot); target != "releases/v1.2.0" {
		t.Fatalf("current target = %q", target)
	}
	if target := readReleaseTarget(t, fixture.releaseRoot, "recovery"); target != "releases/v1.1.0" {
		t.Fatalf("recovery target = %q", target)
	}
	journal, exists, err := fixture.engine.Store.LoadActive()
	if err != nil || !exists || journal.State != StateStabilizing || journal.OldSchemaVersion != 16 || journal.NewSchemaVersion != 16 || journal.CandidateDBSHA256 == "" {
		t.Fatalf("active journal = %+v,%v,%v", journal, exists, err)
	}
	if _, exists, err := fixture.stager.Status(); err != nil || exists {
		t.Fatalf("staging after successful apply = %v,%v", exists, err)
	}
	fixture.clock = fixture.clock.Add(2 * time.Hour)
	finalized, err := fixture.engine.Finalize(context.Background())
	if err != nil || finalized.State != StateFinalized {
		t.Fatalf("Finalize() = %+v,%v", finalized, err)
	}
	if _, err := os.Stat(filepath.Join(fixture.releaseRoot, "releases", "v1.1.0", ReleaseFilename)); err != nil {
		t.Fatalf("previous release was not retained: %v", err)
	}
	if target := readReleaseTarget(t, fixture.releaseRoot, "recovery"); target != "releases/v1.2.0" {
		t.Fatalf("recovery target after finalization = %q", target)
	}
}

func TestUpdateEngineHealthFailureRestoresOldBinaryAndSnapshot(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.runtime.failVersion = "1.2.0"
	fixture.runtime.mutateFailedLive = true
	if _, err := fixture.engine.Apply(context.Background(), fixture.operation.UpdateID); err == nil {
		t.Fatal("candidate health failure unexpectedly succeeded")
	}
	if target := readCurrentTarget(t, fixture.releaseRoot); target != "releases/v1.1.0" {
		t.Fatalf("current after rollback = %q", target)
	}
	journal, exists, err := fixture.engine.Store.LoadActive()
	if err != nil || !exists || journal.State != StateRolledBack || journal.ErrorCode != "NEW_RELEASE_HEALTH_FAILED" {
		t.Fatalf("rollback journal = %+v,%v,%v", journal, exists, err)
	}
	assertEventCount(t, fixture.databasePath, "BEFORE_UPDATE", 1)
	assertEventCount(t, fixture.databasePath, "FAILED_CANDIDATE_WRITE", 0)
	if fixture.runtime.started[len(fixture.runtime.started)-1] != "1.1.0" {
		t.Fatalf("old runtime was not restarted: %+v", fixture.runtime.started)
	}
}

func TestUpdateEngineRejectsDifferentExistingArtifactWithSameVersion(t *testing.T) {
	fixture := newEngineFixture(t)
	otherRoot, _, _ := unsignedReleaseFixture(t, "1.2.0", 1, 16)
	if err := os.WriteFile(filepath.Join(otherRoot, "bin", "gateway-vpn"), []byte("different signed candidate"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Re-sign the different artifact with the same trusted key. This models a
	// rebuilt release that accidentally reused a version number.
	if _, err := SignRelease(otherRoot, fixture.signingKey); err != nil {
		t.Fatal(err)
	}
	otherVerified, err := VerifyRelease(otherRoot, fixture.stager.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.engine.installRelease(otherVerified); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.engine.Apply(context.Background(), fixture.operation.UpdateID); err == nil || !strings.Contains(err.Error(), "not the same verified artifact") {
		t.Fatalf("same-version rebuild was not rejected: %v", err)
	}
	if target := readCurrentTarget(t, fixture.releaseRoot); target != "releases/v1.1.0" {
		t.Fatalf("current changed after rejecting ambiguous artifact: %q", target)
	}
}

func TestUpdateEngineDiscardsInterruptedReleaseCopyAndRetries(t *testing.T) {
	fixture := newEngineFixture(t)
	stagedRoot, err := fixture.stager.ReleaseRoot(fixture.operation.UpdateID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRelease(stagedRoot, fixture.stager.Policy)
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(fixture.releaseRoot, "releases", ".v1.2.0-"+verified.Manifest.ReleaseJSONSHA256[:12])
	if err := os.MkdirAll(filepath.Join(temporary, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(temporary, "bin", "gateway-vpn"), []byte("partial copy"), 0o755); err != nil {
		t.Fatal(err)
	}
	installed, err := fixture.engine.installRelease(verified)
	if err != nil {
		t.Fatal(err)
	}
	if installed != filepath.Join(fixture.releaseRoot, "releases", "v1.2.0") {
		t.Fatalf("installed path = %q", installed)
	}
	if _, err := VerifyRelease(installed, fixture.stager.Policy); err != nil {
		t.Fatalf("retried candidate does not verify: %v", err)
	}
}

func TestUpdateEnginePowerLossAfterDatabaseSwitchRecoversOldPair(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.runtime.mutateCandidate = true
	fixture.engine.AfterState = func(state TransactionState) error {
		if state == StateDatabaseSwitched {
			return errors.New("simulated power loss")
		}
		return nil
	}
	if _, err := fixture.engine.Apply(context.Background(), fixture.operation.UpdateID); !errors.Is(err, errInjectedInterruption) {
		t.Fatalf("interrupted Apply() error = %v", err)
	}
	if target := readCurrentTarget(t, fixture.releaseRoot); target != "releases/v1.1.0" {
		t.Fatalf("release switched before injected crash: %q", target)
	}
	assertEventCount(t, fixture.databasePath, "CANDIDATE_ONLY", 1)
	fixture.engine.AfterState = nil
	recovered, err := fixture.engine.Recover(context.Background())
	if err != nil || !recovered {
		t.Fatalf("Recover() = %v,%v", recovered, err)
	}
	if target := readCurrentTarget(t, fixture.releaseRoot); target != "releases/v1.1.0" {
		t.Fatalf("current after recovery = %q", target)
	}
	assertEventCount(t, fixture.databasePath, "BEFORE_UPDATE", 1)
	assertEventCount(t, fixture.databasePath, "CANDIDATE_ONLY", 0)
	journal, _, _ := fixture.engine.Store.LoadActive()
	if journal.State != StateRolledBack || journal.ErrorCode != "BOOT_OR_PROCESS_RECOVERY" {
		t.Fatalf("recovered journal = %+v", journal)
	}
}

func TestUpdateEngineRecoveryRollsBackUnhealthyStabilizingRelease(t *testing.T) {
	fixture := newEngineFixture(t)
	if _, err := fixture.engine.Apply(context.Background(), fixture.operation.UpdateID); err != nil {
		t.Fatal(err)
	}
	fixture.runtime.failVersion = "1.2.0"
	recovered, err := fixture.engine.Recover(context.Background())
	if err != nil || !recovered {
		t.Fatalf("Recover() = %v,%v", recovered, err)
	}
	if target := readCurrentTarget(t, fixture.releaseRoot); target != "releases/v1.1.0" {
		t.Fatalf("current after stabilizing rollback = %q", target)
	}
	journal, exists, err := fixture.engine.Store.LoadActive()
	if err != nil || !exists || journal.State != StateRolledBack || journal.ErrorCode != "STABILIZING_RECOVERY_HEALTH_FAILED" {
		t.Fatalf("stabilizing recovery journal = %+v,%v,%v", journal, exists, err)
	}
}

func TestUpdateJournalRecoversStabilizingTransactionWithoutActivePointer(t *testing.T) {
	fixture := newEngineFixture(t)
	if _, err := fixture.engine.Apply(context.Background(), fixture.operation.UpdateID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(fixture.engine.Store.Root, "active.json")); err != nil {
		t.Fatal(err)
	}
	journal, exists, err := fixture.engine.Store.LoadActive()
	if err != nil || !exists || journal.State != StateStabilizing || journal.UpdateID != fixture.operation.UpdateID {
		t.Fatalf("recovered stabilizing journal = %+v,%v,%v", journal, exists, err)
	}
}

func TestUpdateFinalizeChecksHealthBeforeStabilityDeadline(t *testing.T) {
	fixture := newEngineFixture(t)
	if _, err := fixture.engine.Apply(context.Background(), fixture.operation.UpdateID); err != nil {
		t.Fatal(err)
	}
	fixture.runtime.failVersion = "1.2.0"
	if _, err := fixture.engine.Finalize(context.Background()); err == nil || errors.Is(err, ErrStabilityWindowActive) {
		t.Fatalf("Finalize() did not reject unhealthy release during window: %v", err)
	}
	if target := readCurrentTarget(t, fixture.releaseRoot); target != "releases/v1.1.0" {
		t.Fatalf("current after early watchdog rollback = %q", target)
	}
}

func TestUpdateFinalizeIsSuccessfulNoopWithoutPendingTransaction(t *testing.T) {
	fixture := newEngineFixture(t)
	journal, err := fixture.engine.Finalize(context.Background())
	if !errors.Is(err, ErrNoFinalizationPending) || journal.UpdateID != "" {
		t.Fatalf("Finalize() without transaction = %+v,%v", journal, err)
	}
}

func TestUpdateFinalizeIsSuccessfulNoopAfterRollback(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.runtime.failVersion = "1.2.0"
	if _, err := fixture.engine.Apply(context.Background(), fixture.operation.UpdateID); err == nil {
		t.Fatal("candidate health failure unexpectedly succeeded")
	}
	journal, err := fixture.engine.Finalize(context.Background())
	if !errors.Is(err, ErrNoFinalizationPending) || journal.State != StateRolledBack {
		t.Fatalf("Finalize() after rollback = %+v,%v", journal, err)
	}
}

func TestUpdateJournalUsesRedundantCopyAndRejectsChecksumWhenBothAreCorrupt(t *testing.T) {
	root := t.TempDir()
	store := JournalStore{Root: root}
	now := time.Date(2026, 8, 24, 22, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	journal := Journal{
		FormatVersion: JournalFormatVersion, UpdateID: "update-20260824T220000Z-0123456789abcdef01234567",
		State: StatePrepared, StartedAt: now, UpdatedAt: now,
		OldVersion: "1.1.0", NewVersion: "1.2.0", OldCurrentTarget: "releases/v1.1.0", NewCurrentTarget: "releases/v1.2.0",
	}
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(root, "active.json")
	content, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	index := bytes.Index(content, []byte(`"PREPARED"`))
	if index < 0 {
		t.Fatal("journal state not found")
	}
	content[index+1] = 'X'
	if err := os.WriteFile(active, content, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := store.LoadActive()
	if err != nil || !exists || loaded.UpdateID != journal.UpdateID {
		t.Fatalf("valid transaction copy did not recover tampered active pointer: %+v,%v,%v", loaded, exists, err)
	}
	transactionJournal := filepath.Join(root, journal.UpdateID, "journal.json")
	if err := os.WriteFile(transactionJournal, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadActive(); err == nil {
		t.Fatal("two tampered update journal copies were accepted")
	}
}

func TestUpdateJournalPrefersDurableTransactionStateOverStaleActivePointer(t *testing.T) {
	root := t.TempDir()
	store := JournalStore{Root: root}
	now := time.Date(2026, 8, 24, 22, 0, 0, 0, time.UTC)
	journal := Journal{
		FormatVersion: JournalFormatVersion, UpdateID: "update-20260824T220000Z-1123456789abcdef01234567",
		State: StatePrepared, StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
		OldVersion: "1.1.0", NewVersion: "1.2.0", OldCurrentTarget: "releases/v1.1.0", NewCurrentTarget: "releases/v1.2.0",
	}
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	staleActive, err := os.ReadFile(filepath.Join(root, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	journal.UpdatedAt = now.Add(time.Second).Format(time.RFC3339Nano)
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "active.json"), staleActive, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := store.LoadActive()
	if err != nil || !exists || loaded.UpdatedAt != journal.UpdatedAt {
		t.Fatalf("LoadActive() = %+v,%v,%v", loaded, exists, err)
	}
}

func TestUpdateEngineRejectsConcurrentTransactionProcess(t *testing.T) {
	fixture := newEngineFixture(t)
	unlock, err := acquireTransactionLock(fixture.engine.Store.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := fixture.engine.Recover(context.Background()); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("Recover() concurrent error = %v", err)
	}
}

type engineFixture struct {
	engine       *Engine
	stager       *Stager
	runtime      *fakeUpdateRuntime
	operation    Operation
	releaseRoot  string
	stateDir     string
	databasePath string
	configPath   string
	clock        time.Time
	signingKey   ed25519.PrivateKey
}

func newEngineFixture(t *testing.T) *engineFixture {
	t.Helper()
	ctx := context.Background()
	stateDir := t.TempDir()
	databasePath := filepath.Join(stateDir, "state.db")
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, database); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES('2026-08-24T21:30:00Z','INFO','BEFORE_UPDATE','{}')`); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeDatabaseSidecars(databasePath); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(testBootstrapConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	newRelease, publicKey, signingKey := signedReleaseFixture(t, "1.2.0", 1, 16)
	keyPath := writePublicKeyFixture(t, stateDir, publicKey)
	policy := fixturePolicy(publicKey)
	policy.CurrentSchemaVersion = 16
	newReleaseMetadata, err := ReadReleaseMetadata(newRelease)
	if err != nil {
		t.Fatal(err)
	}
	policy.CurrentHostContractSHA256 = newReleaseMetadata.HostContractSHA256
	stager, err := NewStager(stateDir, keyPath, policy)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 24, 22, 0, 0, 0, time.UTC)
	stager.Now = func() time.Time { return clock }
	operation, err := stager.Stage(ctx, bytes.NewReader(releaseArchive(t, newRelease, nil)))
	if err != nil {
		t.Fatal(err)
	}
	releaseRoot := filepath.Join(t.TempDir(), "gateway-vpn")
	oldFixture, _, _ := unsignedReleaseFixture(t, "1.1.0", 1, 16)
	oldRoot := filepath.Join(releaseRoot, "releases", "v1.1.0")
	if err := os.MkdirAll(oldRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyExclusiveFile(filepath.Join(oldFixture, ReleaseFilename), filepath.Join(oldRoot, ReleaseFilename), 0o644, MaximumReleaseBytes); err != nil {
		t.Fatal(err)
	}
	for _, relative := range requiredHostContractFiles {
		destination := filepath.Join(oldRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := copyExclusiveFile(filepath.Join(oldFixture, filepath.FromSlash(relative)), destination, 0o644, MaximumReleaseBytes); err != nil {
			t.Fatal(err)
		}
	}
	if err := createCurrentLink(filepath.Join(releaseRoot, "current"), filepath.FromSlash("releases/v1.1.0")); err != nil {
		t.Fatalf("create current release symlink: %v", err)
	}
	runtime := &fakeUpdateRuntime{databasePath: databasePath}
	fixture := &engineFixture{
		stager: stager, runtime: runtime, operation: operation, releaseRoot: releaseRoot,
		stateDir: stateDir, databasePath: databasePath, configPath: configPath, clock: clock, signingKey: signingKey,
	}
	fixture.engine = &Engine{
		Stager: stager, Store: JournalStore{Root: filepath.Join(t.TempDir(), "gateway-vpn-privileged", "update-transactions")}, Runtime: runtime,
		ReleaseRoot: releaseRoot, StateDir: stateDir, DatabasePath: databasePath, ConfigPath: configPath,
		CurrentVersion: "1.1.0", StateUID: 0, StateGID: 0, StabilityWindow: time.Hour,
		Now:          func() time.Time { return fixture.clock },
		setOwnership: func(string, int, int) error { return nil },
	}
	return fixture
}

type fakeUpdateRuntime struct {
	databasePath     string
	quiesced         int
	started          []string
	failVersion      string
	mutateCandidate  bool
	mutateFailedLive bool
}

func (runtime *fakeUpdateRuntime) Quiesce(context.Context) error {
	runtime.quiesced++
	return nil
}

func (runtime *fakeUpdateRuntime) Observe(context.Context) (ManagedRuntimeState, error) {
	return ManagedRuntimeState{}, nil
}

func (runtime *fakeUpdateRuntime) OfflineCheck(ctx context.Context, _ string, databasePath, configPath, _, _ string, schema int64) (OfflineResult, error) {
	result, err := CheckCandidateDatabase(ctx, databasePath, configPath, schema)
	if err != nil || !runtime.mutateCandidate {
		return result, err
	}
	database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		return OfflineResult{}, err
	}
	_, err = database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES('2026-08-24T22:01:00Z','INFO','CANDIDATE_ONLY','{}')`)
	if _, checkpointErr := database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err == nil {
		err = checkpointErr
	}
	closeErr := database.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return OfflineResult{}, err
	}
	if err := removeDatabaseSidecars(databasePath); err != nil {
		return OfflineResult{}, err
	}
	return CheckCandidateDatabase(ctx, databasePath, configPath, schema)
}

func (runtime *fakeUpdateRuntime) StartAndHealth(ctx context.Context, version, databasePath string, _ ManagedRuntimeState) error {
	runtime.started = append(runtime.started, version)
	if version == runtime.failVersion {
		if runtime.mutateFailedLive {
			database, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
			if err == nil {
				_, _ = database.ExecContext(ctx, `INSERT INTO events(occurred_at,severity,type,details_json) VALUES('2026-08-24T22:02:00Z','WARNING','FAILED_CANDIDATE_WRITE','{}')`)
				_, _ = database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
				_ = database.Close()
				_ = removeDatabaseSidecars(databasePath)
			}
		}
		return errors.New("candidate did not become healthy")
	}
	return nil
}

func readCurrentTarget(t *testing.T, root string) string {
	return readReleaseTarget(t, root, "current")
}

func readReleaseTarget(t *testing.T, root, name string) string {
	t.Helper()
	target, err := readCurrentLink(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(target)
}

func assertEventCount(t *testing.T, databasePath, eventType string, expected int) {
	t.Helper()
	database, err := databasepkg.OpenImmutable(context.Background(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM events WHERE type=?", eventType).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("event %s count = %d, want %d", eventType, count, expected)
	}
}

const testBootstrapConfig = `version: 1
system:
  state_dir: /var/lib/gateway-vpn
  database: /var/lib/gateway-vpn/state.db
  log_level: INFO
network:
  lan_interface: enp2s0
  lan_address: 192.168.200.1/24
  ipv6_mode: disabled
modems:
  type: hilink
  auto_discover: true
  require_adoption: true
  require_unique_management_subnets: true
  routing_table_start: 1101
  fwmark_start: 4353
mihomo:
  binary: /opt/gateway-vpn/current/libexec/mihomo
  tun_name: gateway-vpn-tun
  stack: mixed
  api_address: 127.0.0.1:9090
  probe_address: 127.0.0.1:17890
  api_secret_file: /var/lib/gateway-vpn/secrets/mihomo-api-secret
  bootstrap_dns: [1.1.1.1]
  transport_probe_url: https://cp.cloudflare.com/generate_204
  transport_probe_timeout_seconds: 8
  transport_expected_status: "204"
api:
  listen: [192.168.200.1:8443, 10.80.0.2:8443]
  tls_cert: /var/lib/gateway-vpn/tls/cert.pem
  tls_key: /var/lib/gateway-vpn/tls/key.pem
`
