package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/auth"
	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/state"
)

type restoreApplyFixture struct {
	ctx               context.Context
	restorer          *RestoreManager
	applier           *RestoreApplier
	operation         RestoreOperation
	stateDirectory    string
	databasePath      string
	configurationPath string
}

func TestRestoreApplyCreatesSnapshotMigratesRevokesSessionsAndCommitsFailClosed(t *testing.T) {
	fixture := newRestoreApplyFixture(t)
	result, err := fixture.applier.Apply(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := databasepkg.LatestSchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if result.RestoreID != fixture.operation.RestoreID || result.SnapshotID != fixture.operation.SnapshotID || result.PreRestoreSnapshot == "" || result.SchemaVersion != latest || result.SessionsRevoked != 1 || !result.ReconcileRequired || result.AppliedAt == "" {
		t.Fatalf("restore apply result = %+v", result)
	}
	if _, pending, err := fixture.restorer.Status(); err != nil || pending {
		t.Fatalf("completed restore status = %t, %v", pending, err)
	}
	if _, err := os.Stat(filepath.Join(fixture.stateDirectory, "recovery", "last-restore.json")); err != nil {
		t.Fatalf("last restore record missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.stateDirectory, "mihomo", "active")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale Mihomo active path remains: %v", err)
	}
	for _, filename := range []string{
		filepath.Join(fixture.stateDirectory, "secrets", "restored.secret"),
		filepath.Join(fixture.stateDirectory, "subscriptions", "restored.yaml"),
		filepath.Join(fixture.stateDirectory, "tls", "cert.pem"),
		filepath.Join(fixture.stateDirectory, "mihomo", "generations", "gen-restored", "config.yaml"),
		filepath.Join(fixture.stateDirectory, "mihomo", "state", "active.json"),
	} {
		if _, err := os.Stat(filename); err != nil {
			t.Fatalf("restored file %s missing: %v", filename, err)
		}
	}
	if _, err := os.Stat(filepath.Join(fixture.stateDirectory, "secrets", "old.secret")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old secret survived exact restore: %v", err)
	}
	configuration := mustReadFile(t, fixture.configurationPath)
	if !strings.Contains(string(configuration), "lan_interface: enp2s0") || strings.Contains(string(configuration), "oldlan0") {
		t.Fatalf("activated restore configuration = %s", configuration)
	}

	database, err := databasepkg.Open(fixture.ctx, databasepkg.OpenOptions{Path: fixture.databasePath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var restoredMarker string
	var unrevoked, appliedAudits int
	if err := database.QueryRow("SELECT value_json FROM settings WHERE key='fixture-marker'").Scan(&restoredMarker); err != nil || restoredMarker != `"restored"` {
		t.Fatalf("restored database marker = %q, %v", restoredMarker, err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL").Scan(&unrevoked); err != nil || unrevoked != 0 {
		t.Fatalf("unrevoked restored sessions = %d, %v", unrevoked, err)
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM events WHERE type='RESTORE_APPLIED'").Scan(&appliedAudits); err != nil || appliedAudits != 1 {
		t.Fatalf("restore applied audits = %d, %v", appliedAudits, err)
	}
	runtimeState, err := state.NewRepository(database).Get(fixture.ctx)
	if err != nil || runtimeState.GatewayState != state.GatewayBlocked || runtimeState.PathState != state.PathBlocked || runtimeState.ActivePathID != "" {
		t.Fatalf("restored runtime state = %+v, %v", runtimeState, err)
	}

	preRestorePath := filepath.Join(fixture.stateDirectory, "backups", "snapshots", result.PreRestoreSnapshot, "state.db")
	preRestore, err := databasepkg.OpenImmutable(fixture.ctx, preRestorePath)
	if err != nil {
		t.Fatal(err)
	}
	defer preRestore.Close()
	var oldMarker string
	if err := preRestore.QueryRow("SELECT value_json FROM settings WHERE key='fixture-marker'").Scan(&oldMarker); err != nil || oldMarker != `"old"` {
		t.Fatalf("pre-restore snapshot marker = %q, %v", oldMarker, err)
	}
	if _, err := os.Stat(fixture.applier.journalPath(result.RestoreID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed restore journal remains: %v", err)
	}
}

func TestRestoreApplyFailureRollsBackEveryLivePathAndAllowsExplicitRetry(t *testing.T) {
	fixture := newRestoreApplyFixture(t)
	fixture.applier.AfterActivate = func(index int) error {
		if index == 4 {
			return errors.New("injected activation failure")
		}
		return nil
	}
	if _, err := fixture.applier.Apply(fixture.ctx); err == nil || !strings.Contains(err.Error(), "injected activation failure") {
		t.Fatalf("failed restore Apply() error = %v", err)
	}
	operation, pending, err := fixture.restorer.Status()
	if err != nil || !pending || operation.ApplyErrorCode != "RESTORE_APPLY_FAILED_ROLLED_BACK" {
		t.Fatalf("rolled-back restore status = %+v, %t, %v", operation, pending, err)
	}
	assertOldRestoreFixtureLive(t, fixture)
	if _, err := os.Stat(fixture.applier.journalPath(operation.RestoreID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back journal remains: %v", err)
	}
	fixture.applier.AfterActivate = nil
	if _, err := fixture.applier.Apply(fixture.ctx); err != nil {
		t.Fatalf("explicit restore retry failed: %v", err)
	}
}

func TestRestoreApplyRecoversPowerLossJournalBeforeRequiringRetry(t *testing.T) {
	fixture := newRestoreApplyFixture(t)
	verified, err := fixture.restorer.VerifyPending(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	items := fixture.applier.restoreItems(verified)
	preRestore, err := fixture.applier.createPreRestoreSnapshot(fixture.ctx, verified.Operation.RestoreID)
	if err != nil {
		t.Fatal(err)
	}
	result := RestoreApplyResult{RestoreID: verified.Operation.RestoreID, SnapshotID: verified.Operation.SnapshotID, PreRestoreSnapshot: preRestore.Manifest.SnapshotID, ReconcileRequired: true}
	if err := fixture.applier.prepareCandidates(fixture.ctx, verified, items, &result); err != nil {
		t.Fatal(err)
	}
	journal := restoreApplyJournal{FormatVersion: restoreApplyJournalVersion, RestoreID: verified.Operation.RestoreID, State: restoreApplyApplying, Items: items, Result: result}
	journalPath := fixture.applier.journalPath(verified.Operation.RestoreID)
	if err := fixture.applier.writeJournal(journalPath, journal, false); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		if err := fixture.applier.activateItem(items[index]); err != nil {
			t.Fatal(err)
		}
		journal.AppliedItems = index + 1
		if err := fixture.applier.writeJournal(journalPath, journal, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.applier.Apply(fixture.ctx); err == nil || !strings.Contains(err.Error(), "explicit retry is required") {
		t.Fatalf("power-loss recovery Apply() error = %v", err)
	}
	operation, pending, err := fixture.restorer.Status()
	if err != nil || !pending || operation.ApplyErrorCode != "RESTORE_INTERRUPTED_ROLLED_BACK" {
		t.Fatalf("power-loss recovered status = %+v, %t, %v", operation, pending, err)
	}
	assertOldRestoreFixtureLive(t, fixture)
	if _, err := fixture.applier.Apply(fixture.ctx); err != nil {
		t.Fatalf("restore after recovered power loss failed: %v", err)
	}
}

func TestVerifyPendingRejectsTreeAndManifestTampering(t *testing.T) {
	fixture := newRestoreApplyFixture(t)
	secret := filepath.Join(fixture.restorer.Root, fixture.operation.RestoreID, "tree", "state", "secrets", "restored.secret")
	original := mustReadFile(t, secret)
	if err := os.WriteFile(secret, []byte(strings.Repeat("x", len(original))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.restorer.VerifyPending(fixture.ctx); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered restore tree verification error = %v", err)
	}
	if err := os.WriteFile(secret, original, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(fixture.restorer.Root, fixture.operation.RestoreID, "portable-manifest.json")
	content := append(mustReadFile(t, manifest), []byte(`{"trailing":true}`)...)
	if err := os.WriteFile(manifest, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.restorer.VerifyPending(fixture.ctx); err == nil || !strings.Contains(err.Error(), "manifest contract") {
		t.Fatalf("trailing manifest verification error = %v", err)
	}
}

func newRestoreApplyFixture(t *testing.T) restoreApplyFixture {
	t.Helper()
	ctx, sourceDatabase, snapshots := snapshotTestManager(t)
	authService := auth.Service{Database: sourceDatabase, Parameters: auth.Argon2Parameters{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}}
	if _, err := authService.CreateBootstrapAdmin(ctx, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if _, err := authService.Login(ctx, "admin", "correct horse battery staple", "restore-fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceDatabase.ExecContext(ctx, "INSERT INTO settings(key, value_json, updated_at) VALUES ('fixture-marker', ?, ?)", `"restored"`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	sourceState := filepath.Dir(snapshots.DatabasePath)
	writeFixtureFile(t, filepath.Join(sourceState, "secrets", "restored.secret"), "restored-secret")
	writeFixtureFile(t, filepath.Join(sourceState, "secrets", "mihomo-api-secret"), "restored-mihomo-api-secret")
	writeFixtureFile(t, filepath.Join(sourceState, "subscriptions", "restored.yaml"), "proxies: []")
	writeFixtureFile(t, filepath.Join(sourceState, "tls", "cert.pem"), "restored-cert")
	writeFixtureFile(t, filepath.Join(sourceState, "tls", "key.pem"), "restored-key")
	writeFixtureFile(t, filepath.Join(sourceState, "mihomo", "generations", "gen-restored", "config.yaml"), "mixed-port: 7890")
	writeFixtureFile(t, filepath.Join(sourceState, "mihomo", "state", "active.json"), `{"generation":"gen-restored"}`)
	sourceConfiguration := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(sourceConfiguration, []byte(validRestoreConfig()), 0o600); err != nil {
		t.Fatal(err)
	}
	portable, err := NewPortableManager(snapshots, sourceState, sourceConfiguration, "gateway-vpn restore-apply-test")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := portable.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = portable.Remove(artifact) })

	stateDirectory := t.TempDir()
	databasePath := filepath.Join(stateDirectory, "state.db")
	configurationDirectory := t.TempDir()
	configurationPath := filepath.Join(configurationDirectory, "config.yaml")
	oldConfiguration := strings.Replace(validRestoreConfig(), "lan_interface: enp2s0", "lan_interface: oldlan0", 1)
	if err := os.WriteFile(configurationPath, []byte(oldConfiguration), 0o600); err != nil {
		t.Fatal(err)
	}
	liveDatabase, err := databasepkg.Open(ctx, databasepkg.OpenOptions{Path: databasePath})
	if err != nil {
		t.Fatal(err)
	}
	if err := databasepkg.Migrate(ctx, liveDatabase); err != nil {
		t.Fatal(err)
	}
	if _, err := liveDatabase.ExecContext(ctx, "INSERT INTO settings(key, value_json, updated_at) VALUES ('fixture-marker', ?, ?)", `"old"`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := liveDatabase.Close(); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(stateDirectory, "secrets", "old.secret"), "old-secret")
	writeFixtureFile(t, filepath.Join(stateDirectory, "subscriptions", "old.yaml"), "old")
	writeFixtureFile(t, filepath.Join(stateDirectory, "tls", "old.pem"), "old")
	writeFixtureFile(t, filepath.Join(stateDirectory, "mihomo", "generations", "gen-old", "config.yaml"), "old")
	writeFixtureFile(t, filepath.Join(stateDirectory, "mihomo", "state", "active.json"), `{"generation":"gen-old"}`)
	writeFixtureFile(t, filepath.Join(stateDirectory, "mihomo", "active", "config.yaml"), "stale-active")

	restorer, err := NewRestoreManager(stateDirectory, databasePath, configurationPath)
	if err != nil {
		t.Fatal(err)
	}
	restorer.ExpectedStateDirectory = "/var/lib/gateway-vpn"
	restorer.ExpectedDatabasePath = "/var/lib/gateway-vpn/state.db"
	restorer.ExpectedMihomoBinary = "/opt/gateway-vpn/current/libexec/mihomo"
	restorer.ExpectedAPISecretPath = "/var/lib/gateway-vpn/secrets/mihomo-api-secret"
	restorer.ExpectedTLSCertPath = "/var/lib/gateway-vpn/tls/cert.pem"
	restorer.ExpectedTLSKeyPath = "/var/lib/gateway-vpn/tls/key.pem"
	reader, err := portable.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	operation, stageErr := restorer.Stage(ctx, reader, "correct horse battery staple")
	reader.Close()
	if stageErr != nil {
		t.Fatal(stageErr)
	}
	applier, err := NewRestoreApplier(restorer, filepath.Join(stateDirectory, "restore-transactions"), -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	// Unit tests exercise the ownership plan without requiring a root test
	// process. Production constructors retain the real root/chown functions;
	// the root netns/host gate validates those privileged boundaries.
	applier.validateOwner = func(os.FileInfo) error { return nil }
	applier.setOwnership = func(string, int, int) error { return nil }
	applier.Now = func() time.Time { return time.Date(2026, 8, 24, 20, 0, 0, 0, time.UTC) }
	return restoreApplyFixture{ctx: ctx, restorer: restorer, applier: applier, operation: operation, stateDirectory: stateDirectory, databasePath: databasePath, configurationPath: configurationPath}
}

func assertOldRestoreFixtureLive(t *testing.T, fixture restoreApplyFixture) {
	t.Helper()
	configuration := string(mustReadFile(t, fixture.configurationPath))
	if !strings.Contains(configuration, "lan_interface: oldlan0") {
		t.Fatalf("old configuration was not rolled back: %s", configuration)
	}
	for _, filename := range []string{
		filepath.Join(fixture.stateDirectory, "secrets", "old.secret"),
		filepath.Join(fixture.stateDirectory, "subscriptions", "old.yaml"),
		filepath.Join(fixture.stateDirectory, "tls", "old.pem"),
		filepath.Join(fixture.stateDirectory, "mihomo", "generations", "gen-old", "config.yaml"),
		filepath.Join(fixture.stateDirectory, "mihomo", "state", "active.json"),
		filepath.Join(fixture.stateDirectory, "mihomo", "active", "config.yaml"),
	} {
		if _, err := os.Stat(filename); err != nil {
			t.Fatalf("rolled-back live file %s missing: %v", filename, err)
		}
	}
	database, err := databasepkg.Open(fixture.ctx, databasepkg.OpenOptions{Path: fixture.databasePath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var marker string
	if err := database.QueryRow("SELECT value_json FROM settings WHERE key='fixture-marker'").Scan(&marker); err != nil || marker != `"old"` {
		t.Fatalf("rolled-back database marker = %q, %v", marker, err)
	}
	runtimeState, err := state.NewRepository(database).Get(fixture.ctx)
	if err != nil || runtimeState.GatewayState != state.GatewayBlocked || runtimeState.PathState != state.PathBlocked {
		t.Fatalf("rolled-back runtime is not safely blocked = %+v, %v", runtimeState, err)
	}
}

func writeFixtureFile(t *testing.T, filename, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
