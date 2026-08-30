package vpsbackup

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

func TestVPSRestoreApplySameIdentitySnapshotsQuarantinesAndCommits(t *testing.T) {
	ctx := context.Background()
	backupManager, database, stateDirectory := vpsBackupFixture(t)
	peerKey := testPeerKey(t)
	if _, err := database.ExecContext(ctx, `
INSERT INTO gateway_peers(id,site_id,display_name,public_key,assigned_subnet,assigned_address,remote_address,state,created_at,updated_at)
VALUES('peer:one','site:one','Gateway One',?,'10.88.0.0/30','10.88.0.1','10.88.0.2','ACTIVE','now','now')`, peerKey); err != nil {
		t.Fatal(err)
	}
	artifact, err := backupManager.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	liveConfiguration := "version: 1\nlisten: 127.0.0.1:9444\n# live-before-restore\n"
	if err := os.WriteFile(backupManager.ConfigurationPath, []byte(liveConfiguration), 0o600); err != nil {
		t.Fatal(err)
	}
	insertTestSession(t, database, "live-session-before-restore")
	restoreManager, operation := stageArtifactAndAuthorize(t, backupManager, artifact, database, stateDirectory, RestoreModeSameVPS)
	applier, err := NewRestoreApplier(restoreManager, filepath.Join(t.TempDir(), "transactions"), -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	applier.Now = func() time.Time { return time.Date(2026, 8, 30, 20, 0, 0, 0, time.UTC) }
	result, err := applier.Apply(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.RestoreID != operation.RestoreID || result.Mode != RestoreModeSameVPS || result.VPSID != "vps:primary" || !result.Quarantined || !result.ReconcileRequired || result.PreRestoreSnapshot == "" {
		t.Fatalf("Apply() = %+v", result)
	}
	activeConfiguration, err := os.ReadFile(backupManager.ConfigurationPath)
	if err != nil || strings.Contains(string(activeConfiguration), "live-before-restore") || !strings.Contains(string(activeConfiguration), "127.0.0.1:9443") {
		t.Fatalf("restored config = %q, %v", activeConfiguration, err)
	}
	snapshotConfiguration, err := os.ReadFile(filepath.Join(result.PreRestoreSnapshot, "config", "config.yaml"))
	if err != nil || string(snapshotConfiguration) != liveConfiguration {
		t.Fatalf("pre-restore snapshot config = %q, %v", snapshotConfiguration, err)
	}
	liveDatabase, err := databasepkg.OpenImmutable(ctx, filepath.Join(stateDirectory, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer liveDatabase.Close()
	var peerState string
	if err := liveDatabase.QueryRowContext(ctx, "SELECT state FROM gateway_peers WHERE id='peer:one'").Scan(&peerState); err != nil || peerState != "QUARANTINED" {
		t.Fatalf("restored peer state = %q, %v", peerState, err)
	}
	var sessionCount int
	if err := liveDatabase.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions").Scan(&sessionCount); err != nil || sessionCount != 0 {
		t.Fatalf("restored session count = %d, %v", sessionCount, err)
	}
	if _, exists, err := restoreManager.Status(); err != nil || exists {
		t.Fatalf("completed restore remains pending: exists=%t error=%v", exists, err)
	}
	if _, err := os.Stat(filepath.Join(stateDirectory, "recovery", "last-vps-restore.json")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(applier.TransactionRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("completed restore journals = %v, %v", entries, err)
	}
}

func TestVPSRestoreImportAsNewRegeneratesIdentityKeysTLSAndClearsTopology(t *testing.T) {
	ctx := context.Background()
	backupManager, database, stateDirectory := vpsBackupFixture(t)
	adminKeys, err := vpsagent.NewAdminKeyManager(database, stateDirectory, backupManager.Now)
	if err != nil {
		t.Fatal(err)
	}
	managedAdmin, err := adminKeys.Create(ctx, "Source administrator", "10.81.0.50")
	if err != nil || managedAdmin.ConfigState != "AVAILABLE" {
		t.Fatalf("create source managed administrator = %+v, %v", managedAdmin, err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO gateway_peers(id,site_id,display_name,public_key,assigned_subnet,assigned_address,remote_address,state,created_at,updated_at)
VALUES('peer:source','site:source','Source Gateway',?,'10.89.0.0/30','10.89.0.1','10.89.0.2','ACTIVE','now','now')`, testPeerKey(t)); err != nil {
		t.Fatal(err)
	}
	artifact, err := backupManager.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	originalPrivate, _ := os.ReadFile(filepath.Join(stateDirectory, "secrets", "wireguard", "server.key"))
	originalUpdate, _ := os.ReadFile(filepath.Join(stateDirectory, "secrets", "update", "identity.key"))
	originalTLS, _ := os.ReadFile(filepath.Join(stateDirectory, "tls", "key.pem"))
	restoreManager, operation := stageArtifactAndAuthorize(t, backupManager, artifact, database, stateDirectory, RestoreModeNewVPS)
	applier, err := NewRestoreApplier(restoreManager, filepath.Join(t.TempDir(), "transactions"), -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	result, err := applier.Apply(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.RestoreID != operation.RestoreID || result.Mode != RestoreModeNewVPS || result.VPSID == "vps:primary" || result.IdentityFingerprint == strings.Repeat("a", 64) || result.Quarantined || !result.ReconcileRequired {
		t.Fatalf("new VPS Apply() = %+v", result)
	}
	for path, original := range map[string][]byte{
		filepath.Join(stateDirectory, "secrets", "wireguard", "server.key"): originalPrivate,
		filepath.Join(stateDirectory, "secrets", "update", "identity.key"):  originalUpdate,
		filepath.Join(stateDirectory, "tls", "key.pem"):                     originalTLS,
	} {
		content, err := os.ReadFile(path)
		if err != nil || string(content) == string(original) {
			t.Fatalf("imported identity file %s was not regenerated: %v", path, err)
		}
	}
	certificatePEM, err := os.ReadFile(filepath.Join(stateDirectory, "tls", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		t.Fatal("imported VPS certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !strings.Contains(certificate.Subject.CommonName, result.VPSID) {
		t.Fatalf("imported certificate = %+v, %v", certificate, err)
	}
	liveDatabase, err := databasepkg.OpenImmutable(ctx, filepath.Join(stateDirectory, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer liveDatabase.Close()
	identity, err := vpsagent.ReadIdentity(ctx, liveDatabase)
	if err != nil || identity.VPSID != result.VPSID || identity.IdentityFingerprint != result.IdentityFingerprint {
		t.Fatalf("new live identity = %+v, %v", identity, err)
	}
	if err := verifyImportedWireGuardConfig(filepath.Join(stateDirectory, "wg-mgmt.conf"), identity.PublicKey); err != nil {
		t.Fatal(err)
	}
	wireGuardConfiguration, err := os.ReadFile(filepath.Join(stateDirectory, "wg-mgmt.conf"))
	if err != nil || strings.Contains(string(wireGuardConfiguration), "[Peer]") {
		t.Fatalf("imported VPS retained stale WireGuard peers: %q, %v", wireGuardConfiguration, err)
	}
	for _, table := range []string{"gateway_peers", "admin_peers", "prefix_allocations", "resource_publications", "acl_grants", "sessions", "pairing_invitations"} {
		var count int
		if err := liveDatabase.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("imported VPS table %s count = %d, %v", table, count, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(stateDirectory, "secrets", "administrators")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("import-as-new retained source administrator private keys: %v", err)
	}
}

func TestVPSRestoreApplyFailureRollsBackLiveStateAndRequiresFreshAuthorization(t *testing.T) {
	ctx := context.Background()
	backupManager, database, stateDirectory := vpsBackupFixture(t)
	artifact, err := backupManager.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	liveConfiguration := "version: 1\n# must-survive-rollback\n"
	if err := os.WriteFile(backupManager.ConfigurationPath, []byte(liveConfiguration), 0o600); err != nil {
		t.Fatal(err)
	}
	insertTestSession(t, database, "rollback-live-session")
	restoreManager, _ := stageArtifactAndAuthorize(t, backupManager, artifact, database, stateDirectory, RestoreModeSameVPS)
	applier, err := NewRestoreApplier(restoreManager, filepath.Join(t.TempDir(), "transactions"), -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	applier.AfterAppliedItem = func(index int) error {
		if index == 2 {
			return errors.New("injected apply failure")
		}
		return nil
	}
	if _, err := applier.Apply(ctx); !errors.Is(err, ErrRestoreSafelyRolledBack) {
		t.Fatalf("Apply() error = %v", err)
	}
	configuration, err := os.ReadFile(backupManager.ConfigurationPath)
	if err != nil || string(configuration) != liveConfiguration {
		t.Fatalf("rolled-back config = %q, %v", configuration, err)
	}
	liveDatabase, err := databasepkg.OpenImmutable(ctx, filepath.Join(stateDirectory, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer liveDatabase.Close()
	var sessions int
	if err := liveDatabase.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE id_hash='rollback-live-session'").Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("rolled-back session count = %d, %v", sessions, err)
	}
	status, exists, err := restoreManager.Status()
	if err != nil || !exists || status.State != RestoreStateStaged || status.ApplyAuthorization != "" || status.SelectedMode != "" || status.ApplyErrorCode != "RESTORE_APPLY_FAILED_ROLLED_BACK" {
		t.Fatalf("rolled-back status = %+v, exists=%t error=%v", status, exists, err)
	}
	entries, err := os.ReadDir(applier.TransactionRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rolled-back journals = %v, %v", entries, err)
	}
}

func TestVPSRestoreBootRecoveryRollsBackInterruptedSwap(t *testing.T) {
	ctx := context.Background()
	backupManager, database, stateDirectory := vpsBackupFixture(t)
	artifact, err := backupManager.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	liveConfiguration := "version: 1\n# boot-recovery-live\n"
	if err := os.WriteFile(backupManager.ConfigurationPath, []byte(liveConfiguration), 0o600); err != nil {
		t.Fatal(err)
	}
	insertTestSession(t, database, "boot-recovery-session")
	restoreManager, operation := stageArtifactAndAuthorize(t, backupManager, artifact, database, stateDirectory, RestoreModeSameVPS)
	transactionRoot := filepath.Join(t.TempDir(), "transactions")
	applier, err := NewRestoreApplier(restoreManager, transactionRoot, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.validate(); err != nil {
		t.Fatal(err)
	}
	verified, err := restoreManager.VerifyPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := applier.createPreRestoreSnapshot(ctx, operation.RestoreID)
	if err != nil {
		t.Fatal(err)
	}
	items := applier.restoreItems(operation.RestoreID, operation.SelectedMode)
	if _, err := applier.prepareCandidates(ctx, verified, items); err != nil {
		t.Fatal(err)
	}
	if err := restoreManager.Database.Close(); err != nil {
		t.Fatal(err)
	}
	restoreManager.Database = nil
	for index := range items {
		exists, err := safeDestinationExists(items[index].Destination, items[index].Kind)
		if err != nil {
			t.Fatal(err)
		}
		items[index].OriginalExists = exists
	}
	journal := applyJournal{
		FormatVersion: applyJournalVersion, RestoreID: operation.RestoreID, State: applyApplying,
		Mode: operation.SelectedMode, ApplyAuthorization: operation.ApplyAuthorization,
		PreRestoreSnapshot: snapshot, Items: items,
	}
	journalPath := applier.journalPath(operation.RestoreID)
	if err := applier.writeJournal(journalPath, journal, false); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if err := applySwapItem(&journal.Items[index]); err != nil {
			t.Fatal(err)
		}
		journal.AppliedItems = index + 1
		if err := applier.writeJournal(journalPath, journal, true); err != nil {
			t.Fatal(err)
		}
	}
	// The original privileged process is now treated as SIGKILLed. A fresh
	// boot process opens the currently visible (partially restored) database.
	currentDatabase, err := vpsagent.Open(ctx, filepath.Join(stateDirectory, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	recoveryManager, err := NewRestoreManager(currentDatabase, stateDirectory, filepath.Join(stateDirectory, "vps-agent.db"), backupManager.ConfigurationPath)
	if err != nil {
		t.Fatal(err)
	}
	recoveryApplier, err := NewRestoreApplier(recoveryManager, transactionRoot, -1, -1)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := recoveryApplier.Recover(ctx)
	if err != nil || !recovered {
		t.Fatalf("Recover() = %t, %v", recovered, err)
	}
	configuration, err := os.ReadFile(backupManager.ConfigurationPath)
	if err != nil || string(configuration) != liveConfiguration {
		t.Fatalf("boot-recovered config = %q, %v", configuration, err)
	}
	liveDatabase, err := databasepkg.OpenImmutable(ctx, filepath.Join(stateDirectory, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer liveDatabase.Close()
	var sessions int
	if err := liveDatabase.QueryRowContext(ctx, "SELECT COUNT(*) FROM sessions WHERE id_hash='boot-recovery-session'").Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("boot-recovered session count = %d, %v", sessions, err)
	}
	status, exists, err := recoveryManager.Status()
	if err != nil || !exists || status.State != RestoreStateStaged || status.ApplyErrorCode != "BOOT_RECOVERY_ROLLBACK" {
		t.Fatalf("boot-recovered status = %+v, exists=%t error=%v", status, exists, err)
	}
	entries, err := os.ReadDir(transactionRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("boot recovery journals = %v, %v", entries, err)
	}
}

func stageArtifactAndAuthorize(t *testing.T, backupManager *Manager, artifact Artifact, database *sql.DB, stateDirectory, mode string) (*RestoreManager, RestoreOperation) {
	t.Helper()
	restoreManager, err := NewRestoreManager(database, stateDirectory, filepath.Join(stateDirectory, "vps-agent.db"), backupManager.ConfigurationPath)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := backupManager.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := restoreManager.Stage(context.Background(), reader, "correct horse battery staple")
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	operation, err = restoreManager.AuthorizeApply(operation.RestoreID, mode)
	if err != nil {
		t.Fatal(err)
	}
	if operation.State != RestoreStateApplyRequested || operation.SelectedMode != mode || !digestPattern.MatchString(operation.ApplyAuthorization) {
		t.Fatalf("authorized operation = %+v", operation)
	}
	return restoreManager, operation
}

func testPeerKey(t *testing.T) string {
	t.Helper()
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pair.Public
}

func insertTestSession(t *testing.T, database *sql.DB, id string) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(), "INSERT OR IGNORE INTO users(id,username,password_hash,enabled,must_change_password,created_at,updated_at) VALUES('user:test','test','hash',1,0,'now','now')"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(context.Background(), "INSERT INTO sessions(id_hash,user_id,csrf_hash,created_at,expires_at,last_seen_at,client_key_hash) VALUES(?,'user:test','csrf','now','later','now','client')", id); err != nil {
		t.Fatal(err)
	}
}
