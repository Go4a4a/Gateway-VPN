package vpsbackup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	databasepkg "gateway-vpn/internal/db"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/wgingress"
)

func TestVPSRestoreStageVerifiesPreviewAndLeavesNoUploadOrPassphrase(t *testing.T) {
	ctx := context.Background()
	backupManager, database, stateDirectory := vpsBackupFixture(t)
	relayFixture := seedVPSRelayBackupFixture(t, backupManager, database)
	passphrase := "correct horse battery staple"
	artifact, err := backupManager.Build(ctx, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	restoreManager, err := NewRestoreManager(database, stateDirectory, filepath.Join(stateDirectory, "vps-agent.db"), backupManager.ConfigurationPath)
	if err != nil {
		t.Fatal(err)
	}
	restoreManager.Now = func() time.Time { return time.Date(2026, 8, 30, 19, 0, 0, 0, time.UTC) }
	reader, err := backupManager.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := restoreManager.Stage(ctx, reader, passphrase)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if operation.State != RestoreStateStaged || !operation.IdentityMatches || !equalStrings(operation.AllowedModes, []string{RestoreModeSameVPS, RestoreModeNewVPS}) || !operation.CloneQuarantineOnSameVPS || operation.SourceVPSID != "vps:primary" || operation.LiveVPSID != "vps:primary" {
		t.Fatalf("restore preview = %+v", operation)
	}
	status, exists, err := restoreManager.Status()
	if err != nil || !exists || !equalRestoreOperation(status, operation) {
		t.Fatalf("Status() = %+v, %t, %v", status, exists, err)
	}
	verified, err := restoreManager.VerifyPending(ctx)
	if err != nil || verified.Identity.VPSID != "vps:primary" || verified.Manifest.Role != "vps" || verified.TreeRoot == "" {
		t.Fatalf("VerifyPending() = %+v, %v", verified, err)
	}
	stagedDatabase, err := databasepkg.OpenImmutable(ctx, filepath.Join(verified.TreeRoot, "database", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	assertVPSRelayBackupFixture(t, ctx, stagedDatabase, relayFixture, "ACTIVE", "ACTIVE", "RELAY_BACKUP_FIXTURE")
	stagedDatabase.Close()
	if _, err := os.Stat(filepath.Join(verified.TreeRoot, "state", "secrets", "management", "wg-admin.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged VPS restore contains forbidden inner administrator private key: %v", err)
	}
	operationRoot := filepath.Join(restoreManager.Root, operation.RestoreID)
	for _, removed := range []string{"upload.gvpn-vps", "payload.zip"} {
		if _, err := os.Stat(filepath.Join(operationRoot, removed)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary restore file %s remains: %v", removed, err)
		}
	}
	if restoreTreeContains(t, operationRoot, passphrase) {
		t.Fatal("VPS restore passphrase persisted in staging")
	}
	reader, err = backupManager.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restoreManager.Stage(ctx, reader, passphrase); !errors.Is(err, ErrRestorePending) {
		t.Fatalf("second Stage() error = %v", err)
	}
	reader.Close()
	if err := restoreManager.Discard(operation.RestoreID); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := restoreManager.Status(); err != nil || exists {
		t.Fatalf("discarded Status() exists=%t error=%v", exists, err)
	}
}

func TestVPSRestoreMismatchAllowsOnlyImportAsNew(t *testing.T) {
	ctx := context.Background()
	sourceManager, _, _ := vpsBackupFixture(t)
	artifact, err := sourceManager.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	targetState := filepath.Join(t.TempDir(), "target-state")
	targetDatabase, err := vpsagent.Open(ctx, filepath.Join(targetState, "vps-agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer targetDatabase.Close()
	pair, err := wgingress.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vpsagent.InitializeIdentity(ctx, targetDatabase, vpsagent.IdentityInput{
		VPSID: "vps:target", DisplayName: "Target VPS", IdentityFingerprint: strings.Repeat("b", 64), PublicKey: pair.Public,
		PrivateKeySecretRef: "/var/lib/gateway-vpn-vps/agent/secrets/wireguard/server.key",
		UpdateIdentityRef:   "/var/lib/gateway-vpn-vps/agent/secrets/update/identity.key",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	targetConfig := filepath.Join(t.TempDir(), "target.yaml")
	if err := os.WriteFile(targetConfig, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restoreManager, err := NewRestoreManager(targetDatabase, targetState, filepath.Join(targetState, "vps-agent.db"), targetConfig)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sourceManager.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := restoreManager.Stage(ctx, reader, "correct horse battery staple")
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if operation.IdentityMatches || !equalStrings(operation.AllowedModes, []string{RestoreModeNewVPS}) || operation.SourceVPSID != "vps:primary" || operation.LiveVPSID != "vps:target" {
		t.Fatalf("mismatched restore preview = %+v", operation)
	}
}

func TestVPSRestoreRejectsBadPasswordAndCorruptUploadWithoutResidue(t *testing.T) {
	ctx := context.Background()
	backupManager, database, stateDirectory := vpsBackupFixture(t)
	artifact, err := backupManager.Build(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		content    []byte
		passphrase string
	}{
		{name: "wrong password", content: encrypted, passphrase: "wrong password long enough"},
		{name: "corrupt", content: mutateVPSBackup(encrypted), passphrase: "correct horse battery staple"},
		{name: "truncated", content: encrypted[:len(encrypted)-5], passphrase: "correct horse battery staple"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			restoreManager, err := NewRestoreManager(database, stateDirectory, filepath.Join(stateDirectory, "vps-agent.db"), filepath.Join(t.TempDir(), "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restoreManager.Stage(ctx, bytes.NewReader(test.content), test.passphrase); err == nil {
				t.Fatal("invalid encrypted VPS restore was accepted")
			}
			if _, exists, err := restoreManager.Status(); err != nil || exists {
				t.Fatalf("invalid restore left pending marker: exists=%t error=%v", exists, err)
			}
			entries, err := os.ReadDir(restoreManager.Root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("invalid restore left staging entries: %v", entries)
			}
		})
	}
	_ = stateDirectory
}

func restoreTreeContains(t *testing.T, root, value string) bool {
	t.Helper()
	found := false
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		content, err := io.ReadAll(io.LimitReader(file, MaximumFileBytes+1))
		file.Close()
		if err != nil {
			return err
		}
		if bytes.Contains(content, []byte(value)) {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return found
}
