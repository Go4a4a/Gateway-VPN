package vpsupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/vpsbackup"
	"gateway-vpn/internal/vpsrelease"
)

func TestEngineAppliesSignedCandidateAndFinalizes(t *testing.T) {
	fixture := newEngineFixture(t)
	result, err := fixture.engine.Apply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.OldVersion != "1.1.0" || result.NewVersion != "1.2.0" || result.State != StateStabilizing || result.StabilityDeadline == "" {
		t.Fatalf("Apply() = %+v", result)
	}
	assertPointer(t, fixture.releaseRoot, "current", "releases/v1.2.0")
	assertPointer(t, fixture.releaseRoot, "recovery", "releases/v1.1.0")
	journal, exists, err := fixture.engine.Store.LoadActive()
	if err != nil || !exists || journal.State != StateStabilizing || journal.SnapshotSHA256 == "" || journal.CandidateDBSHA256 == "" {
		t.Fatalf("active journal = %+v,%v,%v", journal, exists, err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.engine.StateDirectory, "update-staging", pendingFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending staging marker remained after apply: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.engine.StateDirectory, "update-staging", fixture.operation.UpdateID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged release tree remained after apply: %v", err)
	}
	fixture.clock = fixture.clock.Add(2 * time.Hour)
	finalized, err := fixture.engine.Finalize(context.Background())
	if err != nil || finalized.State != StateFinalized {
		t.Fatalf("Finalize() = %+v,%v", finalized, err)
	}
	assertPointer(t, fixture.releaseRoot, "current", "releases/v1.2.0")
	assertPointer(t, fixture.releaseRoot, "recovery", "releases/v1.2.0")
	if _, exists, err := fixture.engine.Store.LoadActive(); err != nil || exists {
		t.Fatalf("active journal after finalize: exists=%v err=%v", exists, err)
	}
}

func TestEngineStabilizingRecoveryVerifiesOfflineWithoutStartingDependentUnits(t *testing.T) {
	fixture := newEngineFixture(t)
	if _, err := fixture.engine.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	started := len(fixture.runtime.started)
	recovered, err := fixture.engine.Recover(context.Background())
	if err != nil || recovered {
		t.Fatalf("Recover() = %v,%v", recovered, err)
	}
	if len(fixture.runtime.started) != started || len(fixture.runtime.scheduled) != 0 || len(fixture.runtime.verified) != 1 || fixture.runtime.verified[0] != "1.2.0" {
		t.Fatalf("stabilizing recovery runtime calls started=%v scheduled=%v verified=%v", fixture.runtime.started, fixture.runtime.scheduled, fixture.runtime.verified)
	}
}

func TestEngineHealthFailureRestoresOldReleaseAndDatabase(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.runtime.mutateCandidate = true
	fixture.runtime.failVersion = "1.2.0"
	if _, err := fixture.engine.Apply(context.Background()); err == nil {
		t.Fatal("unhealthy candidate unexpectedly succeeded")
	}
	assertPointer(t, fixture.releaseRoot, "current", "releases/v1.1.0")
	assertProbeTable(t, fixture.databasePath, false)
	if got := fixture.runtime.started[len(fixture.runtime.started)-1]; got != "1.1.0" {
		t.Fatalf("last started version = %q", got)
	}
	status, err := fixture.engine.Status.Read()
	if err != nil || status.State != StateRolledBack || status.CurrentVersion != "1.1.0" || status.ErrorCode != "NEW_RELEASE_HEALTH_FAILED" {
		t.Fatalf("rollback status = %+v,%v", status, err)
	}
}

func TestDatabaseReplacementRejectsUnsafeSameDirectoryArtifact(t *testing.T) {
	fixture := newEngineFixture(t)
	source := filepath.Join(t.TempDir(), "replacement.db")
	writeFile(t, source, "verified replacement database\n", 0o600)
	digest, _, err := hashRegular(source, vpsbackup.MaximumFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(filepath.Dir(fixture.databasePath), "."+filepath.Base(fixture.databasePath)+"-"+sanitizeSuffix(fixture.operation.UpdateID+"-candidate")+".tmp")
	if err := os.Mkdir(temporary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fixture.engine.replaceDatabase(source, digest, fixture.operation.UpdateID, "candidate"); err == nil || !strings.Contains(err.Error(), "replacement artifact is unsafe") {
		t.Fatalf("unsafe replacement artifact error = %v", err)
	}
	assertProbeTable(t, fixture.databasePath, false)
}

func TestEngineBootRecoveryAfterDatabaseSwitch(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.runtime.mutateCandidate = true
	fixture.engine.AfterState = func(state State) error {
		if state == StateDBSwitched {
			panic("simulated abrupt process death")
		}
		return nil
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("simulated process death did not occur")
			}
		}()
		_, _ = fixture.engine.Apply(context.Background())
	}()
	assertProbeTable(t, fixture.databasePath, true)
	fixture.engine.AfterState = nil
	recovered, err := fixture.engine.Recover(context.Background())
	if err != nil || !recovered {
		t.Fatalf("Recover() = %v,%v", recovered, err)
	}
	assertPointer(t, fixture.releaseRoot, "current", "releases/v1.1.0")
	assertProbeTable(t, fixture.databasePath, false)
	if len(fixture.runtime.scheduled) != 1 || fixture.runtime.scheduled[0] != "1.1.0" {
		t.Fatalf("boot recovery scheduled releases = %v", fixture.runtime.scheduled)
	}
}

func TestEngineRejectsTamperedRollbackSnapshot(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.runtime.mutateCandidate = true
	fixture.engine.AfterState = func(state State) error {
		if state == StateDBSwitched {
			panic("simulated abrupt process death")
		}
		return nil
	}
	func() {
		defer func() { _ = recover() }()
		_, _ = fixture.engine.Apply(context.Background())
	}()
	journal, exists, err := fixture.engine.Store.LoadActive()
	if err != nil || !exists {
		t.Fatalf("LoadActive() = %+v,%v,%v", journal, exists, err)
	}
	if err := os.WriteFile(filepath.Join(fixture.engine.Store.Root, journal.UpdateID, "snapshot.db"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.engine.AfterState = nil
	if _, err := fixture.engine.Recover(context.Background()); err == nil {
		t.Fatal("tampered rollback snapshot was accepted")
	}
	status, err := fixture.engine.Status.Read()
	if err != nil || status.State != StateRollbackFailed || status.ErrorCode != "ROLLBACK_SNAPSHOT_INVALID" {
		t.Fatalf("rollback-failed status = %+v,%v", status, err)
	}
}

func TestEngineRejectsDifferentSignedArtifactAtExistingVersion(t *testing.T) {
	fixture := newEngineFixture(t)
	stagedRoot, err := fixture.stager.PendingReleaseRoot(fixture.operation.UpdateID)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := vpsrelease.VerifyRelease(stagedRoot, fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	existing := writeSignedRelease(t, filepath.Join(fixture.releaseRoot, "releases", "v1.2.0"), "1.2.0", 4, fixture.privateKey, "different-binary")
	if existing == "" {
		t.Fatal("empty existing release")
	}
	if _, err := fixture.engine.installRelease(verified, fixture.policy); err == nil || !strings.Contains(err.Error(), "different signed artifact") {
		t.Fatalf("ambiguous same-version artifact error = %v", err)
	}
}

func TestEngineRejectsConcurrentTransaction(t *testing.T) {
	fixture := newEngineFixture(t)
	unlock, err := acquireLock(fixture.engine.Store.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := fixture.engine.Recover(context.Background()); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("Recover() concurrent error = %v", err)
	}
}

func TestStagerRejectsSameVersionDowngradeChangedHostContractAndTampering(t *testing.T) {
	for _, test := range []struct {
		name      string
		version   string
		mutate    func(string)
		wantError error
	}{
		{name: "same-version", version: "1.1.0"},
		{name: "downgrade", version: "1.0.9"},
		{name: "changed-host-contract", version: "1.2.0", mutate: func(root string) {
			writeFile(t, filepath.Join(root, "packaging/vps/config/config.yaml"), "version: 2\n", 0o644)
		}, wantError: ErrHostContractChanged},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStagerFixture(t, test.version, test.mutate)
			_, err := fixture.stager.Stage(context.Background(), bytes.NewReader(releaseArchive(t, fixture.candidateRoot)))
			if err == nil || test.wantError != nil && !errors.Is(err, test.wantError) {
				t.Fatalf("Stage() error = %v", err)
			}
		})
	}
	fixture := newStagerFixture(t, "1.2.0", nil)
	operation, err := fixture.stager.Stage(context.Background(), bytes.NewReader(releaseArchive(t, fixture.candidateRoot)))
	if err != nil {
		t.Fatal(err)
	}
	root, err := fixture.stager.PendingReleaseRoot(operation.UpdateID)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "bin/gateway-vpn-vps-agent"), "tampered\n", 0o755)
	if _, _, err := fixture.stager.Status(); err == nil {
		t.Fatal("tampered staged release remained trusted")
	}
}

func TestJournalUsesRedundantCopiesAndStatusDoesNotExposeSensitivePaths(t *testing.T) {
	temporaryRoot := t.TempDir()
	root := filepath.Join(temporaryRoot, "gateway-vpn-vps-privileged", "update-transactions")
	store := JournalStore{Root: root}
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	journal := validJournal(now)
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(root, "active.json")
	active, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activePath, bytes.Replace(active, []byte("PREPARED"), []byte("BROKEN__"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := store.LoadActive()
	if err != nil || !exists || loaded.UpdateID != journal.UpdateID {
		t.Fatalf("redundant journal recovery = %+v,%v,%v", loaded, exists, err)
	}
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err = store.LoadActive()
	if err != nil || !exists || loaded.UpdateID != journal.UpdateID {
		t.Fatalf("missing active journal recovery = %+v,%v,%v", loaded, exists, err)
	}
	status := Status{FormatVersion: JournalFormatVersion, Available: true, UpdateID: journal.UpdateID, State: StateStabilizing, CurrentVersion: "1.2.0", PreviousVersion: "1.1.0", CandidateVersion: "1.2.0", CurrentSchema: 4, CandidateSchema: 4, StartedAt: journal.StartedAt, UpdatedAt: journal.UpdatedAt, StabilityDeadline: now.Add(time.Hour).Format(time.RFC3339Nano), ReconnectRequired: true}
	content, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if strings.Contains(text, temporaryRoot) || strings.Contains(text, "sha256") || strings.Contains(text, "snapshot") || strings.Contains(text, "update-transactions") {
		t.Fatalf("public status exposed a privileged path or digest: %s", text)
	}
}

func TestJournalRejectsBothCorruptedCopies(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gateway-vpn-vps-privileged", "update-transactions")
	store := JournalStore{Root: root}
	journal := validJournal(time.Date(2026, 8, 31, 10, 30, 0, 0, time.UTC))
	if err := store.Save(journal); err != nil {
		t.Fatal(err)
	}
	corrupted := []byte(`{"format_version":1,"update_id":"corrupted"}`)
	for _, path := range []string{filepath.Join(root, "active.json"), filepath.Join(root, journal.UpdateID, "journal.json")} {
		if err := os.WriteFile(path, corrupted, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.LoadActive(); err == nil || !strings.Contains(err.Error(), "both VPS update journal copies are invalid") {
		t.Fatalf("both corrupted journals were not rejected: %v", err)
	}
}

func TestStatusStorePublishesRootStatusToAgentGroupAndServiceResetsStaleStatus(t *testing.T) {
	state := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "update-status.json")
	now := time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC)
	store := StatusStore{Path: path, UID: os.Getuid(), GID: os.Getgid()}
	if err := store.Write(Status{FormatVersion: JournalFormatVersion, Available: true, CurrentVersion: "1.1.0", CurrentSchema: 4, UpdatedAt: now.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("root status mode = %v,%v", info.Mode().Perm(), err)
	}
	service := &Service{StatusPath: path, CurrentVersion: "1.2.0", CurrentSchema: 5, Now: func() time.Time { return now.Add(time.Minute) }}
	if err := service.EnsureInitialStatus(); err != nil {
		t.Fatal(err)
	}
	status, err := (StatusStore{Path: path}).Read()
	if err != nil || status.CurrentVersion != "1.2.0" || status.CurrentSchema != 5 || status.UpdateID != "" {
		t.Fatalf("reset status = %+v,%v", status, err)
	}
}

type engineFixture struct {
	engine       *Engine
	stager       *Stager
	runtime      *fakeRuntime
	operation    Operation
	policy       vpsrelease.VerificationPolicy
	privateKey   ed25519.PrivateKey
	releaseRoot  string
	databasePath string
	clock        time.Time
}

func newEngineFixture(t *testing.T) *engineFixture {
	t.Helper()
	root := t.TempDir()
	stateDirectory := filepath.Join(root, "gateway-vpn-vps", "agent")
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writePublicKey(t, stateDirectory, publicKey)
	releaseRoot := filepath.Join(root, "opt", "gateway-vpn-vps")
	oldRoot := filepath.Join(releaseRoot, "releases", "v1.1.0")
	writeSignedRelease(t, oldRoot, "1.1.0", 4, privateKey, "old-binary")
	if err := os.MkdirAll(releaseRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.FromSlash("releases/v1.1.0"), filepath.Join(releaseRoot, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.FromSlash("releases/v1.1.0"), filepath.Join(releaseRoot, "recovery")); err != nil {
		t.Fatal(err)
	}
	candidateRoot := writeSignedRelease(t, filepath.Join(root, "candidate"), "1.2.0", 4, privateKey, "new-binary")
	clock := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	stager := &Stager{StateDirectory: stateDirectory, ReleaseRoot: releaseRoot, TrustedKeyPath: keyPath, CurrentVersion: "1.1.0", CurrentSchema: 4, Profile: "ubuntu-24.04", Now: func() time.Time { return clock }}
	operation, err := stager.Stage(context.Background(), bytes.NewReader(releaseArchive(t, candidateRoot)))
	if err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(stateDirectory, "vps-agent.db")
	database, err := vpsagent.Open(context.Background(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	_ = removeSidecars(databasePath)
	configPath := filepath.Join(root, "etc", "gateway-vpn-vps", "config.yaml")
	writeFile(t, configPath, "version: 1\n", 0o640)
	runtime := &fakeRuntime{}
	fixture := &engineFixture{stager: stager, runtime: runtime, operation: operation, policy: vpsrelease.VerificationPolicy{PublicKey: publicKey, ExpectedOS: "linux", ExpectedArch: "amd64", ExpectedProfile: "ubuntu-24.04"}, privateKey: privateKey, releaseRoot: releaseRoot, databasePath: databasePath, clock: clock}
	fixture.engine = &Engine{
		Stager: stager, Store: JournalStore{Root: filepath.Join(root, "gateway-vpn-vps-privileged", "update-transactions")}, Status: StatusStore{Path: filepath.Join(stateDirectory, "update-status.json"), UID: 0, GID: 0}, Runtime: runtime,
		ReleaseRoot: releaseRoot, StateDirectory: stateDirectory, DatabasePath: databasePath, ConfigPath: configPath, TrustedKeyPath: keyPath, Profile: "ubuntu-24.04", RunningVersion: "1.1.0", RunningSchema: 4, AgentUID: 0, AgentGID: 0,
		StabilityWindow: time.Hour, Now: func() time.Time { return fixture.clock },
	}
	return fixture
}

type stagerFixture struct {
	stager        *Stager
	candidateRoot string
}

func newStagerFixture(t *testing.T, candidateVersion string, mutate func(string)) stagerFixture {
	t.Helper()
	root := t.TempDir()
	stateDirectory := filepath.Join(root, "gateway-vpn-vps", "agent")
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writePublicKey(t, stateDirectory, publicKey)
	releaseRoot := filepath.Join(root, "opt", "gateway-vpn-vps")
	writeSignedRelease(t, filepath.Join(releaseRoot, "releases", "v1.1.0"), "1.1.0", 4, privateKey, "old-binary")
	if err := os.Symlink(filepath.FromSlash("releases/v1.1.0"), filepath.Join(releaseRoot, "current")); err != nil {
		t.Fatal(err)
	}
	candidateRoot := filepath.Join(root, "candidate")
	writeUnsignedRelease(t, candidateRoot, candidateVersion, 4, "candidate-binary")
	if mutate != nil {
		mutate(candidateRoot)
	}
	if _, err := vpsrelease.SignRelease(candidateRoot, privateKey); err != nil {
		t.Fatal(err)
	}
	return stagerFixture{stager: &Stager{StateDirectory: stateDirectory, ReleaseRoot: releaseRoot, TrustedKeyPath: keyPath, CurrentVersion: "1.1.0", CurrentSchema: 4, Profile: "ubuntu-24.04"}, candidateRoot: candidateRoot}
}

type fakeRuntime struct {
	started         []string
	verified        []string
	scheduled       []string
	failVersion     string
	mutateCandidate bool
}

func (runtime *fakeRuntime) Quiesce(context.Context) error { return nil }

func (runtime *fakeRuntime) OfflineCheck(ctx context.Context, _ string, databasePath, _ string, version string, schema int64) (OfflineResult, error) {
	if runtime.mutateCandidate {
		database, err := vpsagent.Open(ctx, databasePath)
		if err != nil {
			return OfflineResult{}, err
		}
		_, execErr := database.ExecContext(ctx, "CREATE TABLE update_probe(value TEXT NOT NULL)")
		closeErr := database.Close()
		if execErr != nil || closeErr != nil {
			return OfflineResult{}, errors.Join(execErr, closeErr)
		}
		_ = removeSidecars(databasePath)
	}
	digest, size, err := hashRegular(databasePath, vpsbackup.MaximumFileBytes)
	if err != nil {
		return OfflineResult{}, err
	}
	return OfflineResult{Version: version, SchemaVersion: schema, DatabaseBytes: size, DatabaseSHA256: digest, QuickCheck: "PASS", IntegrityCheck: "PASS", ForeignKeyCheck: "PASS"}, nil
}

func (runtime *fakeRuntime) StartAndHealth(_ context.Context, version, _ string) error {
	runtime.started = append(runtime.started, version)
	if version == runtime.failVersion {
		return errors.New("candidate health failed")
	}
	return nil
}

func (runtime *fakeRuntime) VerifyCurrent(_ context.Context, version, _ string) error {
	runtime.verified = append(runtime.verified, version)
	if version == runtime.failVersion {
		return errors.New("current release verification failed")
	}
	return nil
}

func (runtime *fakeRuntime) ScheduleStart(_ context.Context, version, _ string) error {
	runtime.scheduled = append(runtime.scheduled, version)
	if version == runtime.failVersion {
		return errors.New("recovered release scheduling failed")
	}
	return nil
}

func writeSignedRelease(t *testing.T, root, version string, schema int64, privateKey ed25519.PrivateKey, binary string) string {
	t.Helper()
	writeUnsignedRelease(t, root, version, schema, binary)
	if _, err := vpsrelease.SignRelease(root, privateKey); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeUnsignedRelease(t *testing.T, root, version string, schema int64, binary string) {
	t.Helper()
	files := map[string]string{
		"bin/gateway-vpnctl": "controller\n", "bin/gateway-vpn-vps-agent": binary + "\n",
		"scripts/install-vps.sh": "#!/bin/sh\nexit 0\n", "scripts/uninstall-vps.sh": "#!/bin/sh\nexit 0\n", "scripts/recover-vps-install.sh": "#!/bin/sh\nexit 0\n",
		"packaging/vps/nftables/gateway-vpn-vps.nft.in": "table inet gateway_vpn_vps {}\n", "packaging/vps/sysctl.d/90-gateway-vpn-vps.conf": "net.ipv4.ip_forward=1\n",
		"packaging/vps/systemd/gateway-vpn-vps-firewall.service": "[Service]\nType=oneshot\n", "packaging/vps/systemd/gateway-vpn-vps-install-recovery.service": "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-agent.service": "[Service]\nType=simple\n", "packaging/vps/systemd/gateway-vpn-vps-restore.service": "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-restore.path": "[Path]\nPathExists=/tmp/restore\n", "packaging/vps/systemd/gateway-vpn-vps-restore-recovery.service": "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-fabric.service": "[Service]\nType=oneshot\n", "packaging/vps/systemd/gateway-vpn-vps-fabric.path": "[Path]\nPathExists=/tmp/fabric\n",
		"packaging/vps/systemd/gateway-vpn-vps-fabric-recovery.service": "[Service]\nType=oneshot\n", "packaging/vps/systemd/gateway-vpn-vps-fabric-watchdog.service": "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-fabric-watchdog.timer": "[Timer]\nOnUnitActiveSec=60s\n", "packaging/vps/systemd/gateway-vpn-vps-operations.service": "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-operations.timer": "[Timer]\nOnUnitActiveSec=60s\n", "packaging/vps/systemd/gateway-vpn-vps-update.service": "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-update.path": "[Path]\nPathExists=/tmp/update\n", "packaging/vps/systemd/gateway-vpn-vps-update-recovery.service": "[Service]\nType=oneshot\n",
		"packaging/vps/systemd/gateway-vpn-vps-update-finalize.service": "[Service]\nType=oneshot\n", "packaging/vps/systemd/gateway-vpn-vps-update-finalize.timer": "[Timer]\nOnUnitActiveSec=60s\n",
		"packaging/vps/config/config.yaml": "version: 1\n", "packaging/vps/systemd/wg-quick@wg-mgmt.service.d/gateway-vpn.conf": "[Unit]\nAfter=gateway-vpn-vps-firewall.service\n",
		vpsrelease.LegacyHashFilename: strings.Repeat("0", 64) + "  placeholder\n", "share/supply-chain/sbom.spdx.json": "{}\n", "share/supply-chain/provenance.intoto.json": "{}\n",
	}
	for relative, content := range files {
		mode := os.FileMode(0o644)
		if strings.HasPrefix(relative, "bin/") || strings.HasPrefix(relative, "scripts/") {
			mode = 0o755
		}
		writeFile(t, filepath.Join(root, filepath.FromSlash(relative)), content, mode)
	}
	release := vpsrelease.Release{FormatVersion: vpsrelease.ReleaseFormatVersion, Role: "vps", Version: version, OS: "linux", Arch: "amd64", SourceCommit: strings.Repeat("a", 40), BuildDate: "2026-08-31T00:00:00Z", SupportedProfiles: vpsrelease.SupportedProfiles(), InterfaceName: "wg-mgmt", ManagementSubnet: "10.80.0.0/24", ListenPort: 51821, DatabaseSchemaMaximum: schema}
	content, err := json.MarshalIndent(release, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, vpsrelease.ReleaseFilename), string(append(content, '\n')), 0o644)
}

func releaseArchive(t *testing.T, root string) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || path == root {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if entry.IsDir() {
			return tarWriter.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := int64(0o644)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(content))}); err != nil {
			return err
		}
		_, err = tarWriter.Write(content)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writePublicKey(t *testing.T, directory string, key ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "update-signing.pub")
	writeFile(t, path, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), 0o644)
	return path
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func assertPointer(t *testing.T, root, name, want string) {
	t.Helper()
	target, err := os.Readlink(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.ToSlash(target); got != want {
		t.Fatalf("%s target = %q, want %q", name, got, want)
	}
}

func assertProbeTable(t *testing.T, databasePath string, want bool) {
	t.Helper()
	database, err := vpsagent.Open(context.Background(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='update_probe'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if (count == 1) != want {
		t.Fatalf("update_probe exists=%v, want %v", count == 1, want)
	}
}

func validJournal(now time.Time) Journal {
	stamp := now.Format(time.RFC3339Nano)
	return Journal{FormatVersion: JournalFormatVersion, UpdateID: "vps-update-20260831T100000Z-0123456789abcdef01234567", State: StatePrepared, StartedAt: stamp, UpdatedAt: stamp, OldVersion: "1.1.0", NewVersion: "1.2.0", OldSchema: 4, NewSchema: 4, OldCurrentTarget: "releases/v1.1.0", NewCurrentTarget: "releases/v1.2.0"}
}
