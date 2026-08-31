package vpsupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	updatepkg "gateway-vpn/internal/update"
	"gateway-vpn/internal/vpsagent"
	"gateway-vpn/internal/vpsbackup"
	"gateway-vpn/internal/vpsrelease"
)

const DefaultStabilityWindow = 24 * time.Hour

var (
	ErrUpdateInProgress      = errors.New("another VPS update transaction is active")
	ErrUpdateStabilizing     = errors.New("a VPS update is inside its stability window")
	ErrNoFinalizationPending = errors.New("no VPS update awaits finalization")
	ErrStabilityWindowActive = errors.New("the VPS update stability window is active")
)

type OfflineResult struct {
	Version         string `json:"version"`
	SchemaVersion   int64  `json:"schema_version"`
	DatabaseBytes   int64  `json:"database_bytes"`
	DatabaseSHA256  string `json:"database_sha256"`
	QuickCheck      string `json:"quick_check"`
	IntegrityCheck  string `json:"integrity_check"`
	ForeignKeyCheck string `json:"foreign_key_check"`
}

type Runtime interface {
	Quiesce(context.Context) error
	OfflineCheck(context.Context, string, string, string, string, int64) (OfflineResult, error)
	StartAndHealth(context.Context, string, string) error
	VerifyCurrent(context.Context, string, string) error
	ScheduleStart(context.Context, string, string) error
}

type Engine struct {
	Stager          *Stager
	Store           JournalStore
	Status          StatusStore
	Runtime         Runtime
	ReleaseRoot     string
	StateDirectory  string
	DatabasePath    string
	ConfigPath      string
	TrustedKeyPath  string
	Profile         string
	RunningVersion  string
	RunningSchema   int64
	AgentUID        int
	AgentGID        int
	StabilityWindow time.Duration
	Now             func() time.Time
	AfterState      func(State) error
}

type ApplyResult struct {
	UpdateID          string `json:"update_id"`
	OldVersion        string `json:"old_version"`
	NewVersion        string `json:"new_version"`
	OldSchema         int64  `json:"old_schema"`
	NewSchema         int64  `json:"new_schema"`
	State             State  `json:"state"`
	StabilityDeadline string `json:"stability_deadline"`
}

func (engine *Engine) Apply(ctx context.Context) (ApplyResult, error) {
	if err := engine.validate(true); err != nil {
		return ApplyResult{}, err
	}
	unlock, err := acquireLock(engine.Store.Root)
	if err != nil {
		return ApplyResult{}, err
	}
	defer unlock()
	if active, exists, err := engine.Store.LoadActive(); err != nil {
		return ApplyResult{}, err
	} else if exists {
		if active.State == StateStabilizing {
			return ApplyResult{}, ErrUpdateStabilizing
		}
		if _, err := engine.recoverLocked(ctx, false); err != nil {
			return ApplyResult{}, err
		}
	}
	operation, exists, err := engine.Stager.Status()
	if err != nil || !exists {
		return ApplyResult{}, errors.New("verified staged VPS update is unavailable")
	}
	stagedRoot, err := engine.Stager.PendingReleaseRoot(operation.UpdateID)
	if err != nil {
		return ApplyResult{}, err
	}
	policy, err := engine.policy()
	if err != nil {
		return ApplyResult{}, err
	}
	candidate, err := vpsrelease.VerifyRelease(stagedRoot, policy)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("reverify staged VPS update: %w", err)
	}
	oldTarget, current, err := engine.currentRelease(policy)
	if err != nil {
		return ApplyResult{}, err
	}
	if current.Release.Version != engine.RunningVersion || current.Release.DatabaseSchemaMaximum != engine.RunningSchema || operation.CurrentVersion != current.Release.Version || operation.CandidateVersion != candidate.Release.Version {
		return ApplyResult{}, errors.New("running VPS binary, current release, and staged operation do not match")
	}
	oldContract, _ := HostContractSHA256(current.Manifest)
	newContract, _ := HostContractSHA256(candidate.Manifest)
	if oldContract == "" || oldContract != newContract || newContract != operation.HostContractSHA256 {
		return ApplyResult{}, ErrHostContractChanged
	}
	if err := engine.switchPointer("recovery", oldTarget, operation.UpdateID+"-recovery"); err != nil {
		return ApplyResult{}, fmt.Errorf("pin old VPS recovery release: %w", err)
	}
	installedRoot, err := engine.installRelease(candidate, policy)
	if err != nil {
		return ApplyResult{}, err
	}
	now := engine.now()
	journal := Journal{FormatVersion: JournalFormatVersion, UpdateID: operation.UpdateID, State: StatePrepared, StartedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), OldVersion: current.Release.Version, NewVersion: candidate.Release.Version, OldSchema: engine.RunningSchema, NewSchema: candidate.Release.DatabaseSchemaMaximum, OldCurrentTarget: oldTarget, NewCurrentTarget: "releases/v" + candidate.Release.Version}
	if err := engine.save(&journal, StatePrepared); err != nil {
		return ApplyResult{}, err
	}
	fail := func(code string, cause error) (ApplyResult, error) {
		if rollbackErr := engine.rollback(ctx, &journal, code, false); rollbackErr != nil {
			return ApplyResult{}, fmt.Errorf("VPS update failed (%v) and rollback failed: %w", cause, rollbackErr)
		}
		return ApplyResult{}, fmt.Errorf("VPS update rejected and rolled back: %w", cause)
	}
	if err := engine.Stager.discardApplied(journal.UpdateID); err != nil {
		return fail("STAGING_CLEANUP_FAILED", err)
	}
	if err := engine.Runtime.Quiesce(ctx); err != nil {
		return fail("QUIESCE_FAILED", err)
	}
	if err := engine.save(&journal, StateQuiesced); err != nil {
		return fail("JOURNAL_QUIESCED_FAILED", err)
	}
	transactionRoot := engine.transactionRoot(journal.UpdateID)
	snapshotPath := filepath.Join(transactionRoot, "snapshot.db")
	database, err := vpsagent.Open(ctx, engine.DatabasePath)
	if err != nil {
		return fail("LIVE_DATABASE_OPEN_FAILED", err)
	}
	if err := vpsagent.Verify(ctx, database); err != nil {
		database.Close()
		return fail("LIVE_DATABASE_VERIFY_FAILED", err)
	}
	if err := vpsbackup.CreateOnlineDatabaseCopy(ctx, database, snapshotPath); err != nil {
		database.Close()
		return fail("SNAPSHOT_FAILED", err)
	}
	if err := database.Close(); err != nil {
		return fail("LIVE_DATABASE_CLOSE_FAILED", err)
	}
	snapshotDigest, _, err := hashRegular(snapshotPath, vpsbackup.MaximumFileBytes)
	if err != nil {
		return fail("SNAPSHOT_HASH_FAILED", err)
	}
	journal.SnapshotSHA256 = snapshotDigest
	candidateDB := filepath.Join(transactionRoot, "candidate.db")
	if err := copyExclusive(snapshotPath, candidateDB, 0o600, vpsbackup.MaximumFileBytes); err != nil {
		return fail("CANDIDATE_DATABASE_COPY_FAILED", err)
	}
	offline, err := engine.Runtime.OfflineCheck(ctx, filepath.Join(installedRoot, "bin", "gateway-vpn-vps-agent"), candidateDB, engine.ConfigPath, candidate.Release.Version, candidate.Release.DatabaseSchemaMaximum)
	if err != nil || !validOffline(offline, candidate.Release.Version, candidate.Release.DatabaseSchemaMaximum) {
		return fail("CANDIDATE_OFFLINE_CHECK_FAILED", errors.Join(err, errors.New("candidate offline result is invalid")))
	}
	journal.CandidateDBSHA256 = offline.DatabaseSHA256
	if err := engine.save(&journal, StateCandidateReady); err != nil {
		return fail("JOURNAL_CANDIDATE_FAILED", err)
	}
	journal.DatabaseSwitchBegun = true
	if err := engine.save(&journal, StateDBSwitching); err != nil {
		return fail("JOURNAL_DATABASE_SWITCH_FAILED", err)
	}
	if err := removeSidecars(engine.DatabasePath); err != nil {
		return fail("DATABASE_SIDECAR_REMOVE_FAILED", err)
	}
	if err := engine.replaceDatabase(candidateDB, journal.CandidateDBSHA256, journal.UpdateID, "candidate"); err != nil {
		return fail("DATABASE_REPLACE_FAILED", err)
	}
	if err := engine.setDatabaseOwnership(); err != nil {
		return fail("DATABASE_OWNERSHIP_FAILED", err)
	}
	if err := syncDirectory(filepath.Dir(engine.DatabasePath)); err != nil {
		return fail("DATABASE_DIRECTORY_SYNC_FAILED", err)
	}
	if err := engine.save(&journal, StateDBSwitched); err != nil {
		return fail("JOURNAL_DATABASE_SWITCHED_FAILED", err)
	}
	if err := engine.save(&journal, StateReleaseSwitch); err != nil {
		return fail("JOURNAL_RELEASE_SWITCH_FAILED", err)
	}
	if err := engine.switchPointer("current", journal.NewCurrentTarget, journal.UpdateID); err != nil {
		return fail("CURRENT_POINTER_SWITCH_FAILED", err)
	}
	if err := engine.save(&journal, StateHealthChecking); err != nil {
		return fail("JOURNAL_HEALTH_FAILED", err)
	}
	if err := engine.Runtime.StartAndHealth(ctx, journal.NewVersion, engine.DatabasePath); err != nil {
		return fail("NEW_RELEASE_HEALTH_FAILED", err)
	}
	journal.StabilityDeadline = engine.now().Add(engine.stabilityWindow()).Format(time.RFC3339Nano)
	journal.ErrorCode = ""
	if err := engine.save(&journal, StateStabilizing); err != nil {
		return fail("JOURNAL_STABILIZING_FAILED", err)
	}
	return ApplyResult{UpdateID: journal.UpdateID, OldVersion: journal.OldVersion, NewVersion: journal.NewVersion, OldSchema: journal.OldSchema, NewSchema: journal.NewSchema, State: journal.State, StabilityDeadline: journal.StabilityDeadline}, nil
}

func (engine *Engine) Recover(ctx context.Context) (bool, error) {
	if err := engine.validate(false); err != nil {
		return false, err
	}
	unlock, err := acquireLock(engine.Store.Root)
	if err != nil {
		return false, err
	}
	defer unlock()
	return engine.recoverLocked(ctx, true)
}

func (engine *Engine) recoverLocked(ctx context.Context, scheduleStart bool) (bool, error) {
	journal, exists, err := engine.Store.LoadActive()
	if err != nil || !exists {
		return false, err
	}
	if !journal.InProgress() {
		// A crash can occur after the terminal journal is durably saved but
		// before active.json is removed. That is completed audit evidence, not
		// a transaction to roll back.
		return false, engine.Store.ClearActive()
	}
	if journal.State == StateStabilizing {
		if err := engine.verifyCurrentOffline(ctx, journal.NewCurrentTarget, journal.NewVersion, journal.NewSchema); err == nil {
			return false, nil
		}
	}
	if err := engine.rollback(ctx, &journal, "BOOT_OR_PROCESS_RECOVERY", scheduleStart); err != nil {
		return false, err
	}
	return true, nil
}

func (engine *Engine) Finalize(ctx context.Context) (Journal, error) {
	if err := engine.validate(false); err != nil {
		return Journal{}, err
	}
	unlock, err := acquireLock(engine.Store.Root)
	if err != nil {
		return Journal{}, err
	}
	defer unlock()
	journal, exists, err := engine.Store.LoadActive()
	if err != nil {
		return Journal{}, err
	}
	if !exists || journal.State != StateStabilizing {
		return Journal{}, ErrNoFinalizationPending
	}
	if err := engine.verifyCurrent(ctx, journal.NewCurrentTarget, journal.NewVersion, journal.NewSchema); err != nil {
		if rollbackErr := engine.rollback(ctx, &journal, "FINALIZE_HEALTH_FAILED", false); rollbackErr != nil {
			return Journal{}, rollbackErr
		}
		return Journal{}, errors.New("VPS candidate health failed and was rolled back")
	}
	deadline, _ := time.Parse(time.RFC3339Nano, journal.StabilityDeadline)
	if engine.now().Before(deadline) {
		return Journal{}, ErrStabilityWindowActive
	}
	if err := engine.switchPointer("recovery", journal.NewCurrentTarget, journal.UpdateID+"-finalize"); err != nil {
		return Journal{}, err
	}
	journal.ErrorCode = ""
	if err := engine.save(&journal, StateFinalized); err != nil {
		return Journal{}, err
	}
	if err := engine.Store.ClearActive(); err != nil {
		return Journal{}, err
	}
	return journal, nil
}

func (engine *Engine) rollback(ctx context.Context, journal *Journal, code string, scheduleStart bool) error {
	journal.ErrorCode = sanitizeCode(code)
	if err := engine.saveNoHook(journal, StateRollingBack); err != nil {
		return err
	}
	failed := func(errorCode string, cause error) error {
		journal.ErrorCode = errorCode
		_ = engine.saveNoHook(journal, StateRollbackFailed)
		return cause
	}
	if err := engine.Runtime.Quiesce(ctx); err != nil {
		return failed("ROLLBACK_QUIESCE_FAILED", err)
	}
	if journal.DatabaseSwitchBegun {
		snapshot := filepath.Join(engine.transactionRoot(journal.UpdateID), "snapshot.db")
		digest, _, err := hashRegular(snapshot, vpsbackup.MaximumFileBytes)
		if err != nil || digest != journal.SnapshotSHA256 {
			return failed("ROLLBACK_SNAPSHOT_INVALID", errors.New("verified VPS update snapshot is unavailable"))
		}
		rollback := filepath.Join(engine.transactionRoot(journal.UpdateID), "rollback.db")
		_ = os.Remove(rollback)
		if err := copyExclusive(snapshot, rollback, 0o600, vpsbackup.MaximumFileBytes); err != nil {
			return failed("ROLLBACK_DATABASE_COPY_FAILED", err)
		}
		if err := removeSidecars(engine.DatabasePath); err != nil {
			return failed("ROLLBACK_SIDECAR_REMOVE_FAILED", err)
		}
		if err := engine.replaceDatabase(rollback, journal.SnapshotSHA256, journal.UpdateID, "rollback"); err != nil {
			return failed("ROLLBACK_DATABASE_REPLACE_FAILED", err)
		}
		if err := engine.setDatabaseOwnership(); err != nil {
			return failed("ROLLBACK_DATABASE_OWNERSHIP_FAILED", err)
		}
		if err := syncDirectory(filepath.Dir(engine.DatabasePath)); err != nil {
			return failed("ROLLBACK_DATABASE_SYNC_FAILED", err)
		}
	}
	if err := engine.switchPointer("current", journal.OldCurrentTarget, journal.UpdateID+"-rollback"); err != nil {
		return failed("ROLLBACK_CURRENT_POINTER_FAILED", err)
	}
	if scheduleStart {
		if err := engine.Runtime.ScheduleStart(ctx, journal.OldVersion, engine.DatabasePath); err != nil {
			return failed("ROLLBACK_OLD_RELEASE_SCHEDULE_FAILED", err)
		}
	} else if err := engine.Runtime.StartAndHealth(ctx, journal.OldVersion, engine.DatabasePath); err != nil {
		return failed("ROLLBACK_OLD_RELEASE_HEALTH_FAILED", err)
	}
	journal.StabilityDeadline = ""
	if err := engine.saveNoHook(journal, StateRolledBack); err != nil {
		return err
	}
	return engine.Store.ClearActive()
}

func (engine *Engine) verifyCurrent(ctx context.Context, expectedTarget, version string, schema int64) error {
	policy, err := engine.policy()
	if err != nil {
		return err
	}
	target, verified, err := engine.currentRelease(policy)
	if err != nil || target != expectedTarget || verified.Release.Version != version || verified.Release.DatabaseSchemaMaximum != schema {
		return errors.New("current VPS release differs from update journal")
	}
	return engine.Runtime.StartAndHealth(ctx, version, engine.DatabasePath)
}

func (engine *Engine) verifyCurrentOffline(ctx context.Context, expectedTarget, version string, schema int64) error {
	policy, err := engine.policy()
	if err != nil {
		return err
	}
	target, verified, err := engine.currentRelease(policy)
	if err != nil || target != expectedTarget || verified.Release.Version != version || verified.Release.DatabaseSchemaMaximum != schema {
		return errors.New("current VPS release differs from update journal")
	}
	return engine.Runtime.VerifyCurrent(ctx, version, engine.DatabasePath)
}

func (engine *Engine) save(journal *Journal, state State) error {
	if err := engine.saveNoHook(journal, state); err != nil {
		return err
	}
	if engine.AfterState != nil {
		return engine.AfterState(state)
	}
	return nil
}

func (engine *Engine) saveNoHook(journal *Journal, state State) error {
	journal.State = state
	journal.UpdatedAt = engine.now().Format(time.RFC3339Nano)
	if err := engine.Store.Save(*journal); err != nil {
		return err
	}
	return engine.Status.Write(Status{FormatVersion: JournalFormatVersion, Available: true, UpdateID: journal.UpdateID, State: journal.State, CurrentVersion: currentVersionForState(*journal), PreviousVersion: journal.OldVersion, CandidateVersion: journal.NewVersion, CurrentSchema: currentSchemaForState(*journal), CandidateSchema: journal.NewSchema, StartedAt: journal.StartedAt, UpdatedAt: journal.UpdatedAt, StabilityDeadline: journal.StabilityDeadline, ErrorCode: journal.ErrorCode, ReconnectRequired: state != StatePrepared})
}

func currentVersionForState(journal Journal) string {
	switch journal.State {
	case StateDBSwitched, StateReleaseSwitch, StateHealthChecking, StateStabilizing, StateFinalized:
		return journal.NewVersion
	}
	return journal.OldVersion
}
func currentSchemaForState(journal Journal) int64 {
	switch journal.State {
	case StateDBSwitched, StateReleaseSwitch, StateHealthChecking, StateStabilizing, StateFinalized:
		return journal.NewSchema
	}
	return journal.OldSchema
}

func (engine *Engine) currentRelease(policy vpsrelease.VerificationPolicy) (string, vpsrelease.VerifiedRelease, error) {
	link := filepath.Join(engine.ReleaseRoot, "current")
	target, err := os.Readlink(link)
	if err != nil || filepath.IsAbs(target) {
		return "", vpsrelease.VerifiedRelease{}, errors.New("current VPS release pointer is invalid")
	}
	target = filepath.ToSlash(filepath.Clean(target))
	if !strings.HasPrefix(target, "releases/v") || strings.Contains(strings.TrimPrefix(target, "releases/v"), "/") {
		return "", vpsrelease.VerifiedRelease{}, errors.New("current VPS release pointer escapes its layout")
	}
	verified, err := vpsrelease.VerifyRelease(filepath.Join(engine.ReleaseRoot, filepath.FromSlash(target)), policy)
	if err != nil || target != "releases/v"+verified.Release.Version {
		return "", vpsrelease.VerifiedRelease{}, errors.New("current VPS signed release is invalid")
	}
	return target, verified, nil
}

func (engine *Engine) installRelease(verified vpsrelease.VerifiedRelease, policy vpsrelease.VerificationPolicy) (string, error) {
	releases := filepath.Join(engine.ReleaseRoot, "releases")
	if err := ensureDirectory(releases, 0o755); err != nil {
		return "", err
	}
	destination := filepath.Join(releases, "v"+verified.Release.Version)
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("existing VPS candidate path is unsafe")
		}
		existing, verifyErr := vpsrelease.VerifyRelease(destination, policy)
		if verifyErr != nil || !sameRelease(existing, verified) {
			return "", errors.New("same VPS version already names a different signed artifact")
		}
		return destination, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	temporary := filepath.Join(releases, ".v"+verified.Release.Version+"-"+verified.Manifest.ReleaseJSONSHA256[:12])
	_ = os.RemoveAll(temporary)
	if err := os.Mkdir(temporary, 0o755); err != nil {
		return "", err
	}
	defer os.RemoveAll(temporary)
	records := append([]vpsrelease.FileRecord(nil), verified.Manifest.Files...)
	for _, extra := range []string{vpsrelease.ManifestFilename, vpsrelease.SignatureFilename} {
		info, err := os.Lstat(filepath.Join(verified.Root, extra))
		if err != nil {
			return "", err
		}
		records = append(records, vpsrelease.FileRecord{Path: extra, Bytes: info.Size(), Executable: false})
	}
	for _, record := range records {
		source := filepath.Join(verified.Root, filepath.FromSlash(record.Path))
		target := filepath.Join(temporary, filepath.FromSlash(record.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", err
		}
		mode := os.FileMode(0o644)
		if record.Executable {
			mode = 0o755
		}
		maximum := vpsrelease.MaximumFileBytes
		if record.Path == vpsrelease.ManifestFilename {
			maximum = vpsrelease.MaximumManifestBytes
		}
		if record.Path == vpsrelease.SignatureFilename {
			maximum = vpsrelease.MaximumSignatureBytes
		}
		if err := copyExclusive(source, target, mode, maximum); err != nil {
			return "", err
		}
	}
	if err := normalizeReleaseDirectories(temporary); err != nil {
		return "", err
	}
	if err := syncTree(temporary); err != nil {
		return "", err
	}
	installed, err := vpsrelease.VerifyRelease(temporary, policy)
	if err != nil || !sameRelease(installed, verified) {
		return "", errors.New("installed VPS candidate changed during copy")
	}
	if err := os.Rename(temporary, destination); err != nil {
		return "", err
	}
	if err := syncDirectory(releases); err != nil {
		return "", err
	}
	return destination, nil
}

func normalizeReleaseDirectories(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o755)
		}
		return nil
	})
}

func sameRelease(left, right vpsrelease.VerifiedRelease) bool {
	if left.Release.Version != right.Release.Version || left.Fingerprint != right.Fingerprint || left.Manifest.ReleaseJSONSHA256 != right.Manifest.ReleaseJSONSHA256 || len(left.Manifest.Files) != len(right.Manifest.Files) {
		return false
	}
	for index := range left.Manifest.Files {
		if left.Manifest.Files[index] != right.Manifest.Files[index] {
			return false
		}
	}
	return true
}

func (engine *Engine) switchPointer(name, target, suffix string) error {
	if name != "current" && name != "recovery" || target != "releases/v"+strings.TrimPrefix(target, "releases/v") || updatepkg.ValidateGatewayVersion(strings.TrimPrefix(target, "releases/v")) != nil {
		return errors.New("VPS release pointer contract is invalid")
	}
	temporary := filepath.Join(engine.ReleaseRoot, "."+name+"-"+sanitizeSuffix(suffix))
	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.FromSlash(target), temporary); err != nil {
		return err
	}
	if err := replacePath(temporary, filepath.Join(engine.ReleaseRoot, name)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(engine.ReleaseRoot)
}

func (engine *Engine) policy() (vpsrelease.VerificationPolicy, error) {
	key, err := updatepkg.LoadPublicKey(engine.TrustedKeyPath)
	if err != nil {
		return vpsrelease.VerificationPolicy{}, err
	}
	return vpsrelease.VerificationPolicy{PublicKey: key, ExpectedOS: "linux", ExpectedArch: "amd64", ExpectedProfile: engine.Profile}, nil
}

func (engine *Engine) validate(withStager bool) error {
	transactionRoot := filepath.Clean(engine.Store.Root)
	validTransactionRoot := filepath.IsAbs(transactionRoot) &&
		filepath.Base(transactionRoot) == "update-transactions" &&
		filepath.Base(filepath.Dir(transactionRoot)) == "gateway-vpn-vps-privileged"
	validDatabasePath := filepath.Clean(engine.DatabasePath) == filepath.Join(filepath.Clean(engine.StateDirectory), "vps-agent.db")
	if engine.Runtime == nil || !filepath.IsAbs(engine.ReleaseRoot) || !filepath.IsAbs(engine.StateDirectory) || !filepath.IsAbs(engine.DatabasePath) || !filepath.IsAbs(engine.ConfigPath) || !filepath.IsAbs(engine.TrustedKeyPath) || updatepkg.ValidateGatewayVersion(engine.RunningVersion) != nil || engine.RunningSchema < 1 || engine.AgentUID < 0 || engine.AgentGID < 0 || engine.Status.UID != engine.AgentUID || engine.Status.GID != engine.AgentGID || !contains(vpsrelease.SupportedProfiles(), engine.Profile) || !validTransactionRoot || !validDatabasePath || filepath.Clean(engine.Status.Path) != filepath.Join(filepath.Clean(engine.StateDirectory), "update-status.json") {
		return errors.New("complete fixed VPS update engine configuration is required")
	}
	if withStager && engine.Stager == nil {
		return errors.New("VPS update stager is required")
	}
	return nil
}

func (engine *Engine) transactionRoot(updateID string) string {
	return filepath.Join(engine.Store.Root, updateID)
}
func (engine *Engine) now() time.Time {
	if engine.Now != nil {
		return engine.Now().UTC()
	}
	return time.Now().UTC()
}
func (engine *Engine) stabilityWindow() time.Duration {
	if engine.StabilityWindow > 0 {
		return engine.StabilityWindow
	}
	return DefaultStabilityWindow
}
func (engine *Engine) setDatabaseOwnership() error {
	if err := chownPath(engine.DatabasePath, engine.AgentUID, engine.AgentGID); err != nil {
		return err
	}
	return os.Chmod(engine.DatabasePath, 0o600)
}

func (engine *Engine) replaceDatabase(source, expectedSHA256, updateID, phase string) error {
	directory := filepath.Dir(engine.DatabasePath)
	directoryInfo, err := os.Lstat(directory)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return errors.New("VPS Agent database directory is unsafe")
	}
	destinationInfo, err := os.Lstat(engine.DatabasePath)
	if err != nil || destinationInfo.Mode()&os.ModeSymlink != 0 || !destinationInfo.Mode().IsRegular() {
		return errors.New("VPS Agent database destination is unsafe")
	}
	temporary := filepath.Join(directory, "."+filepath.Base(engine.DatabasePath)+"-"+sanitizeSuffix(updateID+"-"+phase)+".tmp")
	if info, statErr := os.Lstat(temporary); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("VPS Agent database replacement artifact is unsafe")
		}
		if removeErr := os.Remove(temporary); removeErr != nil {
			return removeErr
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := copyExclusive(source, temporary, 0o600, vpsbackup.MaximumFileBytes); err != nil {
		return err
	}
	defer os.Remove(temporary)
	digest, _, err := hashRegular(temporary, vpsbackup.MaximumFileBytes)
	if err != nil || !digestPattern.MatchString(expectedSHA256) || digest != expectedSHA256 {
		return errors.New("VPS Agent database replacement digest differs")
	}
	// systemd exposes Agent state and the privileged transaction root as
	// separate bind mounts, so a direct rename between them returns EXDEV.
	// The verified copy is created beside the live database, keeping this
	// final rename atomic on the Linux runtime.
	return replacePath(temporary, engine.DatabasePath)
}

func validOffline(value OfflineResult, version string, schema int64) bool {
	return value.Version == version && value.SchemaVersion == schema && value.DatabaseBytes > 0 && value.DatabaseBytes <= vpsbackup.MaximumFileBytes && digestPattern.MatchString(value.DatabaseSHA256) && value.QuickCheck == "PASS" && value.IntegrityCheck == "PASS" && value.ForeignKeyCheck == "PASS"
}

func copyExclusive(source, destination string, mode os.FileMode, maximum int64) error {
	content, err := readStable(source, maximum)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(content) {
		_ = os.Remove(destination)
		return errors.New("durable VPS update file copy failed")
	}
	return os.Chmod(destination, mode)
}

func hashRegular(path string, maximum int64) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return "", 0, errors.New("bounded VPS update file is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	read, copyErr := io.Copy(hash, io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || read != info.Size() {
		return "", 0, errors.New("hash VPS update file failed")
	}
	return hex.EncodeToString(hash.Sum(nil)), read, nil
}

func removeSidecars(path string) error {
	var result error
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	return result
}
func ensureDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("VPS update directory is unsafe")
	}
	return os.Chmod(path, mode)
}
func sanitizeSuffix(value string) string {
	value = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, strings.ToLower(value))
	if len(value) > 96 {
		value = value[:96]
	}
	return value
}
func sanitizeCode(value string) string {
	value = strings.ToUpper(value)
	if errorCodePattern.MatchString(value) {
		return value
	}
	return "UPDATE_FAILED"
}

// Keep runtime referenced here: Windows source tests intentionally exercise
// transaction logic but cannot assert Unix ownership.
var _ = runtime.GOOS
